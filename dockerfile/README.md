# Dockerfile seguro

> Complemento de [compose/](../compose/README.md) (reglas OWASP a nivel de contenedor).
> OWASP no tiene una cheat sheet solo de Dockerfile: esto junta lo que la
> **OWASP Docker Security Cheat Sheet** pide a nivel de imagen (reglas #2, #9, #12, #13),
> las buenas prácticas oficiales de Docker y las reglas de **hadolint**.
> Revisado: 2026-11-16 · Ver [qué es fijo y qué se adapta](#qué-es-fijo-y-qué-se-adapta) antes de comparar con un proyecto real.

---

## Plantilla comentada

> ⚠ Los comentarios al final de línea son solo para leerla aquí: **Dockerfile no admite comentarios en la misma línea** que una instrucción (`COPY a ./  # x` buscaría un fichero llamado `#`). En un Dockerfile real, el comentario va en la línea de arriba — ver los `Dockerfile.*` de esta carpeta.

```dockerfile
# syntax=docker/dockerfile:1

# ── 1. ETAPA DE BUILD: aquí van compiladores, dev-deps, secretos de build ──
FROM python:3.12-slim@sha256:<digest> AS build        # versión + digest (#13)
WORKDIR /app
COPY requirements.txt .                                # primero deps → mejor caché
RUN --mount=type=secret,id=pip_token \
    pip install --no-cache-dir --prefix=/install -r requirements.txt   # secreto SIN dejar rastro (#12)

# ── 2. ETAPA FINAL: solo lo necesario para ejecutar ──
FROM python:3.12-slim@sha256:<digest>
SHELL ["/bin/bash", "-o", "pipefail", "-c"]            # un fallo en un pipe rompe el build

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini=0.19.* \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r app && useradd -r -g app -s /usr/sbin/nologin app   # usuario sin login (#2)

WORKDIR /app
COPY --from=build /install /usr/local
COPY src/ ./src/                                       # COPY deja root:root (dirs 755, ficheros 644) → app solo lee

USER app                                               # SIEMPRE antes de CMD (#2)
EXPOSE 8000                                            # puerto > 1024 → sin capabilities
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
ENTRYPOINT ["tini", "--"]                              # init: reenvía señales y recoge zombies
CMD ["python", "-m", "src.app"]                        # forma JSON (exec)
```

---

## Las reglas

### 1. Imagen base: pequeña, oficial y fijada
- **Oficial o de confianza** (Docker Official Images, Verified Publisher). Nada de imágenes random de Docker Hub.
- **Mínima:** `alpine`, `-slim`, `distroless`, `scratch` → menos paquetes = menos CVEs y menos herramientas para el atacante.
- **Nunca `latest`** ni sin tag (hadolint **DL3006**, **DL3007**).
- **Fijar por digest** (OWASP #13): `nginx:1.27-alpine@sha256:...`. El tag puede moverse; el digest no.
- Para actualizar sin perder el pin → **Dependabot / Renovate**.

```bash
docker pull nginx:1.27-alpine && docker inspect --format '{{index .RepoDigests 0}}' nginx:1.27-alpine
```

### 2. Usuario sin privilegios (OWASP #2)
- **`USER` no root antes de `CMD`/`ENTRYPOINT`.** hadolint **DL3002**: el último `USER` no debe ser root.
- Se puede subir a `USER root` para pasos de build, pero **volver a bajar** al final.
- Usuario de sistema, sin shell: `useradd -r -s /usr/sbin/nologin`.
- Imágenes que ya lo traen: `nginxinc/nginx-unprivileged`, `node` (usuario `node`), distroless `:nonroot`.
- Usar **puertos > 1024** → no hace falta `NET_BIND_SERVICE`.

### 3. Ficheros: dueño root, app solo lee
- Código y config de **root** con permisos de lectura → si comprometen la app, **no puede reescribirse** a sí misma.
- `COPY` ya deja todo como `root:root` → basta con no hacer `chown` al usuario de la app. Si se fuerza `--chmod`, **nunca `0444` en carpetas**: sin el bit `x` no se puede entrar en el directorio y la app no arranca (usar `0755` o `chmod -R go-w` en un `RUN`).
- Solo dar escritura a la app en lo que realmente lo necesite (`/tmp`, un volumen de datos).
- Combinar con `read_only: true` en el compose (OWASP #8).

### 4. `COPY` y no `ADD` (OWASP #9 · hadolint **DL3020**)
- `ADD` descarga URLs y **descomprime tar automáticamente** → comportamiento implícito, riesgo de traer algo inesperado.
- `COPY` solo copia. Si necesitas descargar: `RUN curl` + **verificar checksum**.
- **Copiar ficheros explícitos**, no `COPY . .` → no se cuela nada por accidente.

### 5. `.dockerignore` siempre
```gitignore
.git
.env
.env.*
*.pem
*.key
id_rsa*
secrets/
node_modules
__pycache__
*.log
Dockerfile
docker-compose*.yml
```
- Reduce el *build context* y evita que un `COPY . .` meta secretos o el `.git` (historial completo) en la imagen.
- **Mejor aún: allowlist** (lo que usan [`dockerignore.python`](dockerignore.python) y panchi-bot). Se ignora todo con `*` y se permite solo lo necesario con `!`:
  ```gitignore
  *
  !requirements.txt
  !wsgi.py
  !app/
  **/__pycache__
  **/.env*
  ```
  Lista negra = "entra todo menos lo que me acordé de prohibir". Allowlist = "no entra nada que no haya permitido". Un `.env.prod` o un `dump.sql` nuevo no se cuela nunca.

### 6. Secretos: nunca en la imagen (OWASP #12)
| ❌ Mal | Por qué |
|---|---|
| `ENV DB_PASS=...` | Visible en `docker inspect` y en la imagen |
| `ARG TOKEN=...` | Queda en `docker history` |
| `COPY id_rsa .` + `RUN rm id_rsa` | El fichero **sigue en la capa anterior** |

✅ Bien:
```dockerfile
RUN --mount=type=secret,id=token  TOKEN=$(cat /run/secrets/token) && ...
```
```bash
docker build --secret id=token,src=./token.txt .
```
- En runtime: Docker secrets / variables inyectadas al arrancar, nunca horneadas.

> 🎯 **Pentest:** `docker history --no-trunc img`, `docker save img -o img.tar` y revisar capas (`dive img` lo hace visual).

### 7. Paquetes del sistema
- **Fijar versiones** (OWASP #9 · hadolint **DL3008** apt, **DL3018** apk): `apk add curl=8.11.1-r0`.
- **No dejar caché:** `apk add --no-cache` (**DL3019**), `apt-get ... && rm -rf /var/lib/apt/lists/*` (**DL3009**).
- `apt-get install --no-install-recommends` (**DL3015**) → no meter extras.
- `update` e `install` **en el mismo `RUN`** (**DL3009**) → si no, la caché deja índices viejos.
- **Borrar lo que no se usa en runtime** (curl, compiladores, gestores de paquetes si se puede): menos herramientas para quien consiga RCE.
- Trade-off: `apk upgrade` / `apt-get upgrade` mete parches pero hace el build menos reproducible. Si se usa, documentarlo.

### 8. Nada de `curl | bash` (OWASP #9)
```dockerfile
# ❌
RUN curl -fsSL https://ejemplo.com/install.sh | bash
# ✅
RUN curl -fsSLo tool.tgz https://ejemplo.com/tool-1.2.3.tgz \
 && echo "<sha256>  tool.tgz" | sha256sum -c - \
 && tar xzf tool.tgz && rm tool.tgz
```
- Con pipes: `SHELL ["/bin/bash", "-o", "pipefail", "-c"]` (hadolint **DL4006**), si no un fallo del `curl` pasa desapercibido.
- Claves GPG de repos externos: comprobar la **huella** (fingerprint), no solo descargarla:
  ```dockerfile
  RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc -o /microsoft-prod.asc \
   && gpg --show-keys --with-colons /microsoft-prod.asc | grep -q '^fpr:::::::::<HUELLA>:$'
  ```
  Si la clave cambia por el camino (MITM, repo comprometido), `grep -q` falla → con `pipefail` falla el build.

### 9. Multi-stage builds
- Etapa `build` con compiladores, dev-dependencies, tokens de build.
- Etapa final con **solo el binario/artefacto** → `COPY --from=build`.
- Resultado: imagen final pequeña, sin `gcc`, `git`, `npm` dev-deps, etc.
- Bonus: etapa final `FROM gcr.io/distroless/...` o `scratch` (sin shell → un atacante no tiene ni `sh`).

### 10. `CMD` / `ENTRYPOINT` en forma JSON
- `CMD ["nginx", "-g", "daemon off;"]` ✅ — el proceso es PID 1 y recibe señales (`SIGTERM` → parada limpia).
- `CMD nginx -g "daemon off;"` ❌ — lo envuelve en `sh -c`, las señales no llegan (hadolint **DL3025**).
- Si la app no gestiona señales/zombies: `tini` o `docker run --init`.

### 11. `HEALTHCHECK`
- Permite a Docker saber si la app responde, no solo si el proceso vive.
- Usar `127.0.0.1` y no `localhost` en Alpine si la app solo escucha IPv4 (`localhost` → `::1`).
- Usar una herramienta que ya esté en la imagen (no instalar curl solo para esto).
- `--start-period` si la app tarda en arrancar (carga un modelo, migraciones): los fallos en ese margen no cuentan y no se marca `unhealthy` al arrancar.

### 12. Metadatos y orden
- `LABEL org.opencontainers.image.source=...`, `version`, `maintainer` → trazabilidad.
- Ordenar de lo que menos cambia a lo que más (deps antes que código) → caché eficiente.
- `WORKDIR` explícito (no `cd` en `RUN` — hadolint **DL3003**).
- `EXPOSE` documenta; **no publica** nada (eso lo hace `ports:`).

### 13. Escaneo (OWASP #9 y #13)
```bash
docker run --rm -i hadolint/hadolint < Dockerfile             # lint
trivy config .                                                # misconfiguraciones
trivy image --severity HIGH,CRITICAL --ignore-unfixed img:tag # CVEs
trivy image --format cyclonedx -o sbom.json img:tag           # SBOM
dive img:tag                                                  # capas y desperdicio
```
- Meterlo en CI (GitHub Actions) + escaneo semanal programado (salen CVEs nuevos sin que cambies nada).

---

## Configs de referencia (probadas)

| Fichero | Para qué |
|---|---|
| [`Dockerfile.static`](Dockerfile.static) | Web estática (HTML/CSS/JS a mano) con nginx sin root |
| [`Dockerfile.static-build`](Dockerfile.static-build) | Web con paso de build (Vite, React, Vue, Astro...) → multi-stage |
| [`Dockerfile.python`](Dockerfile.python) | Backend Python (Flask + gunicorn) → multi-stage con venv |
| [`dockerignore.static`](dockerignore.static) · [`dockerignore.python`](dockerignore.python) | `.dockerignore` de cada caso |

¿Cuál uso?

| Mi proyecto | Dockerfile |
|---|---|
| HTML/CSS/JS escritos a mano, se sirven tal cual | `Dockerfile.static` |
| Hay `package.json` y `npm run build` genera `dist/` | `Dockerfile.static-build` |
| SPA con rutas en el cliente (`/about` sin fichero real) | `Dockerfile.static-build` + variante SPA de [nginx](../nginx/README.md) |
| App Python con base de datos | `Dockerfile.python` + [compose app + BD](../compose/compose.app-db.yml) |

### Qué es fijo y qué se adapta

Cada proyecto real tendrá un Dockerfile **distinto** a la plantilla. Es normal. Al leer uno, mirar primero lo fijo:

| | Qué | Ejemplos |
|---|---|---|
| 🔒 **Fijo** (si falta, está mal) | Base oficial con versión + digest · misma base en las dos etapas · multi-stage (pip/compiladores/curl solo en build) · usuario sin root, sin shell, uid fijo · código de root y solo lectura · `USER` antes de `CMD` · `CMD` en JSON · healthcheck sin instalar curl · ningún secreto en `ENV`/`ARG` · `.dockerignore` | Todos los `Dockerfile.*` de esta carpeta |
| 🔧 **Se adapta** (lo decide la app) | Versión de Python · paquetes del sistema (drivers, librerías C) · qué se copia · puerto · config de gunicorn · carpetas escribibles · `start-period` · descargas extra en el build | Ver [Ejemplo real: panchi-bot](#ejemplo-real-panchi-bot) |

Regla: **cada cosa que se adapta lleva un comentario con el porqué** encima. Si al leer un Dockerfile no sabes por qué algo es distinto, falta ese comentario.

### Notas: web con paso de build
- Carpeta de salida: Vite/Astro → `dist/`, Create React App → `build/`, Angular → `dist/<proyecto>/browser/`.
- Los `COPY` de la etapa 1 según la estructura del proyecto.
- `npm ci --ignore-scripts` evita que paquetes de npm ejecuten scripts al instalarse (vector de supply chain), pero **puede romper** paquetes que los necesitan. Probarlo y quedarse con él si el build pasa.

### Notas: backend Python
- `tini` no va en el Dockerfile: se activa con `init: true` en el compose (Docker trae su propio init). Comprobado: PID 1 = `docker-init`.
- `--bind 0.0.0.0` es **dentro** del contenedor; desde fuera solo se publica en `127.0.0.1` (compose).
- Workers: punto de partida `2 × núcleos + 1`, ajustar mirando `docker stats` y el `mem_limit`.
- La imagen base trae **dos** `pip`: el del venv (se quita en la etapa 1) y el del sistema (`/usr/local/bin/pip`, se quita en la etapa final con `/usr/local/bin/python -m pip uninstall -y pip`). Antes solo se quitaba el del venv y `python -m pip` daba un falso "No module named pip" porque `python` es el del venv. El del sistema importa sobre todo si hay un volumen escribible y ejecutable (`pip install --target /data …`).

---

#### `requirements.txt`

```text
flask==3.1.0
gunicorn==23.0.0
psycopg[binary]==3.2.3
```
- **Versiones exactas** (`==`), nunca sin fijar.
- `psycopg[binary]` trae libpq compilada → no hacen falta compiladores.
- Más estricto (supply chain): `pip-compile --generate-hashes` + `pip install --require-hashes -r requirements.txt`.

---

---

## Checklist rápida

- [ ] `FROM` con versión concreta **y** `@sha256:` digest
- [ ] Imagen base mínima y oficial
- [ ] Multi-stage si hay compilación / dev-deps
- [ ] `.dockerignore` con `.git`, `.env*`, claves
- [ ] `COPY` de ficheros concretos, nunca `ADD` (salvo motivo)
- [ ] Ningún secreto en `ENV`, `ARG` ni `COPY` → `--mount=type=secret`
- [ ] Paquetes con versión fijada, `--no-cache` / limpiar listas
- [ ] Sin `curl | bash`; descargas con checksum; `pipefail`
- [ ] Herramientas innecesarias borradas al final
- [ ] Código propiedad de root, solo lectura para la app
- [ ] `USER` no root como último `USER`
- [ ] Puerto > 1024
- [ ] `HEALTHCHECK`
- [ ] `CMD`/`ENTRYPOINT` en forma JSON
- [ ] hadolint + trivy pasan sin HIGH/CRITICAL

---

## Ejemplo real: mi portfolio

| Práctica | Cómo se aplica |
|---|---|
| Base mínima y fijada | `nginxinc/nginx-unprivileged:1.30-alpine@sha256:...` + Dependabot |
| Usuario | Sube a `USER root` solo para build, termina en `USER 101` |
| Ficheros | `chown -R root:root /etc/nginx && chmod -R go-w` → nginx no puede tocar su config |
| COPY explícito | `COPY index.html styles.css main.js ./` (no `COPY . .`) |
| Paquetes | `apk upgrade` (parches) + `tzdata` instalado y borrado en la misma capa + `curl` eliminado |
| Puerto | 8080, sin capabilities |
| Healthcheck | `wget` de busybox contra `127.0.0.1` |
| CMD | Forma JSON |
| CI | hadolint, gitleaks, trivy config/image, SBOM CycloneDX |

Pruebas hechas el 2026-11-16 desde dentro del contenedor: no puede escribir en la web ni en la config, `/tmp` no ejecuta, sin SUIDs, `CapEff` 0.

---

## Ejemplo real: panchi-bot

Flask + gunicorn + workers RQ, con SQL Server y Redis. Mismo esqueleto que [`Dockerfile.python`](Dockerfile.python); las diferencias son por lo que la app necesita:

| Diferencia con la plantilla | Por qué |
|---|---|
| `python:3.11-slim-bookworm` | Versión que piden sus dependencias |
| Clave GPG de Microsoft + `msodbcsql18` | Usa SQL Server vía `pyodbc` → necesita el driver ODBC del sistema. Postgres (`psycopg[binary]`) no lo necesita |
| `curl` + `gnupg` en la etapa build | Solo para bajar la clave y **comprobar su huella**; no llegan a la imagen final |
| `SHELL ... pipefail` | Hay un pipe (`gpg ... \| grep`) |
| `spacy download es_core_news_sm` | Modelo de NLP descargado en el build |
| `COPY . .` | ~15 carpetas y ficheros; seguro porque el `.dockerignore` es **allowlist** |
| `/app/logs` con dueño `appuser` | La app escribe log a fichero: único sitio escribible (volumen/tmpfs en el compose) |
| `HOME=/tmp` | El usuario no tiene home; cachés de librerías → tmpfs |
| Puerto 5000 + `gunicorn.conf.py` | Config propia (filtro de logs del polling) |
| `--start-period=60s` | Cargar spaCy tarda |
| Una imagen para app **y** workers | El compose cambia el `command:` y desactiva el healthcheck en los workers (no escuchan en :5000) |

**Excepciones conscientes** (documentadas en su Dockerfile/compose):
- `msodbcsql18` sin versión fijada: Microsoft retira las versiones antiguas de su repo → fijarla rompería el build.
- `sqlserver` con `cap_add: [NET_BIND_SERVICE]`: el binario trae esa *file capability* y sin ella el kernel no deja ejecutarlo.

**Pendiente en panchi-bot** (no cumple aún la plantilla):
- Secretos por `.env` / `env_file` → pasar a `secrets:` ([compose/](../compose/README.md#rule-12--secretos)).
- Contraseña de Redis en `command: --requirepass ${REDIS_PASSWORD}` → visible en `docker inspect` y en `ps` del host. Mejor un fichero de config/secreto.

---

## Preguntas de repaso

1. ¿Por qué `COPY clave && RUN rm clave` deja la clave en la imagen?
2. ¿Qué diferencia hay entre `ARG` y `RUN --mount=type=secret`?
3. ¿Qué ventaja de seguridad tiene un multi-stage build?
4. ¿Por qué `CMD nginx ...` (forma shell) es peor que la forma JSON?
5. ¿Qué gana un atacante si el código de la app es propiedad del usuario que la ejecuta?
6. ¿Por qué `ADD https://...` es más arriesgado que `COPY`?
7. ¿Qué hace `pipefail` y qué fallo evita en `curl ... | tar`?
8. ¿Qué ventaja y qué inconveniente tiene `apk upgrade` en el Dockerfile?
9. ¿Por qué una imagen distroless dificulta la post-explotación?
10. ¿Cómo sacarías secretos de una imagen ajena en un pentest?
