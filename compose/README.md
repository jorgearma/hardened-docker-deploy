# Compose y runtime seguros — OWASP Docker Security Cheat Sheet

> Fuente: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
> Copia del original en el repo: [`owasp/docker-security-cheat-sheet.md`](../owasp/docker-security-cheat-sheet.md)
> Resumen propio (en mis palabras) para configurar y auditar mis contenedores.
> Revisado: 2026-11-16

---

## Chuleta rápida (lo mínimo en cada `docker-compose.yml`)

```yaml
services:
  app:
    image: imagen:1.2.3@sha256:...      # #9/#13 versión + digest fijados
    user: "1000:1000"                   # #2  (o USER en el Dockerfile)
    read_only: true                     # #8
    tmpfs:
      - /tmp:size=16m,noexec,nosuid,nodev
    cap_drop: [ALL]                     # #3
    # cap_add: [NET_BIND_SERVICE]       #     solo si hace falta
    security_opt:
      - no-new-privileges:true          # #4
    mem_limit: 256m                     # #7
    memswap_limit: 256m
    cpus: 0.5
    pids_limit: 100
    ulimits:
      nofile: { soft: 1024, hard: 2048 }
    logging:                            # #7  logs rotados (si no, llenan el disco)
      driver: json-file
      options: { max-size: "10m", max-file: "3" }
    restart: on-failure:5               # #7 (OWASP sugiere on-failure:N)
    ports:
      - "127.0.0.1:8080:8080"           # #5a nunca 0.0.0.0 si hay UFW
    networks: [app_net]                 # #5  red propia
    volumes:
      - datos:/data:ro                  # #8  :ro siempre que se pueda
    # NUNCA: privileged: true
    # NUNCA: /var/run/docker.sock montado
    # NUNCA: seccomp=unconfined / apparmor=unconfined

networks:
  app_net:
```

---

## Las reglas una a una

### RULE #0 — Host y Docker actualizados
- Los contenedores **comparten el kernel del host**: una vulnerabilidad del kernel o del runtime (runc) puede dar root en el host desde dentro del contenedor.
- Ejemplos que cita: **Leaky Vessels** (runc, 2024) y **Dirty COW** (kernel).
- **Qué hacer:** actualizar kernel, Docker Engine, containerd y runc regularmente.

```bash
docker version; uname -r
apt list --upgradable 2>/dev/null | grep -Ei 'docker|containerd|runc|linux-image'
```

---

### RULE #1 — No exponer el socket del daemon
- `/var/run/docker.sock` = **root en el host**. Quien habla con el socket puede lanzar un contenedor `--privileged` montando `/` del host.
- **No montarlo en contenedores.** Montarlo `:ro` **no sirve**: el modo de solo lectura afecta al fichero, no a la API.
- **No** exponer el daemon por TCP (`-H tcp://0.0.0.0:2375`): sin autenticación ni cifrado. Si es imprescindible → TLS con certificados de cliente.

```bash
# ¿Algún contenedor monta el socket?
docker ps -q | xargs docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' | grep docker.sock
# ¿El daemon escucha por TCP?
ss -tlnp | grep -E '2375|2376'
```

> 🎯 **Pentest:** si encuentras el socket dentro de un contenedor →
> `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host` = root en el host.

---

### RULE #2 — Usuario sin privilegios
Tres formas de hacerlo:

| Dónde | Cómo |
|---|---|
| Dockerfile | `RUN addgroup -S app && adduser -S -G app app` + `USER app` |
| Runtime | `docker run -u 4000 ...` / `user: "4000"` en compose |
| Daemon | `"userns-remap": "default"` en `/etc/docker/daemon.json` (root del contenedor = uid sin privilegios en el host) |

- Kubernetes: `runAsUser`, `runAsNonRoot: true`, Pod Security nivel `Restricted`.

```bash
docker exec <c> id                 # no debe ser uid=0
```

---

### RULE #3 — Limitar capabilities
- Linux divide los poderes de root en *capabilities*. Docker deja por defecto un subconjunto (CHOWN, SETUID, NET_RAW...).
- **Nunca `--privileged`**: da todas las capabilities y acceso a dispositivos → escape trivial.
- Patrón correcto: **quitar todas y añadir solo las necesarias.**

```bash
docker run --cap-drop all --cap-add NET_BIND_SERVICE ...
docker exec <c> grep Cap /proc/self/status      # CapEff: 0000000000000000 = ninguna
capsh --decode=00000000a80425fb                  # traducir el hex
```

> 🎯 **Pentest:** capabilities peligrosas a buscar: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`.

---

### RULE #4 — Impedir escalada dentro del contenedor
- `--security-opt=no-new-privileges` → los binarios **SUID/SGID** dejan de dar privilegios (bloquea `sudo`, `su`, SUIDs mal puestos...).
- Kubernetes: `allowPrivilegeEscalation: false`.

```bash
docker exec <c> grep NoNewPrivs /proc/self/status   # debe ser 1
docker exec <c> find / -xdev -perm -4000 2>/dev/null # SUIDs que existen
```

---

### RULE #5 — Conectividad entre contenedores
- En la red por defecto (`docker0`) **todos los contenedores se ven entre sí** (ICC activado).
- **No** confiar en `--icc=false` global (rompe todo). Mejor: **redes personalizadas** y meter en cada una solo los contenedores que deben hablar.
- Ejemplo: `frontend_net` (proxy + web) y `backend_net` (web + db). La db no ve el proxy.
- Kubernetes: NetworkPolicies.

```bash
docker network ls
docker network inspect <red> --format '{{range .Containers}}{{.Name}} {{end}}'
```

### RULE #5a — Cuidado con UFW (y firewalls tipo UFW)
- Docker escribe sus reglas en iptables/nftables **antes** que las de UFW → `-p 8000:8000` queda **abierto a Internet aunque UFW diga deny**.
- **Opción 1 (la buena):** publicar solo en localhost → `127.0.0.1:8000:8000` y poner delante un nginx del host.
- **Opción 2:** `ufw-docker` (`ufw-docker allow <contenedor> 8000/tcp`).

```bash
docker ps --format '{{.Names}} {{.Ports}}' | grep 0.0.0.0   # lo que esté aquí está expuesto
nmap -p- <IP_PUBLICA_VPS>                                  # comprobar DESDE FUERA
```

---

### RULE #6 — Módulos de seguridad (seccomp, AppArmor, SELinux)
- **Nunca desactivar los perfiles por defecto** (`seccomp=unconfined`, `apparmor=unconfined` = bandera roja).
- **seccomp:** filtra syscalls. El perfil por defecto de Docker bloquea las peligrosas (`mount`, `kexec_load`, `add_key`...). Se pueden hacer perfiles más estrictos por aplicación.
- **AppArmor** (Ubuntu/Debian) / **SELinux** (RHEL/Fedora): restringen acceso a ficheros y recursos.
- **Monitorización en runtime:** Falco, Tetragon, Cilium (eBPF) → detectan `exec` raros, escaladas, conexiones inesperadas.

```bash
docker info --format '{{.SecurityOptions}}'                      # apparmor, seccomp...
docker inspect <c> --format '{{.AppArmorProfile}} {{.HostConfig.SecurityOpt}}'
docker exec <c> grep Seccomp /proc/self/status                   # 2 = filtro activo
```

---

### RULE #7 — Limitar recursos
Evita que un DoS o un proceso desbocado tumbe todo el VPS.

| Recurso | `docker run` | compose |
|---|---|---|
| Memoria | `--memory 256m --memory-swap 256m` | `mem_limit` / `memswap_limit` |
| CPU | `--cpus 0.5` | `cpus` |
| Procesos | `--pids-limit 100` | `pids_limit` |
| Descriptores | `--ulimit nofile=1024:2048` | `ulimits.nofile` |
| Reinicios | `--restart=on-failure:5` | `restart: on-failure:5` |
| Logs (disco) | `--log-opt max-size=10m --log-opt max-file=3` | `logging.options` (o por defecto en `daemon.json`) |

- ⚠ **No usar `--ulimit nproc`** para limitar procesos: cuenta los procesos de ese **UID en todo el host** (sin userns, el uid del contenedor es el mismo del host). Me pasó: uid 101 = nginx-unprivileged **y** `messagebus` (dbus) del host → con varios nginx se agotó y fallaban el healthcheck y `docker exec` con `resource temporarily unavailable`. `pids_limit` va por cgroup y cuenta solo los del contenedor.
- `on-failure:N` evita bucles infinitos de reinicio. (`unless-stopped` es aceptable si se decide a conciencia, p.ej. web pública.)

```bash
docker stats --no-stream
```

---

### RULE #8 — Sistema de ficheros y volúmenes de solo lectura
- `--read-only` / `read_only: true` → un atacante no puede dejar webshells, binarios ni modificar config.
- Lo que necesite escribir → `--tmpfs /tmp` (mejor con `noexec,nosuid,nodev`).
- Volúmenes en `:ro` siempre que se pueda: `-v datos:/data:ro`.
- Kubernetes: `readOnlyRootFilesystem: true`.

```bash
docker exec <c> touch /prueba      # debe dar "Read-only file system"
```

> ⚠️ Lección propia (portfolio): un volumen **escribible** compartido con el host (ej. logs) permite al contenedor crear **symlinks**. Si en el host algo lo procesa **como root** (logrotate), cuidado → usar `su <uid> <gid>` en logrotate.
> Ojo: `noexec` no impide `sh /tmp/script.sh` (el intérprete sí está permitido). Es una capa más, no una barrera total.

---

### RULE #9 — Escaneo en CI/CD
| Qué | Herramientas |
|---|---|
| Lint del Dockerfile | **hadolint** (USER puesto, imagen fijada, COPY y no ADD, nada de `curl \| bash`) |
| CVEs de la imagen | **Trivy**, Grype, Clair (gratis) · Snyk, Docker Scout, Anchore... |
| Secretos en el repo | **gitleaks**, TruffleHog, ggshield |
| Config de Docker/host | **Docker Bench for Security**, InSpec / dev-sec |
| Compose / IaC | **KICS**, conftest (reglas propias en Rego) · ⚠ Trivy `config` **no** analiza `docker-compose.yml` (solo Dockerfile) |
| Kubernetes | kube-bench, kubesec, kubeaudit |

```bash
docker run --rm -i hadolint/hadolint < Dockerfile
trivy image --severity HIGH,CRITICAL --ignore-unfixed mi-imagen:tag
trivy config .                      # Dockerfiles (NO revisa el compose)
# Auditoría del host:
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security
```

---

### RULE #10 — Log del daemon en `info`
- Nivel por defecto `info`. **No dejar `debug`** en producción (ruido, posible info sensible).
- Se configura en `/etc/docker/daemon.json` → `"log-level": "info"`. Un flag `--log-level` en el arranque de dockerd tiene prioridad.

```bash
cat /etc/docker/daemon.json
ps aux | grep '[d]ockerd.*--log-level'
```

---

### RULE #11 — Docker rootless
- El **daemon** y los contenedores corren **sin root en el host**. Si comprometen el daemon o runc, el atacante no es root.
- Diferencia clave: `userns-remap` remapea usuarios **pero el daemon sigue siendo root**; rootless no.
- **No protege** contra vulnerabilidades del kernel.
- Limitaciones: puertos < 1024, algunos drivers de red/almacenamiento.
- Alternativa: **Podman** (sin daemon, rootless por diseño, buena integración con SELinux).

```bash
docker info --format '{{.SecurityOptions}}'   # aparece "rootless" si lo está
```

---

### RULE #12 — Secretos
- **Nunca** credenciales en `ENV`, `ARG`, ni `COPY` + `rm` → quedan en las **capas de la imagen** (`docker history`, extraer capas).
- Runtime: **Docker secrets** → se montan en `/run/secrets/<nombre>`.

```yaml
services:
  app:
    secrets: [db_pass]
secrets:
  db_pass:
    file: ./secrets/db_pass.txt    # en compose es un bind mount → proteger permisos del fichero
```

- Build: BuildKit → `RUN --mount=type=secret,id=token cat /run/secrets/token`.
- `.dockerignore` con `.env`, `.env.*`, `*.pem`, `.git`...
- Kubernetes: los Secrets van en claro en etcd por defecto → cifrado de etcd o gestor externo (Vault, etc.).

> 🎯 **Pentest:** `docker history --no-trunc <img>` y `docker inspect <c> --format '{{.Config.Env}}'` → buscar contraseñas.

---

### RULE #13 — Cadena de suministro (supply chain)
- **Fijar imágenes por digest:** `nginx:1.27-alpine@sha256:...` (el tag se puede mover, el digest no).
- **SBOM** (lista de componentes): CycloneDX → `trivy image --format cyclonedx -o sbom.json img`.
- **Firma de imágenes:** Notary / cosign.
- **Procedencia:** SLSA.
- **Registry de confianza** con control de acceso y **políticas de despliegue** (OPA).
- Extra (propio): Dependabot para actualizar digests; actions de GitHub fijadas por SHA.

---

## Configs de referencia (probadas)

| Fichero | Para qué |
|---|---|
| [`compose.static.yml`](compose.static.yml) | Un contenedor: web estática sin root |
| [`compose.app-db.yml`](compose.app-db.yml) | App + PostgreSQL con dos redes y Docker secrets |
| [`compose.proxy-app-db.yml`](compose.proxy-app-db.yml) | nginx + app + PostgreSQL: solo el proxy publica puerto (estructura de panchi-bot) |
| [`compose.static-tunnel.yml`](compose.static-tunnel.yml) | Web estática + Cloudflare Tunnel en contenedor: sin puertos en el host y sin salida a Internet (estructura del portfolio) |

### Variante: el proxy es tu propio frontend (SPA + API, sin BD)

Caso `siege-map`: un frontend (React/Vite) que nginx sirve **y** que reenvía `/api` al backend. No hace falta otra plantilla: es `compose.proxy-app-db.yml` con tres cambios.

1. **`proxy`: se construye en vez de usar la imagen oficial + `nginx.conf` montado.** El `nginx.conf` va dentro de la imagen ([`Dockerfile.static-build`](../dockerfile/Dockerfile.static-build) ya lo copia).
   ```yaml
   proxy:
     <<: *hardening
     build:
       context: ./frontend
       args:
         VITE_MAP_KEY: ${MAP_KEY:-}     # SOLO valores públicos: acaban en el JS del navegador
     image: mi-app-frontend:${TAG:-latest}
     # sin volumes: ./nginx.conf (va en la imagen)
   ```
   En el Dockerfile, `ARG VITE_MAP_KEY` en la etapa de build, antes de `RUN npm run build`. Un `ARG` queda en `docker history`: nunca para secretos (RULE #12).
2. **Sin BD:** borrar el servicio `db`, la red `backend_net`, el volumen y el `depends_on: db` de `app`.
3. **Configuración del backend explícita.** No poner `env_file: .env`: compose ya lee `.env` para los `${...}`, y `env_file` lo mete **entero** en el contenedor, incluidas las variables que solo usa compose (build args, `TAG`, puertos). Las ve `docker inspect` y `contenedor.sh` las marca en `#12`. Usar `environment:` variable a variable o, si son muchas, un fichero propio (`env_file: backend.env`) que solo tenga lo del backend. Las claves, en `secrets:`.

## Patrón web + Cloudflare Tunnel en contenedor

1. Internet → Cloudflare → **túnel propio del proyecto** → **cloudflared** (contenedor, uid 65532).
2. **cloudflared** está en dos redes: `egress` (con salida, para hablar con Cloudflare) e `internal`.
3. **web** está **solo** en `internal` (`internal: true`): **sin `ports:`** y **sin salida a Internet**. Si alguien consigue ejecutar código dentro, no puede descargar herramientas ni abrir una reverse shell.
4. El token del túnel va como Docker secret con `--token-file`: ni en `environment` ni en la línea de comandos.
5. `internal` lleva **subred fija**: cloudflared está en ella, así que `set_real_ip_from` de `nginx.conf` sigue recibiendo la IP real (`CF-Connecting-IP`).

**Frente a cloudflared en el host (systemd):**

| | cloudflared en el host | cloudflared en el compose |
|---|---|---|
| Usuario | root (si la unidad no pone `User=`) | 65532, `read_only`, `cap_drop: ALL` |
| Puerto en el host | `127.0.0.1:<puerto>` por proyecto | Ninguno |
| Salida a Internet de la web | Sí (la red no puede ser `internal` si publica puerto) | No |
| Alcance si se compromete | Todas las webs del túnel | Solo este proyecto |
| Dónde vive la config | Panel + unidad de systemd | Panel + compose versionado en git |

**Un túnel por proyecto.** Si un único túnel del host sirve varias webs, no se puede apagar sin cortarlas todas: se migra proyecto a proyecto.

### Montarlo

```bash
# 1. Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared → nombre del proyecto.
#    En "Install connector" elegir Docker y copiar SOLO el token (lo que va tras --token, empieza por eyJ).
#    No ejecutar el comando que da el panel (usa :latest y el token en la línea de comandos).

# 2. Guardar el token (sin que se vea ni quede en el historial)
mkdir -m 700 secrets
read -rs -p "Token: " T; echo; printf '%s' "$T" > secrets/tunnel_token; unset T
chmod 444 secrets/tunnel_token
wc -l secrets/tunnel_token          # 0 → sin salto de línea final
git status --short                  # secrets/ NO debe aparecer

# 3. Levantar y comprobar que conecta
docker compose up -d --build
docker compose logs cloudflared | grep 'Registered tunnel connection'   # normalmente 4

# 4. Panel: rutas del túnel → http://web:8080 (nombre del SERVICIO y puerto de DENTRO)
docker compose logs cloudflared | grep 'Updated to new configuration'

# 5. DNS → Records: comprobar que existen @ y www como CNAME <tunnelID>.cfargotunnel.com (proxied)
docker compose logs cloudflared | grep -o 'tunnelID=[a-f0-9-]*' | head -1
```

### Migrar un proyecto desde el cloudflared del host

1. Crear el túnel nuevo y el secreto (pasos 1-2). Hasta aquí no se corta nada.
2. `docker compose down` **con el compose viejo** (o `docker rm -f` + `docker network rm` de la red vieja): la red nueva usa la misma subred y chocaría (`Pool overlaps`).
3. `git pull` + `docker compose up -d --build`. **Desde aquí la web está caída.**
4. Panel: borrar las rutas del túnel viejo y añadirlas al nuevo.
5. **DNS → Records:** al quitar la ruta del túnel viejo, Cloudflare borra el registro DNS y puede no recrearlo (error **1016**). Crearlo a mano: CNAME `@` / `www` → `<tunnelID>.cfargotunnel.com`, proxied.
6. Si tu navegador sigue sin resolver, es la caché DNS de tu red (guardó el "no existe"): `dig @1.1.1.1` lo confirma.

## Patrón proxy + app + base de datos

1. Internet → Cloudflare Tunnel / nginx del host (HTTPS) → `127.0.0.1:8081` → **proxy** ([`nginx/proxy.conf`](../nginx/proxy.conf)).
2. **proxy** (nginx, uid 101) está **solo** en `web_net`: habla con la app, no ve la BD.
3. **app** está en `web_net` y `backend_net`, **sin `ports:`** → no se puede llegar a ella saltándose nginx.
4. **db** está **solo** en `backend_net` (`internal: true`).
5. `web_net` lleva **subred y gateway fijos**: es la única IP de la que nginx acepta la cabecera con la IP real.
6. Lo común (`read_only`, `cap_drop`, `no-new-privileges`, `restart`, `logging`) va en un anchor `x-hardening` → no se olvida en ningún servicio.

¿Cuándo este y cuándo `compose.app-db.yml`? Con proxy propio, las cabeceras, el rate limit y el filtro de Host viajan con el proyecto y se prueban en local. Sin él, todo eso hay que ponerlo en el nginx del host.

## Patrón app + base de datos: dos redes

1. Internet → Cloudflare / nginx del host (HTTPS) → `127.0.0.1:8000` → **app**.
2. **app** (gunicorn + Flask, uid 10001) está en `frontend_net` **y** en `backend_net`: recibe del proxy y habla con la BD.
3. **db** (PostgreSQL, uid 70) está **solo** en `backend_net`, que es `internal: true` → sin puertos publicados, sin salida a Internet, el proxy no la alcanza.

## Secretos en la app: leerlos del fichero leer secretos y endpoint `/health`

```python
# app/__init__.py
import os
from flask import Flask, jsonify
import psycopg

def read_secret(name: str) -> str:
    """Docker secrets se montan como ficheros en /run/secrets/<nombre>."""
    with open(f"/run/secrets/{name}", encoding="utf-8") as f:
        return f.read().strip()

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = read_secret("flask_secret_key")

    dsn = (f"host={os.environ['DB_HOST']} dbname={os.environ['DB_NAME']} "
           f"user={os.environ['DB_USER']} password={read_secret('db_password')}")

    # /health comprueba de verdad que llega a la BD, no solo que el proceso vive
    @app.get("/health")
    def health():
        with psycopg.connect(dsn, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok")

    return app
```
```python
# wsgi.py
from app import create_app
app = create_app()
```

- Lo **no sensible** (host, nombre de BD, usuario) → `environment:`.
- Lo **sensible** (contraseñas, claves) → `secrets:` → fichero. **Nunca** en `environment:` (se ve con `docker inspect`).
- Detrás de un proxy, para que Flask vea la IP/esquema reales:
  ```python
  from werkzeug.middleware.proxy_fix import ProxyFix
  app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)   # 1 = un proxy delante
  ```

## Crear los secretos

```bash
mkdir -p secrets && chmod 700 secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > secrets/db_password.txt
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > secrets/flask_secret_key.txt
chmod 444 secrets/*.txt
echo "secrets/" >> .gitignore
```

**¿Por qué 444 y no 400?** En compose (sin Swarm) un secreto es un *bind mount*: dentro del contenedor el fichero conserva el dueño y permisos del host. Con `400` y dueño tu usuario, el uid 10001 (app) y el 70 (postgres) **no podrían leerlo**. La protección en el host la da el **directorio** `secrets/` con `700`: ningún otro usuario del host puede entrar.

> ⚠ `POSTGRES_PASSWORD_FILE` solo se usa **la primera vez** (cuando el volumen está vacío). Cambiar el fichero después **no** cambia la contraseña de la BD → hacerlo con `ALTER USER app PASSWORD '...'` y luego actualizar el fichero.

## Varios proyectos en el mismo VPS

> Cada proyecto: **puerto del host distinto** (8089, 8090...) y **subred distinta** (172.30.89.0/24, 172.30.90.0/24...).
> Si no hay logs al host, `/var/log/nginx` en la imagen son symlinks a stdout/stderr → `docker logs mi-web`.

---

## Preguntas de repaso

1. ¿Por qué montar `docker.sock` en `:ro` no protege nada?
2. ¿Qué diferencia hay entre `userns-remap` y rootless?
3. ¿Por qué un puerto publicado como `8080:8080` puede estar abierto aunque UFW lo bloquee?
4. ¿Qué hace exactamente `no-new-privileges`? ¿Qué ataque concreto frena?
5. ¿Por qué `COPY secreto && rm secreto` en el Dockerfile no sirve?
6. ¿Qué significa `CapEff: 0000000000000000` y `Seccomp: 2` en `/proc/self/status`?
7. ¿Por qué fijar por digest y no solo por tag?
8. ¿Qué riesgo hay en un volumen escribible compartido con el host que procesa root?
9. ¿Contra qué **no** protege Docker rootless?
10. Si encuentras `CAP_SYS_ADMIN` en un contenedor durante un pentest, ¿qué probarías?
