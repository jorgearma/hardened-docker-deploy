---
name: docker-nginx-seguro
description: Escribir, endurecer o auditar un Dockerfile, un docker-compose o un nginx.conf, y desplegar una app en contenedor en un VPS (web estática, app + base de datos, o nginx proxy + app + base de datos). Usar cuando se pida crear o revisar cualquiera de esos ficheros, "dockerizar" un proyecto, poner nginx delante de una app, comprobar si un contenedor está bien endurecido, o aplicar la OWASP Docker Security Cheat Sheet.
disable-model-invocation: true
---

# Docker + nginx: despliegue seguro

Este repo es una guía con configs de referencia **ya probadas atacándolas desde dentro**. No escribas un Dockerfile, compose o nginx.conf desde cero: parte de la plantilla del caso y adáptala.

Todas las rutas de este fichero son relativas a la carpeta de la skill (la raíz de este repo). Los ficheros que generes van en el proyecto del usuario, no aquí.

## 1. Elegir el caso

| Caso | Dockerfile | Compose | nginx |
|---|---|---|---|
| Web estática (HTML/CSS/JS tal cual) | `dockerfile/Dockerfile.static` | `compose/compose.static.yml` | `nginx/static.conf` |
| Web estática con paso de build (npm) | `dockerfile/Dockerfile.static-build` | `compose/compose.static.yml` | `nginx/static.conf` |
| App Python + base de datos, sin nginx propio | `dockerfile/Dockerfile.python` | `compose/compose.app-db.yml` | — |
| nginx proxy + app + base de datos | `dockerfile/Dockerfile.python` | `compose/compose.proxy-app-db.yml` | `nginx/proxy.conf` |
| Web estática servida por Cloudflare Tunnel (túnel propio del proyecto) | `dockerfile/Dockerfile.static` o `Dockerfile.static-build` | `compose/compose.static-tunnel.yml` | `nginx/static.conf` (con `set_real_ip_from` = subred `internal`) |

- `.dockerignore`: copiar `dockerfile/dockerignore.static` o `dockerfile/dockerignore.python` como `.dockerignore`.
- HTTPS: si el TLS lo termina el nginx del host, añadir `nginx/host-vhost.conf`. Con Cloudflare Tunnel no hace falta.
- Si el proyecto no encaja en ningún caso (otro lenguaje, otra BD), usa la plantilla más parecida y di qué has cambiado y qué queda sin probar.

Si no está claro qué caso es, o faltan datos que no se pueden deducir del proyecto (dominio, quién termina el TLS, puerto libre en el host), pregunta antes de generar.

## 2. Qué leer antes de tocar cada fichero

Lee solo lo que corresponda al fichero que vas a escribir o revisar:

| Vas a tocar… | Lee |
|---|---|
| Dockerfile | `dockerfile/README.md` (sobre todo "Qué es fijo y qué se adapta") |
| Compose | `compose/README.md` (chuleta rápida + la regla que aplique; "Varios proyectos en el mismo VPS" si no es el primero) |
| nginx | `nginx/README.md` ("Quién hace qué" y las secciones "Trampas") |
| Límites, usuarios, cualquier cosa que ya falló antes | `errores-vividos.md` — **siempre** |

`owasp/docker-security-cheat-sheet.md` es la copia del original: consúltala solo para citar el texto exacto de una regla.

## 3. Invariantes

Toda config que salga de aquí cumple esto. Si algo obliga a saltarse un punto, no lo quites en silencio: dilo, explica por qué y qué riesgo deja abierto.

1. Proceso **sin root** (`USER` en el Dockerfile o `user:` en el compose).
2. Sistema de ficheros **read-only**; solo `/tmp` escribible, con `noexec,nosuid,nodev`.
3. `cap_drop: [ALL]` + `no-new-privileges:true`. `cap_add` solo justificado.
4. Puertos publicados **solo en `127.0.0.1`** (Docker se salta UFW), o ninguno si el túnel va en el compose.
5. Secretos **fuera de la imagen**: Docker secrets, nunca `ENV`/`ARG` ni en el repo.
6. Imágenes fijadas por **versión + digest**.
7. Límites de memoria, CPU y procesos (`pids_limit`, **no** `ulimits.nproc`).

Nunca: `privileged: true`, montar `docker.sock`, `seccomp=unconfined` / `apparmor=unconfined`.

## 4. Adaptar la plantilla

- Conserva los comentarios de la plantilla que explican el porqué de cada línea; quita los que no apliquen al proyecto.
- Cambia nombres (`mi-app`, `mi-web`), puertos del host (únicos por proyecto en el VPS) y subredes.
- En proxy + app + db: la subred/gateway de `web_net` está en el compose **y** en `proxy.conf` (`set_real_ip_from`). Si cambias uno, cambia el otro.
- Las cabeceras de seguridad van en el nginx del contenedor; en el del host solo TLS y HSTS (si se repiten, llegan duplicadas).
- No reutilices los digests de las plantillas sin comprobarlos: obtén el actual con `docker pull` + `docker inspect --format '{{index .RepoDigests 0}}'`. Si no puedes ejecutar Docker, deja el de la plantilla y avisa de que hay que actualizarlo.

## 5. Verificar (obligatorio antes de dar nada por terminado)

Con el contenedor arriba, en la máquina donde corre:

```bash
V=<carpeta de la skill>/verificacion
$V/contenedor.sh <contenedor> [<contenedor>...]      # o --todos
$V/web.sh -e http://127.0.0.1:<puerto>               # web estática
$V/web.sh -H <dominio> -l <ruta-login> -b 2 http://127.0.0.1:<puerto>   # proxy + app
sudo $V/host.sh                                      # el VPS y el daemon
$V/herramientas.sh imagen <imagen:tag>               # trivy, dockle, hadolint...
$V/herramientas.sh nginx <ruta/nginx.conf>           # gixy
```

- Cada línea sale como `OK`, `FALLO`, `AVISO` o `MANUAL`; código de salida 1 si hay algún `FALLO`.
- Enseña la salida real. Un `FALLO` se arregla o se justifica; un `MANUAL` se le pasa al usuario.
- `web.sh -l` deja la IP limitada en el login un minuto; `contenedor.sh` crea y borra un fichero temporal dentro del contenedor. Avisa antes de lanzarlos contra algo en producción.
- Si no puedes ejecutarlos (no hay Docker, el contenedor está en otro equipo), dilo y deja los comandos exactos para que los pase el usuario. No declares la config "segura" sin esa salida.
- Para pruebas a mano y los resultados esperados: `verificacion/README.md` (secciones "Pruebas: …" y "Checklist de proyecto nuevo").

## 6. Auditar una config que ya existe

1. Identifica el caso y compárala con su plantilla y con los invariantes.
2. Si el contenedor está arriba, pasa los scripts del punto 5; si no, revisa los ficheros con la checklist de `dockerfile/README.md` y la chuleta de `compose/README.md`.
3. Informa por hallazgo: regla OWASP (`#N`) o hadolint (`DLxxxx`), qué línea, qué riesgo real deja y el cambio exacto. Ordena por gravedad.
4. No reescribas el fichero entero salvo que te lo pidan: propone los cambios mínimos.

## 7. Cuando algo falle de una forma nueva

Si aparece un fallo de despliegue que no está en `errores-vividos.md`, propón al usuario añadirlo con el mismo formato (síntoma, causa, arreglo, lección).
