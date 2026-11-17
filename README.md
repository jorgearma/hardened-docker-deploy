# Docker + nginx: guía de despliegue seguro

Lo que necesito saber para escribir un **Dockerfile**, un **docker-compose** y un **nginx.conf** endurecidos, explicado línea a línea y con configs de referencia **probadas atacándolas desde dentro**.

Basado en la [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), las reglas de hadolint y lo que he aprendido desplegando mis propias apps.

## Índice

| Quiero saber… | Ir a |
|---|---|
| Cómo escribir un Dockerfile seguro (imagen, usuario, secretos, multi-stage…) | [`dockerfile/`](dockerfile/README.md) |
| Qué poner en el compose (sin root, read-only, capabilities, redes, límites, secretos) | [`compose/`](compose/README.md) |
| Cómo configurar nginx (cabeceras, CSP, `location`, caché, rutas sensibles) | [`nginx/`](nginx/README.md) |
| Cómo comprobar que un contenedor está bien endurecido | [`verificacion/`](verificacion/README.md) |
| Qué me ha salido mal y cómo lo arreglé | [`errores-vividos.md`](errores-vividos.md) |

## Lo que garantizan todas las configs

- Proceso **sin root** (`USER` en el Dockerfile o `user:` en el compose).
- Sistema de ficheros **read-only**; solo `/tmp` escribible, con `noexec`.
- `cap_drop: [ALL]` + `no-new-privileges`.
- Puertos publicados **solo en `127.0.0.1`** (Docker se salta UFW).
- Secretos **fuera de la imagen** (Docker secrets, nunca `ENV`/`ARG`).
- Imágenes fijadas por **versión + digest**.
- Límites de memoria, CPU y procesos.

## Configs de referencia

| Carpeta | Ficheros |
|---|---|
| `dockerfile/` | `Dockerfile.static` · `Dockerfile.static-build` · `Dockerfile.python` · `dockerignore.*` |
| `compose/` | `compose.static.yml` · `compose.app-db.yml` · `compose.proxy-app-db.yml` |
| `nginx/` | `static.conf` · `proxy.conf` · `host-vhost.conf` (nginx del host, HTTPS) |

## Licencia

[MIT](LICENSE)
