# 3. Hallazgos

> **Alcance ampliado (2026-11-18):** además del portfolio, se revisó **radar** (panel de logs: backend Python + frontend nginx, en el mismo VPS), que en la fase 2 había quedado fuera. Sus hallazgos propios son **H-12 a H-18**; los que repiten un hallazgo del portfolio se anotan en ese hallazgo ("También en radar"). En radar no hubo reconocimiento externo propio: se partió de `contenedor.sh` y `web.sh`.

## Cómo se ha puntuado

- **CVSS 3.1 solo cuando hay un camino de ataque hoy**, sin depender de otro fallo previo (H-01, H-02). CVSS mide vulnerabilidades explotables; ponerle un 9 a "si hubiera un 0-day en cloudflared, sería root" infla el informe y le quita credibilidad.
- **Endurecimiento (defensa en profundidad):** los hallazgos que solo importan **después** de que falle otra capa (ejecución de código en un contenedor, UFW desactivado, un 0-day) se califican con una matriz probabilidad × impacto y sin vector CVSS. Se indica cuál es la condición previa.
- Calculadora: fórmula oficial de CVSS 3.1 (FIRST), comprobada para los dos vectores.

| Severidad | CVSS 3.1 | Criterio para endurecimiento |
|---|---|---|
| Crítica | 9.0–10.0 | — |
| Alta | 7.0–8.9 | — |
| Media | 4.0–6.9 | Condición previa probable o impacto alto en todo el host |
| Baja | 0.1–3.9 | Condición previa poco probable; reduce el daño si ocurre |
| Informativa | — | Buena práctica sin camino de ataque claro |

## Resumen

| ID | Hallazgo | Severidad | CVSS | Regla | Detectado por | Estado |
|---|---|---|---|---|---|---|
| H-01 | SSH: `PermitRootLogin yes` + contraseña, sin fail2ban | **Alta** | 8.1 *(provisional)* | CIS Ubuntu (SSH) | nmap `ssh-auth-methods` + `sshd -T` | Abierto |
| H-02 | HSTS de 30 días, sin `includeSubDomains` | Baja | 2.6 | OWASP Secure Headers | `web.sh` + testssl | Abierto |
| H-03 | Logs: bind mount del host escribible y con ejecución *(también radar: `/data`)* | Baja | — | OWASP #8 | `contenedor.sh` | Abierto · radar: aceptado |
| H-06 | nginx del host innecesario en `0.0.0.0:80`, con versión | Baja | — | OWASP #0 / CIS (servicios innecesarios) | `host.sh` → `ss` → `nginx -T` | Abierto |
| H-07 | cloudflared corre como root *(también radar)* | Baja | — | OWASP #2 | `systemctl show -p User` · `ps -C cloudflared` | **Mitigado** (portfolio) · radar: abierto |
| H-08 | Daemon sin `no-new-privileges`, `live-restore` ni `userland-proxy: false` | Baja | — | OWASP #4 / CIS 2.14-2.16 | docker-bench + `NoNewPrivs: 0` | Abierto |
| H-11 | Contenedor web con salida a Internet *(también radar)* | Baja | — | OWASP #5 | `contenedor.sh` | **Cerrado** (portfolio) · radar: abierto |
| H-12 | radar: API key en variables de entorno | Baja | — | OWASP #12 | `contenedor.sh` | Abierto |
| H-14 | radar: imagen del backend con `pip` | Baja | — | OWASP #13 / #8 | `contenedor.sh` | **Cerrado** |
| H-15 | radar: frontend con `curl`/`nc` y config de nginx escribible por nginx | Baja | — | OWASP #8 | `contenedor.sh` | **Cerrado** |
| H-16 | radar: sin límite de CPU | Baja | — | OWASP #7 | `contenedor.sh` | **Cerrado** |
| H-04 | nginx acepta cualquier `Host` *(también radar)* | Informativa | — | — | `web.sh` contra `127.0.0.1` | Abierto · radar: aceptado |
| H-05 | Imagen solo con `:latest` *(también radar)* | Informativa | — | OWASP #13 | `contenedor.sh` + dockle DKL-DI-0006 | Abierto · radar: corregido en el compose, falta desplegar |
| H-09 | Sin auditd para Docker | Informativa | — | CIS Docker 1.1.x | docker-bench | Abierto |
| H-10 | Docker una versión menor por detrás | Informativa | — | OWASP #0 | `apt list --upgradable` | Abierto |
| H-17 | radar: imágenes base sin digest y desactualizadas (Node 20 sin soporte, nginx 1.27) | Informativa | — | OWASP #13 / #0 | `contenedor.sh` (`MANUAL #13`) + Dockerfile | **Cerrado** |
| H-18 | radar: frontend sin healthcheck | Informativa | — | — | `contenedor.sh` | **Cerrado** |
| H-13 | radar: panel público sin login | *Por decidir* | *5.3 si no debe ser público* | — | Navegación + fase 2 | Abierto |

**Recuento:** 1 Alta · 10 Baja · 6 Informativa · 1 por decidir (H-13) · 0 Crítica · 0 Media.
Portfolio: 1 Alta · 6 Baja · 4 Informativa. Radar: 4 Baja · 2 Informativa · 1 por decidir (+ 5 que repiten H-03/04/05/07/11).

---

## H-01 — SSH permite root y contraseña, sin protección contra fuerza bruta

- **Severidad:** Alta · **CVSS 3.1:** 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) — *provisional*
- **Componente:** host (OpenSSH)
- **Detectado por:** fase 1, `nmap --script ssh-auth-methods` (`password` aceptado) · fase 2, `sshd -T`

**Descripción.** El único servicio expuesto a Internet acepta autenticación por contraseña, permite entrar directamente como root y no hay nada que limite los intentos.

**Evidencia.**

```text
$ sudo sshd -T
permitrootlogin yes
passwordauthentication yes
maxauthtries 6
$ systemctl is-active fail2ban
inactive
```

**Vector.**

- `AV:N` — accesible desde Internet (puerto 22, único abierto).
- `AC:H` — el éxito depende de que alguna contraseña sea adivinable, algo que el atacante no controla.
- `PR:N / UI:N` — no necesita credenciales previas ni que nadie haga nada.
- `C:H / I:H / A:H` — acceso como root (o como un usuario del grupo `sudo`): control total del host y de todos los contenedores.

**Por qué es provisional.** Faltan dos datos (SSH aparcado a petición del propietario):

- `passwd -S root`: si root tiene la contraseña **bloqueada**, `PermitRootLogin yes` no permite entrar con contraseña como root. Seguiría el camino por el usuario normal del grupo `sudo`.
- Intentos reales en `journalctl -u ssh`, que confirmarían que se está atacando.

Si la contraseña de algún usuario fuera débil o reutilizada, el vector pasa a `AC:L` → **9.8 (Crítica)**.

**Impacto.** Compromiso total del VPS: todas las webs, sus datos y el token del túnel compartido. El endurecimiento de los contenedores no protege de esto.

**Remediación.** `PasswordAuthentication no`, `PermitRootLogin no`, `KbdInteractiveAuthentication no`; revisar `/etc/ssh/sshd_config.d/` (en Ubuntu, `50-cloud-init.conf` suele activar la contraseña y se lee primero). Opcional: fail2ban, `MaxAuthTries 3`, `X11Forwarding no`. Probar la entrada con clave en otra sesión antes de reiniciar `sshd`.

---

## H-02 — HSTS corto y solo para el dominio principal

- **Severidad:** Baja · **CVSS 3.1:** 2.6 (`AV:A/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`)
- **Componente:** Cloudflare (Edge Certificates)
- **Detectado por:** `web.sh` (`HSTS: max-age=2592000`) · testssl (`30 days is too short`)

**Descripción.** `Strict-Transport-Security: max-age=2592000` (30 días), sin `includeSubDomains` ni `preload`.

**Vector.** Un atacante en la misma red que el visitante (`AV:A`, p. ej. una wifi pública) puede interceptar la primera petición HTTP de alguien que no ha visitado la web en 30 días (`AC:H`, `UI:R`) y servirle una versión modificada (`I:L`). Web estática, sin cookies ni formularios: no hay datos que robar (`C:N`).

**Remediación.** En Cloudflare: `max-age` de 1 año (`31536000`) e `includeSubDomains`, después de comprobar que todos los subdominios funcionan por HTTPS. `preload` solo cuando se tenga claro que no habrá vuelta atrás.

---

## H-03 — El volumen de logs permite escribir y ejecutar

- **Severidad:** Baja (endurecimiento)
- **Condición previa:** ejecución de código en el contenedor web (uid 101).
- **Componente:** contenedor web (compose)
- **Detectado por:** `contenedor.sh`

```text
[ AVISO] #8  bind mounts con escritura: <logs-host>->/var/log/nginx
[ AVISO] #8  activa: se puede ejecutar desde volúmenes escribibles: /var/log/nginx
```

**Descripción.** El resto del contenedor es de solo lectura y `/tmp` lleva `noexec`. El directorio de logs, montado desde el host, es el único sitio donde se puede escribir **y** ejecutar.

**Impacto.** Si alguien consigue ejecutar código en nginx, puede dejar ahí un binario y lanzarlo, saltándose el `noexec`. Además escribe en un directorio del host que procesa otra herramienta (el panel de logs) y logrotate.

**Remediación.** Montarlo con `noexec,nosuid,nodev`: con sintaxis larga de volumen sobre un sistema de ficheros del host montado con esas opciones, o enviar los logs por stdout y que el panel los lea de `docker logs`.

**También en radar (aceptado).** El volumen con nombre `/data` (SQLite) del backend es escribible y ejecutable:

```text
[ AVISO] #8  activa: se puede ejecutar desde volúmenes escribibles: /data (ahí dejaría su binario un atacante)
```

Se acepta: el driver `local` de Docker ignora `noexec` en un bind (comprobado en `/proc/mounts`, ver `errores-vividos.md`), y la imagen trae `python`, así que `python /data/x.py` funcionaría igual con `noexec`. Lo que limita a un atacante es el resto del endurecimiento (sin root, sin capabilities, read-only) y que la imagen ya no lleve `pip` (H-14).

---

## H-06 — nginx del host instalado y escuchando sin uso

- **Severidad:** Baja (endurecimiento)
- **Condición previa:** que UFW deje de filtrar (desactivación, error de reglas) o que el VPS reciba IPv6 pública sin reglas.
- **Componente:** host
- **Detectado por:** `host.sh` (`puertos TCP escuchando en interfaces públicas: 22 80`) → `ss -tlnp` → `nginx -T` → `curl -sI`

```text
LISTEN 0.0.0.0:80   nginx
LISTEN    [::]:80   nginx
sites-enabled/default → root /var/www/html; server_name _;
Server: nginx/1.24.0 (Ubuntu)
```

**Descripción.** Paquete nginx de Ubuntu con el sitio por defecto, arranca con el sistema, escucha en todas las interfaces y expone su versión. Ninguna web lo usa. Desde fuera aparece `filtered` (fase 1): la única barrera es UFW.

**Remediación.** `systemctl disable --now nginx` o `apt purge nginx nginx-common`.

---

## H-07 — cloudflared corre como root

- **Severidad:** Baja (endurecimiento) · **Estado:** mitigado para el portfolio
- **Condición previa:** una vulnerabilidad de ejecución remota en cloudflared.
- **Componente:** host (servicio systemd)
- **Detectado por:** `systemctl show cloudflared -p User` → `User=` vacío (systemd ejecuta como root)

**Descripción.** El proceso que recibe **todo** el tráfico de las webs del VPS corre como root, fuera de cualquier contenedor, y un único túnel sirve a todos los proyectos.

**Impacto.** Un fallo explotable en cloudflared daría root en el host directamente, sin pasar por el aislamiento de los contenedores, y afectaría a todas las webs a la vez.

**Remediación.** Aplicada para el portfolio: túnel propio en un contenedor (uid 65532, read-only, sin capabilities). Se cierra al migrar el resto de proyectos y apagar el servicio del host.

**También en radar (abierto).** Evidencia directa del proceso, con el túnel del portfolio ya en contenedor al lado:

```text
$ ps -o user,pid,cmd -C cloudflared
USER         PID CMD
root        5730 /usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token
65532    2160263 cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:20241 run --token-file /run/secrets/tunnel_token

$ sudo ss -tunap      # extracto
tcp ESTAB 172.20.0.1:50188  172.20.0.3:3000  users:(("docker-proxy",...))    ← ×18, frontend de radar
```

Camino actual de radar: `cloudflared` del host (root) → `127.0.0.1:<puerto>` → `docker-proxy` (root) → frontend. Se cierra con un túnel propio en el compose de radar (mismo patrón que el portfolio).

---

## H-08 — El daemon no aplica protecciones por defecto

- **Severidad:** Baja (endurecimiento)
- **Condición previa:** lanzar un contenedor sin las opciones en su compose, o reiniciar el daemon.
- **Componente:** daemon de Docker (`/etc/docker/daemon.json`)
- **Detectado por:** docker-bench `[WARN] 2.14`, `2.15`, `2.16` · confirmado a mano:

```text
$ sudo docker info --format '{{json .SecurityOptions}}'
["name=apparmor,profile=default","name=seccomp,profile=builtin","name=cgroupns"]
$ sudo docker run --rm alpine grep NoNewPrivs /proc/self/status
NoNewPrivs:    0
```

**Descripción.**

- `no-new-privileges` no es el valor por defecto: solo lo tienen los contenedores que lo piden en su compose (el portfolio sí).
- Sin `live-restore`: actualizar o reiniciar Docker (hay una actualización pendiente, H-10) tira **todos** los contenedores.
- Con `userland-proxy`: un proceso `docker-proxy` por puerto publicado.

**Remediación.**

```json
{ "no-new-privileges": true, "live-restore": true, "userland-proxy": false }
```

Reiniciar el daemon en una ventana de mantenimiento y comprobar que todos los proyectos siguen funcionando: `userland-proxy: false` cambia cómo llegan las conexiones a `127.0.0.1:<puerto>`.

---

## H-11 — El contenedor web podía salir a Internet

- **Severidad:** Baja (endurecimiento) · **Estado:** cerrado
- **Condición previa:** ejecución de código en el contenedor web.
- **Detectado por:** `contenedor.sh` → `[ INFO ] #5 redes: <red>(con salida)`

**Impacto.** Con ejecución dentro, descargar herramientas (`wget` disponible), abrir una reverse shell o usar el VPS contra terceros. Una web estática no necesita iniciar conexiones.

**Remediación.** Red `internal: true` + túnel en el mismo compose. Retest: `wget: bad address` → [`04-retest.md`](04-retest.md).

**También en radar (abierto).** El frontend (nginx) está en una red con salida (`[ INFO ] #5 redes: <red>(con salida)`) y no la necesita. A diferencia del portfolio, el **backend sí necesita salida** (geolocalización, AbuseIPDB, lista de nodos Tor), así que no basta con una sola red `internal`: frontend solo en `internal`; backend y cloudflared en `internal` + red con salida.

---

## H-12 — radar: API key en variables de entorno

- **Severidad:** Baja (endurecimiento) · **Estado:** abierto
- **Condición previa:** acceso a `docker inspect` (root o sudo en el host) o una fuga del entorno del proceso (traza de error, volcado de depuración, log).
- **Componente:** radar, backend (compose)
- **Detectado por:** `contenedor.sh`

```text
[ FALLO] #12 posibles secretos en variables de entorno (se ven con docker inspect): CARTO_API_KEY ABUSEIPDB_API_KEY
```

**Descripción.** El backend recibe su configuración con `env_file: .env`, que mete **todo** el `.env` en el contenedor: la key privada de AbuseIPDB y también la de Carto, que el backend no usa (solo la necesita el frontend como argumento de build, por interpolación del compose). La de Carto es pública por diseño (acaba en el JS del navegador, restringida por dominio); la de AbuseIPDB no.

**Impacto.** Una variable de entorno se ve en `docker inspect`, en `/proc/<pid>/environ`, la heredan los procesos hijos y muchas herramientas la vuelcan al fallar. Con la key, un tercero consume la cuota de la cuenta o la usa en su nombre.

**Lección de la propia auditoría.** El comando usado para localizar dónde se definían las keys (`grep -rn "..._API_KEY" --include=*.env* .`) **mostró sus valores en claro**. Para inventariar secretos, sacar solo los nombres: `grep -E '^[A-Z_]+=.+' .env | cut -d= -f1`. La key de AbuseIPDB se considera expuesta y hay que regenerarla.

**Remediación.** Un fichero por secreto en `secrets/` (700, ficheros 444, en `.gitignore`), declarado en `secrets:` solo para el backend; la app lo lee de `/run/secrets/<nombre>` vía `<NOMBRE>_FILE`. Separar el `.env` de interpolación del compose (donde se queda la key pública de Carto) de la configuración del backend. Regenerar la key de AbuseIPDB.

---

## H-14 — radar: la imagen del backend lleva `pip`

- **Severidad:** Baja (endurecimiento) · **Estado:** cerrado
- **Condición previa:** ejecución de código en el backend (uid 10001).
- **Componente:** radar, Dockerfile del backend · y la plantilla `dockerfile/Dockerfile.python`
- **Detectado por:** `contenedor.sh`

```text
[ INFO ] herramientas disponibles para un atacante: pip apt-get
```

**Descripción.** Dockerfile de una sola etapa con `pip install` en el sistema. Combinado con `/data` escribible y ejecutable (H-03), un atacante con ejecución podría instalar paquetes ahí (`pip install --target /data/...`).

**Hallazgo en la plantilla.** Al comparar con `Dockerfile.python` se vio que la plantilla **tampoco** lo quitaba del todo: borraba el `pip` del venv, pero no el del sistema (`/usr/local/bin/pip`), y su prueba (`python -m pip --version`) daba un falso "No module named pip" porque `python` es el del venv. Cualquier imagen construida con la plantilla anterior lo lleva.

**Remediación aplicada.** Dockerfile en dos etapas (venv en la de build) y, en la final, `RUN /usr/local/bin/python -m pip uninstall -y pip`. Corregidos también la plantilla y su prueba. Retest: `which pip pip3` vacío y `No module named pip` con los dos intérpretes; `contenedor.sh` → `herramientas disponibles: apt-get` (sin root no instala nada).

---

## H-15 — radar: frontend con `curl`/`nc` y config de nginx escribible por nginx

- **Severidad:** Baja (endurecimiento) · **Estado:** cerrado
- **Condición previa:** ejecución de código en el frontend (uid 101).
- **Componente:** radar, Dockerfile del frontend
- **Detectado por:** `contenedor.sh` + `ls -ld /etc/nginx` dentro de la imagen

```text
[ INFO ] herramientas disponibles para un atacante: curl wget nc apk
drwxrwxr-x  nginx  root  /etc/nginx
```

**Descripción.** La imagen final era `nginx-unprivileged` tal cual: con `curl` y `nc` (reverse shell con `nc -e`) y `/etc/nginx` con dueño `nginx`. Hoy lo tapa `read_only: true` del compose; si esa línea se quitara, nginx podría reescribir su propia configuración.

**Remediación aplicada.** `apk del curl`, `rm /usr/bin/nc`, `chown -R root:root /etc/nginx` y web copiada como root (plantilla `Dockerfile.static-build`). Retest: `herramientas disponibles: wget apk` (`wget` lo usa el healthcheck; `apk` no instala sin root) y `/etc/nginx` de root.

---

## H-16 — radar: sin límite de CPU

- **Severidad:** Baja (endurecimiento) · **Estado:** cerrado
- **Condición previa:** un bucle en la app o un pico de tráfico/ataques (el backend procesa cada línea de log).
- **Componente:** radar, compose
- **Detectado por:** `contenedor.sh` → `[ AVISO] #7 sin límite de CPU` (backend y frontend)

**Impacto.** Sin límite, un solo contenedor puede ocupar toda la CPU del VPS (2 núcleos) y dejar sin servicio al portfolio, a los demás proyectos y a SSH. Es el riesgo que la fase 2 ya apuntaba como "fuera del alcance, pero relevante".

**Remediación aplicada.** `cpus: "1.0"` en el backend y `"0.5"` en el frontend. Retest: `[ OK ] #7 límite de CPU` en los dos.

---

## Informativos

| ID | Hallazgo | Por qué no sube de informativo | Recomendación |
|---|---|---|---|
| H-04 | nginx responde 200 a cualquier `Host` (`server_name _;`) | Web estática sin URLs absolutas ni cookies: no hay envenenamiento de caché ni de enlaces que explotar. Desde fuera Cloudflare ya filtra, y tras la remediación solo cloudflared llega a nginx. **Radar (aceptado):** igual, y además el backend no usa el `Host` para nada (ni `request.url`, ni `base_url`, ni cabeceras); por Cloudflare, `web.sh` → `Host inventado rechazado (403)` | `server_name <dominio> www.<dominio>` + `default_server` con `return 444`. Ojo: el healthcheck pide `Host: 127.0.0.1` y se rompería (ver `errores-vividos.md`) |
| H-05 | Imagen etiquetada solo `:latest` | No es explotable; afecta a la trazabilidad y a la vuelta atrás. **Radar:** corregido en el compose (`image: <imagen>:${TAG:-latest}`); falta desplegar con `TAG` (el primer despliegue salió en `:latest`, probablemente porque `TAG=x sudo …` pierde la variable) | Etiquetar con el commit: `TAG=$(git rev-parse --short HEAD) docker compose up -d --build`. Para volver atrás, comprobar antes que la imagen existe (ver `errores-vividos.md`) |
| H-09 | Sin auditd sobre Docker | No previene nada; sin él, un incidente deja menos rastro | `auditd` con reglas para `docker.service`, `/etc/docker`, `/var/lib/docker`, `containerd`, `runc` |
| H-10 | Docker 29.9.3 → 29.10.0 pendiente | Ningún paquete del canal `-security` de Ubuntu pendiente; sin revisar si 29.10.0 corrige CVEs | Actualizar después de aplicar `live-restore` (H-08) |
| H-17 | radar: `FROM` sin digest; build con Node 20 (sin parches) y nginx 1.27 | Sin CVE concreto explotable; cada build podía bajar una base distinta | **Cerrado:** `python:3.12-slim`, `node:22-alpine` y `nginx-unprivileged:1.30-alpine` fijadas por digest; `npm ci --ignore-scripts` con lockfile |
| H-18 | radar: frontend sin healthcheck | Si nginx se cuelga, Docker no lo detecta ni lo reinicia | **Cerrado:** `wget` a `127.0.0.1:3000/` en el compose (no `localhost`: en Alpine resuelve a `::1`) y el frontend espera a que el backend esté `healthy` |
| H-13 | radar: panel público sin login | Muestra los ataques SSH/HTTP al VPS (IPs de bots, usuarios probados) y los visitantes del portfolio con el último octeto oculto. **Por decidir:** si es una demo pública intencionada, se acepta; si no, `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3 (Media)**. Pendiente comprobar que la API no devuelve más que la pantalla | Cloudflare Access (login) delante de la ruta |

## Descartados

| Indicio | Por qué se descarta |
|---|---|
| ICMP *admin-prohibited* en nmap | Lo envía la red de origen (CGNAT, `ttl=63`), no el VPS |
| dockle `FATAL CIS-DI-0010` | `KEY_SHA512` en una capa de la imagen base: hash de la clave **pública** de nginx.org |
| testssl: BREACH | Página estática, sin secretos ni cookies en la respuesta |
| testssl: LUCKY13 | Suites CBC de Cloudflare por compatibilidad; ataque no práctico |
| testssl: OCSP stapling | Let's Encrypt dejó de ofrecer OCSP en 2025 |
| gixy `try_files_is_evil_too` | Rendimiento, no seguridad |
| radar: uvicorn con `--forwarded-allow-ips=*` | El backend no lee la IP del cliente en ningún sitio (las IPs salen de los logs, no de las peticiones) y solo el frontend comparte red con él |
| radar: `web.sh` → `sin rate limit en /api/...` | Falso positivo: `limit_req … burst=30` y el script mandaba 20 peticiones. Con `-n 60`: `27 de 60 peticiones → 429` |
