# 2. Auditoría interna inicial

Estado del VPS **antes** de tocar nada. Salidas completas en [`evidencias/antes/`](evidencias/antes/).

- **Fecha:** 2026-11-17
- **Copia de seguridad hecha:** sí (`tar` del proyecto + imagen etiquetada como `:pre-audit`)
- **Objetivo:** contenedor `<portfolio>` (nginx-unprivileged, web estática), publicado en `127.0.0.1:<puerto>` y servido por `cloudflared` en el host

## Contenedores: `contenedor.sh`

```text
== Contenedor: <portfolio> ==
  [  OK  ] #1  no monta el socket de Docker
  [  OK  ] #2  proceso principal sin root (uid 101, User='101')
  [  OK  ] #2  no es --privileged
  [  OK  ] #3  cap_drop: ALL
  [  OK  ] #3  CapBnd = 0 (ninguna capability alcanzable dentro del contenedor)
  [  OK  ] #3  CapEff = 0 (el proceso principal no tiene ninguna capability activa)
  [  OK  ] #4  no-new-privileges activo
  [  OK  ] #5  red propia
  [ INFO ] #5  redes: <red-portfolio>(con salida)
  [  OK  ] #5a puertos solo en localhost: 127.0.0.1:<puerto>->8080/tcp
  [  OK  ] #6  seccomp en modo filtro
  [  OK  ] #6  AppArmor: docker-default
  [  OK  ] #7  límite de memoria: 128 MB
  [  OK  ] #7  pids_limit: 100
  [  OK  ] #7  límite de CPU
  [  OK  ] #8  sistema de ficheros read-only
  [ AVISO] #8  bind mounts con escritura: <ruta-logs-host>->/var/log/nginx
  [  OK  ] #12 ninguna variable de entorno con pinta de secreto
  [MANUAL] #13 imagen construida en local (<portfolio>:latest): comprobar que el FROM lleva @sha256
  [ AVISO] #13 <portfolio>:latest sin versión en la etiqueta: no se sabe qué build está en marcha ni se puede volver atrás
  [  OK  ] healthcheck: healthy
  [  OK  ] #8  activa: no se puede escribir en /, /etc, código ni librerías
  [  OK  ] #8  activa: escribible pero sin ejecución (noexec): /dev/shm /tmp
  [ AVISO] #8  activa: se puede ejecutar desde volúmenes escribibles: /var/log/nginx
  [  OK  ] #4  activa: sin binarios SUID
  [ INFO ] herramientas disponibles para un atacante: wget nc apk

Resumen: 20 OK · 0 FALLO · 3 AVISO · 1 MANUAL
```

| Resultado | Valoración |
|---|---|
| uid 101, sin capabilities, no-new-privileges, seccomp, AppArmor, límites, read-only | ✅ El endurecimiento del proceso es completo |
| #13 `FROM` con digest | ✅ Comprobado a mano: `FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:<digest>` |
| #8 `/var/log/nginx`: bind mount del host, escribible **y con ejecución** | ⚠️ Es la única vía para saltarse el `noexec` de `/tmp`. Además el directorio es del host y lo lee otra herramienta (el panel de logs) → hallazgo |
| #13 etiqueta `:latest` sin versión | ⚠️ Sin trazabilidad ni rollback → hallazgo bajo |
| Red con salida a Internet | ⚠️ Una web estática no necesita iniciar conexiones. Con ejecución dentro, un atacante puede descargar herramientas (`wget` está disponible) o abrir una reverse shell → H-11. `internal: true` no vale tal cual (impide publicar el puerto que usa `cloudflared`), pero hay alternativas |
| `wget`, `nc`, `apk` disponibles | Informativo: `wget` lo usa el healthcheck; `apk` no sirve sin root; `nc` viene en busybox |

## nginx sin Cloudflare delante: `web.sh` contra `127.0.0.1`

```text
== Web: http://127.0.0.1:<puerto> (Host: <dominio>) ==
  [  OK  ] responde (200)
  [  OK  ] x-content-type-options / referrer-policy / permissions-policy / COOP / CORP
  [  OK  ] CSP activa
  [  OK  ] protección contra clickjacking (X-Frame-Options / frame-ancestors)
  [ INFO ] sin HSTS (correcto en HTTP: va donde se termina el TLS)
  [  OK  ] Server sin versión (nginx)
  [  OK  ] sin X-Powered-By
  [  OK  ] las cabeceras también salen en páginas de error (always)
  [  OK  ] rutas sensibles (.git, .env, copias, configs) no se sirven
  [  OK  ] TRACE rechazado (405)
  [  OK  ] web estática: POST/PUT/DELETE/PATCH rechazados
  [ AVISO] responde 200 a un Host inventado (poco impacto en una web estática)
  [MANUAL] rate limit del login no probado (usar -l /ruta/login)

Resumen: 14 OK · 0 FALLO · 1 AVISO · 1 MANUAL
```

- Las cabeceras de seguridad las pone **el propio nginx**, no Cloudflare: siguen ahí sin el túnel delante. Solo HSTS depende de Cloudflare, que es lo correcto.
- **Filtro de Host:** nginx responde 200 a cualquier `Host` (`server_name _;` en un único `server`). El 403 que se vio desde fuera en la fase 1 lo ponía Cloudflare. Hallazgo bajo: confirma que el filtrado depende de una sola capa.

## Host y daemon: `host.sh`

```text
== Host: <vps> ==
  [MANUAL] #0  Docker 29.9.3 · kernel 6.8.0-<x>-generic: comprobar que están al día (apt list --upgradable)
  [  OK  ] #1  el daemon no escucha por TCP
  [  OK  ] #1  permisos de docker.sock: 660 root:docker
  [  OK  ] #1  ningún contenedor monta docker.sock
  [  OK  ] #5a ningún contenedor publica puertos fuera de localhost
  [ INFO ] #5a puertos TCP escuchando en interfaces públicas: 22 80
  [MANUAL] #5a confirmarlo desde FUERA: nmap -p- <IP_PUBLICA_VPS>
  [  OK  ] #6  seccomp disponible en el daemon
  [  OK  ] #6  AppArmor/SELinux disponible en el daemon
  [MANUAL] #11 daemon como root, sin userns-remap (opcional; lo compensan #2 #3 #4 en cada contenedor)
  [  OK  ] #10 daemon sin modo debug (log en info)
  [ INFO ] #7  sin max-size en daemon.json: cada compose debe llevar su bloque logging
  [  OK  ] #2  ningún contenedor --privileged

Resumen: 8 OK · 0 FALLO · 0 AVISO · 3 MANUAL
```

| Resultado | Valoración |
|---|---|
| Daemon sin TCP, `docker.sock` 660 y sin montar, sin `--privileged`, seccomp y AppArmor | ✅ |
| **Puerto 80 escuchando en interfaz pública** | ⚠️ nginx del host con el sitio `default` de Ubuntu (ver abajo). Desde fuera sale `filtered`: solo lo tapa UFW → hallazgo |
| #5a confirmación externa | ✅ Hecha en la [fase 1](01-reconocimiento.md): solo 22 abierto |
| #11 sin userns-remap | Aceptado: lo compensan uid 101, `cap_drop: ALL` y no-new-privileges en el contenedor |
| #7 sin `max-size` global | Informativo: el compose del portfolio sí lo lleva (10m × 3) |
| #0 versiones | ⚠️ Docker 29.9.3 → 29.10.0 pendiente; ninguna actualización del canal `-security` (ver abajo) |

### nginx del host en el puerto 80

```text
$ sudo ss -tlnp 'sport = :80'
LISTEN 0 511    0.0.0.0:80   0.0.0.0:*   users:(("nginx",...))
LISTEN 0 511       [::]:80      [::]:*   users:(("nginx",...))

$ ls -la /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
sites-enabled/default -> /etc/nginx/sites-available/default
conf.d/            (vacío)

$ sudo nginx -T | grep -E 'listen|server_name|root|proxy_pass|return'
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    server_name _;

$ curl -sI http://127.0.0.1/
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Content-Length: 615

$ systemctl is-enabled nginx
enabled
```

- Es la instalación por defecto del paquete de Ubuntu: solo el sitio `default` sirviendo la página de bienvenida (615 bytes), sin `proxy_pass` ni dominios.
- **No forma parte del camino de la web**: el túnel va directo a `127.0.0.1:<puerto>` del contenedor.
- Escucha en `0.0.0.0` y `[::]`, arranca con el sistema y expone la versión (`nginx/1.24.0 (Ubuntu)`).
- No es alcanzable desde fuera: por IPv4 sale `filtered` (fase 1) y el VPS no tiene IPv6 pública (ver abajo). Pero la única barrera es UFW.

### Firewall e IPv6

```text
$ ip -6 addr show scope global
(nada: sin IPv6 pública)

$ grep IPV6 /etc/default/ufw
IPV6=yes

$ sudo ufw status verbose
Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
22/tcp (OpenSSH)           ALLOW IN    Anywhere
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)
```

- UFW activo, entrada denegada por defecto y solo SSH permitido, también en IPv6. ✅
- Sin IPv6 global, el `[::]:80` del nginx del host no tiene ruta desde Internet. ✅
- Coherente con la fase 1: solo el 22 abierto. Los puertos publicados por Docker no pasan por UFW, pero ninguno está fuera de `127.0.0.1`.

### Actualizaciones pendientes (#0)

```text
$ apt list --upgradable
distro-info/noble-updates          1.7ubuntu0.1               [upgradable from: 1.7build1]
docker-ce-cli/noble                5:29.10.0-1~ubuntu.24.04   [upgradable from: 5:29.9.3-1]
docker-ce-rootless-extras/noble    5:29.10.0-1~ubuntu.24.04   [upgradable from: 5:29.9.3-1]
docker-ce/noble                    5:29.10.0-1~ubuntu.24.04   [upgradable from: 5:29.9.3-1]
docker-compose-plugin/noble        5.7.2-1~ubuntu.24.04       [upgradable from: 5.7.1-1]
python3-distro-info/noble-updates  1.7ubuntu0.1               [upgradable from: 1.7build1]
snapd/noble-updates                2.78+ubuntu24.04           [upgradable from: 2.77.1+ubuntu24.04]
```

- Ningún paquete viene de `noble-security`: los parches de seguridad de Ubuntu están aplicados.
- Docker va una versión menor por detrás (29.9.3 → 29.10.0). Sin revisar si 29.10.0 corrige vulnerabilidades → hallazgo informativo.
- Al actualizar Docker se reinicia el daemon y, sin `live-restore` (docker-bench 2.15), caen todos los contenedores.

### Acceso a Docker de los usuarios

```text
$ id
uid=1000(<usuario>) gid=1000(<usuario>) groups=1000(<usuario>),27(sudo),100(users)
$ getent group docker
docker:x:988:
```

✅ El grupo `docker` está vacío. Estar en él equivale a ser root sin contraseña (`docker run -v /:/host ...`); aquí solo se llega a Docker con `sudo`.

### cloudflared

```text
$ systemctl cat cloudflared | grep ExecStart
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token

$ sudo stat -c '%a %U:%G %n' /etc/cloudflared/token
600 root:root /etc/cloudflared/token

$ systemctl show cloudflared -p User
User=

$ cloudflared --version
cloudflared version 2026.11.0 (built 2026-11-12)
$ apt list --upgradable | grep -i cloudflared
(nada)
```

| Comprobación | Resultado | Valoración |
|---|---|---|
| Token fuera de la línea de comandos (`--token-file`) | ✅ | No aparece en `ps` ni en `systemctl cat`, que cualquier usuario puede leer |
| Permisos del token | ✅ `600 root:root` | |
| Versión | ✅ 2026.11.0, sin actualizaciones pendientes | `--no-autoupdate` → se actualiza por apt |
| Usuario del servicio | ⚠️ root (`User=` vacío) | cloudflared no necesita root: si se compromete el proceso que recibe todo el tráfico de Internet, el atacante es root en el host → hallazgo bajo |
| Rutas del túnel | Pendiente | Configuradas en el panel de Cloudflare (no hay `config.yml`) |

## SSH: `sshd -T`

```text
permitrootlogin yes
passwordauthentication yes
kbdinteractiveauthentication no
pubkeyauthentication yes
maxauthtries 6
x11forwarding yes

$ systemctl is-active fail2ban
inactive
```

| Directiva | Valor | Esperado | Valoración |
|---|---|---|---|
| `PermitRootLogin` | `yes` | `no` (o `prohibit-password`) | ❌ root accesible directamente desde Internet |
| `PasswordAuthentication` | `yes` | `no` | ❌ Confirma desde dentro lo visto en la fase 1 |
| fail2ban | inactivo | activo (o solo clave pública) | ❌ Nada frena la fuerza bruta |
| `X11Forwarding` | `yes` | `no` | ⚠️ Superficie innecesaria en un servidor sin entorno gráfico |
| `MaxAuthTries` | `6` | `3` | Menor |

**Combinación:** root + contraseña + sin fail2ban, en el único puerto expuesto. Es el hallazgo más grave del caso (H-01).

## Herramientas: `herramientas.sh`

| Herramienta | Objetivo | Resultado resumido |
|---|---|---|
| trivy | imagen del VPS | ✅ 0 vulnerabilidades HIGH/CRITICAL (Alpine 3.24.2, 62 paquetes) |
| dockle | imagen del VPS | WARN DKL-DI-0006 (`latest`) → confirma H-05 · INFO CIS-DI-0005 (Content trust) |
| dockle | imagen local | FATAL CIS-DI-0010 → **falso positivo** (ver abajo) |
| hadolint | Dockerfile | DL3066 (info, usuario no numérico en `USER root`) · DL3025 (warning, `HEALTHCHECK CMD` sin formato JSON) |
| trivy config | Dockerfile | 0 misconfiguraciones |
| gixy | nginx.conf | 2 × `try_files_is_evil_too` (MEDIUM según gixy, pero es rendimiento, no seguridad) |
| testssl.sh | HTTPS | Solo TLS 1.2/1.3; HSTS de 30 días (ver [fase 1](01-reconocimiento.md#tls-testsslsh)) |
| gitleaks | repo de la app | 0 secretos en 45 commits |
| docker-bench-security | host | 117 checks, score 21. Detalle abajo |

### dockle CIS-DI-0010: falso positivo

En la imagen construida en local, dockle dio `FATAL CIS-DI-0010: Do not store credential in environment variables/files`. Con `-f json` se ve el detalle:

```text
CIS-DI-0010 FATAL Suspicious ENV key found : KEY_SHA512 on RUN |2 UID=101 GID=101 /bin/sh -c set -x ...
    && KEY_SHA512="*******"
    && wget -O /tmp/nginx_signing.rsa.pub https://nginx.org/keys/nginx_signing.rsa.pub
    && if echo "$KEY_SHA512 */tmp/nginx_signing.rsa.pub" | sha512sum -c -; then ...
```

- La capa es de la **imagen base** (`nginxinc/nginx-unprivileged`), no de nuestro Dockerfile.
- `KEY_SHA512` es el hash SHA-512 de la **clave pública** de firma de nginx.org, que se usa para verificar los paquetes. Es público y no da acceso a nada.
- dockle lo marca solo porque el nombre de la variable contiene `KEY`.
- Comprobación cruzada: `docker image inspect` no muestra ninguna variable sensible (solo `NGINX_VERSION`, `NJS_VERSION`, `PKG_RELEASE`…) y `contenedor.sh` dio `#12 ninguna variable de entorno con pinta de secreto`.
- En la ejecución del VPS dockle no lo mostró; no se ha determinado si es por otra versión de dockle.

**Conclusión:** descartado. Se puede silenciar con `dockle --accept-key KEY_SHA512`.

## docker-bench-security (CIS Docker Benchmark)

Clonado en `/root/docker-bench-security` (commit anotado en `evidencias/antes/bruto/vps/3-docker-bench-version.txt`) y ejecutado como root.

```text
[WARN] 1.1.1  - Ensure a separate partition for containers has been created
[WARN] 1.1.3-1.1.18 - Ensure auditing is configured for the Docker daemon / files (11 checks)
[WARN] 2.2  - Ensure network traffic is restricted between containers on the default bridge
[WARN] 2.9  - Enable user namespace support
[WARN] 2.12 - Ensure that authorization for Docker client commands is enabled
[WARN] 2.13 - Ensure centralized and remote logging is configured
[WARN] 2.14 - Ensure containers are restricted from acquiring new privileges
[WARN] 2.15 - Ensure live restore is enabled
[WARN] 2.16 - Ensure Userland Proxy is Disabled
[WARN] 4.5  - Ensure Content trust for Docker is Enabled
[WARN] 4.6  - Ensure that HEALTHCHECK instructions have been added to container images
              (la imagen del portfolio no aparece: tiene HEALTHCHECK)
[WARN] 5.9  - Ensure that only needed ports are open on the container
              * Port in use: <puerto> in <portfolio>
[WARN] 5.12 - Ensure that CPU priority is set appropriately on containers
              (el portfolio no aparece: tiene límite de CPU; sí aparecen 4 contenedores de otros proyectos)
[WARN] 5.27 - Ensure that container health is checked at runtime
              (el portfolio no aparece)
[INFO] Checks: 117
[INFO] Score: 21
```

| Check | Valoración |
|---|---|
| 1.1.1 partición separada | Aceptado: VPS con un solo disco |
| 1.1.3–1.1.18 auditd | ⚠️ Sin `auditd` no queda rastro de quién toca Docker → hallazgo informativo (forense, no prevención) |
| 2.2 `icc` en la red `bridge` por defecto | Informativo: el portfolio usa su propia red |
| 2.9 userns-remap | Aceptado (igual que #11 en `host.sh`) |
| 2.12 plugin de autorización | Aceptado: solo root usa Docker (el usuario normal no está en el grupo `docker`) |
| 2.13 logs remotos | Informativo |
| 2.14 `no-new-privileges` por defecto en el daemon | ⚠️ **Confirmado a mano** (ver abajo). El portfolio lo lleva en su compose, pero no es el valor por defecto → hallazgo bajo |
| 2.15 `live-restore` | ⚠️ Disponibilidad: reiniciar o actualizar el daemon tumba todos los contenedores |
| 2.16 `userland-proxy` | ⚠️ Un proceso `docker-proxy` por puerto publicado; desactivarlo reduce superficie |
| 4.5 Content trust | Aceptado: compensado con imágenes fijadas por digest (#13) |
| 4.6 / 5.12 / 5.27 | ✅ El portfolio cumple; los avisos son de otros proyectos |
| 5.9 puerto publicado | ✅ Esperado: solo en `127.0.0.1` |

> **Score 21** no es una nota sobre 100: suma 1 por cada check que pasa y resta por cada uno que falla. Lo útil es la lista de WARN, no el número.

**Confirmación del 2.14:**

```text
$ sudo docker info --format '{{json .SecurityOptions}}'
["name=apparmor,profile=default","name=seccomp,profile=builtin","name=cgroupns"]

$ sudo docker run --rm alpine grep NoNewPrivs /proc/self/status
NoNewPrivs:    0
```

El daemon aplica AppArmor y seccomp por defecto, pero no `no-new-privileges`: un contenedor lanzado sin la opción arranca con `NoNewPrivs: 0` y un binario SUID dentro puede subir a root. El del portfolio da `1` porque la lleva su compose.

**Fuera del alcance de este caso, pero relevante:** en el mismo VPS corren otros proyectos (4 contenedores sin límite de CPU, varios sin healthcheck). Un DoS o un compromiso en cualquiera de ellos afecta al host compartido y, por tanto, a la disponibilidad del portfolio.
> *Actualización 2026-11-18:* radar se revisó y corrigió (límite de CPU y healthcheck, entre otros) → H-12 a H-18 en [`03-hallazgos.md`](03-hallazgos.md).

## Recuento

| Resultado | `contenedor.sh` | `web.sh` (local) | `host.sh` | Total |
|---|---|---|---|---|
| OK | 20 | 14 | 8 | 42 |
| FALLO | 0 | 0 | 0 | 0 |
| AVISO | 3 | 1 | 0 | 4 |
| MANUAL | 1 | 1 | 3 | 5 |

Los scripts no dan ningún FALLO, pero el hallazgo más grave (SSH) sale de una comprobación manual: `host.sh` no revisa `sshd`.

## Hallazgos que salen de las fases 1 y 2

Lista provisional; severidad y CVSS definitivos en [`03-hallazgos.md`](03-hallazgos.md).

| ID | Hallazgo | Severidad aprox. | Detectado por |
|---|---|---|---|
| H-01 | SSH: `PermitRootLogin yes` + `PasswordAuthentication yes`, sin fail2ban | Alta | nmap `ssh-auth-methods` (fase 1) + `sshd -T` |
| H-02 | HSTS de 30 días, sin `includeSubDomains` (Cloudflare) | Baja | `web.sh` + testssl |
| H-03 | `/var/log/nginx`: bind mount del host escribible y con ejecución | Baja | `contenedor.sh` |
| H-04 | nginx del contenedor acepta cualquier `Host` (`server_name _`) | Baja | `web.sh` contra `127.0.0.1` |
| H-05 | Imagen solo con `:latest` | Informativa | `contenedor.sh` + dockle DKL-DI-0006 |
| H-06 | nginx del host innecesario en `0.0.0.0:80` / `[::]:80`, con versión expuesta | Baja | `host.sh` → `ss` → `nginx -T` |
| H-07 | cloudflared corre como root | Baja | `systemctl show cloudflared -p User` |
| H-08 | Daemon sin `no-new-privileges`, `live-restore` ni `userland-proxy: false` | Baja | docker-bench 2.14/2.15/2.16 + `NoNewPrivs: 0` |
| H-09 | Sin auditd para Docker | Informativa | docker-bench 1.1.x |
| H-10 | Docker una versión menor por detrás (29.9.3 → 29.10.0) | Informativa | `apt list --upgradable` |
| H-11 | Contenedor con salida a Internet (red no `internal`) | Baja | `contenedor.sh` (`redes: <red>(con salida)`) |

**Puntos positivos:** solo SSH expuesto · web solo por el túnel · contenedor con endurecimiento completo · 0 CVEs HIGH/CRITICAL · token del túnel en fichero `600` · grupo `docker` vacío · parches de seguridad de Ubuntu al día.

**Descartados:** ICMP *admin-prohibited* (red de origen) · dockle CIS-DI-0010 (`KEY_SHA512` de la imagen base) · BREACH (estática, sin secretos) · OCSP stapling.

## Pendiente para cerrar la fase

- [ ] Panel de Cloudflare → Zero Trust → Tunnels → Public Hostname: confirmar que solo hay `<dominio>` → `http://localhost:<puerto>`
- [ ] SSH (aparcado): `journalctl` de intentos fallidos, `passwd -S root`, `/etc/ssh/sshd_config.d/`
- [ ] Nmap UDP (`-sU --top-ports 50`) y pegar la salida real de `ssh-auth-methods` en la fase 1
- [ ] Limpiar en el VPS: `sudo docker rmi alpine:latest`

## Rutas del túnel (panel de Cloudflare)

Un único túnel, servido por el `cloudflared` del host, publica **todos** los proyectos del VPS:

| Hostname | Proyecto | Cloudflare Access |
|---|---|---|
| `<dominio>` y `www.<dominio>` | Portfolio (este caso) | No |
| `<proyecto-bot>` y `www.<proyecto-bot>` | Otro proyecto | No |
| `radar.<dominio>` | Panel de logs (lee el `access.log` del portfolio) | No |
| `ad-lab.<dominio>` | Laboratorio de AD | No |

- Refuerza H-07: un solo proceso, como root, es la puerta de entrada de todas las webs.
- La remediación de H-07/H-11 no puede apagar el `cloudflared` del host sin cortar los demás proyectos → **un túnel por proyecto**, empezando por el portfolio.

### Observaciones fuera del alcance (para un segundo caso)

> *Actualización 2026-11-18:* el alcance se amplió a **radar**; sus hallazgos están en [`03-hallazgos.md`](03-hallazgos.md) (H-12 a H-18, y "También en radar" en H-03/04/05/07/11). `radar` sin login es H-13.

- **`radar` sin login:** muestra las IPs de los visitantes del portfolio con el último octeto oculto (`a.b.c.xxx`). Mitigación razonable en pantalla. Pendiente comprobar que la API tampoco devuelve la IP completa (si el enmascarado se hace solo en el frontend, la IP entera viaja en el JSON).
- **`ad-lab` sin login:** web estática (descripción del laboratorio). Riesgo bajo.
- Opción de mitigación para ambos: Cloudflare Access (login) delante de la ruta.

## Notas para la remediación (fase 5)

- **H-07 + H-11 juntos:** mover cloudflared a un contenedor con dos redes (una con salida para el túnel y otra `internal: true` compartida con el portfolio). El portfolio se queda sin salida y sin puerto publicado, y cloudflared deja de correr como root en el host. Antes, comprobar en el panel si el túnel sirve también a otros proyectos del VPS (un túnel por proyecto o un cloudflared en varias redes).
- **Alternativa rápida para H-11:** reglas en `DOCKER-USER` (`-s <subred> -j DROP` con `ESTABLISHED,RELATED` antes); hay que hacerlas persistentes y comprobar el backend de firewall (iptables/nftables) de Docker 29.
