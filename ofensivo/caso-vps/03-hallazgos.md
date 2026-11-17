# 3. Hallazgos

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
| H-03 | Logs: bind mount del host escribible y con ejecución | Baja | — | OWASP #8 | `contenedor.sh` | Abierto |
| H-06 | nginx del host innecesario en `0.0.0.0:80`, con versión | Baja | — | OWASP #0 / CIS (servicios innecesarios) | `host.sh` → `ss` → `nginx -T` | Abierto |
| H-07 | cloudflared corre como root | Baja | — | OWASP #2 | `systemctl show -p User` | **Mitigado** (portfolio) |
| H-08 | Daemon sin `no-new-privileges`, `live-restore` ni `userland-proxy: false` | Baja | — | OWASP #4 / CIS 2.14-2.16 | docker-bench + `NoNewPrivs: 0` | Abierto |
| H-11 | Contenedor web con salida a Internet | Baja | — | OWASP #5 | `contenedor.sh` | **Cerrado** |
| H-04 | nginx acepta cualquier `Host` | Informativa | — | — | `web.sh` contra `127.0.0.1` | Abierto |
| H-05 | Imagen solo con `:latest` | Informativa | — | OWASP #13 | `contenedor.sh` + dockle DKL-DI-0006 | Abierto |
| H-09 | Sin auditd para Docker | Informativa | — | CIS Docker 1.1.x | docker-bench | Abierto |
| H-10 | Docker una versión menor por detrás | Informativa | — | OWASP #0 | `apt list --upgradable` | Abierto |

**Recuento:** 1 Alta · 6 Baja · 4 Informativa · 0 Crítica · 0 Media.

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

**Remediación.** Aplicada para el portfolio: túnel propio en un contenedor (uid 65532, read-only, sin capabilities) → [`05-remediacion.md`](05-remediacion.md). Se cierra al migrar el resto de proyectos y apagar el servicio del host.

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

**Remediación.** Red `internal: true` + túnel en el mismo compose → [`05-remediacion.md`](05-remediacion.md). Retest: `wget: bad address` → [`06-retest.md`](06-retest.md).

---

## Informativos

| ID | Hallazgo | Por qué no sube de informativo | Recomendación |
|---|---|---|---|
| H-04 | nginx responde 200 a cualquier `Host` (`server_name _;`) | Web estática sin URLs absolutas ni cookies: no hay envenenamiento de caché ni de enlaces que explotar. Desde fuera Cloudflare ya filtra, y tras la remediación solo cloudflared llega a nginx | `server_name <dominio> www.<dominio>` + `default_server` con `return 444`. Ojo: el healthcheck pide `Host: 127.0.0.1` y se rompería (ver `errores-vividos.md`) |
| H-05 | Imagen etiquetada solo `:latest` | No es explotable; afecta a la trazabilidad y a la vuelta atrás | Etiquetar con el commit: `image: <imagen>:${GIT_SHA}` |
| H-09 | Sin auditd sobre Docker | No previene nada; sin él, un incidente deja menos rastro | `auditd` con reglas para `docker.service`, `/etc/docker`, `/var/lib/docker`, `containerd`, `runc` |
| H-10 | Docker 29.9.3 → 29.10.0 pendiente | Ningún paquete del canal `-security` de Ubuntu pendiente; sin revisar si 29.10.0 corrige CVEs | Actualizar después de aplicar `live-restore` (H-08) |

## Descartados

| Indicio | Por qué se descarta |
|---|---|
| ICMP *admin-prohibited* en nmap | Lo envía la red de origen (CGNAT, `ttl=63`), no el VPS |
| dockle `FATAL CIS-DI-0010` | `KEY_SHA512` en una capa de la imagen base: hash de la clave **pública** de nginx.org |
| testssl: BREACH | Página estática, sin secretos ni cookies en la respuesta |
| testssl: LUCKY13 | Suites CBC de Cloudflare por compatibilidad; ataque no práctico |
| testssl: OCSP stapling | Let's Encrypt dejó de ofrecer OCSP en 2025 |
| gixy `try_files_is_evil_too` | Rendimiento, no seguridad |
