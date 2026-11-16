# OWASP Docker Security Cheat Sheet — Resumen para repasar

> Fuente: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
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
      nproc: 64
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
| Procesos | `--pids-limit 100` / `--ulimit nproc=64` | `pids_limit` / `ulimits.nproc` |
| Descriptores | `--ulimit nofile=1024:2048` | `ulimits.nofile` |
| Reinicios | `--restart=on-failure:5` | `restart: on-failure:5` |

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
| Compose / IaC | Trivy `config`, KICS, DockSec |
| Kubernetes | kube-bench, kubesec, kubeaudit |

```bash
docker run --rm -i hadolint/hadolint < Dockerfile
trivy image --severity HIGH,CRITICAL --ignore-unfixed mi-imagen:tag
trivy config .
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

## Checklist de auditoría de un contenedor (copiar y pegar)

```bash
C=nombre_contenedor
docker inspect $C --format '
User:        {{.Config.User}}
Privileged:  {{.HostConfig.Privileged}}
ReadOnly:    {{.HostConfig.ReadonlyRootfs}}
CapDrop:     {{.HostConfig.CapDrop}}
CapAdd:      {{.HostConfig.CapAdd}}
SecurityOpt: {{.HostConfig.SecurityOpt}}
AppArmor:    {{.AppArmorProfile}}
Memory:      {{.HostConfig.Memory}}
NanoCPUs:    {{.HostConfig.NanoCpus}}
PidsLimit:   {{.HostConfig.PidsLimit}}
Restart:     {{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}
Ports:       {{.HostConfig.PortBindings}}
Networks:    {{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}
Mounts:      {{range .Mounts}}{{.Source}}->{{.Destination}}(rw={{.RW}}) {{end}}'
docker exec $C sh -c 'id; grep -E "CapEff|NoNewPrivs|Seccomp:" /proc/self/status'
```

| Campo | Valor esperado |
|---|---|
| User | no vacío / no `root` / no `0` |
| Privileged | `false` |
| ReadOnly | `true` |
| CapDrop | `[ALL]` |
| SecurityOpt | contiene `no-new-privileges:true` |
| AppArmor | `docker-default` (no `unconfined`) |
| Memory / PidsLimit | distinto de 0 |
| Ports | `127.0.0.1` delante |
| Mounts | sin `docker.sock`; `rw=false` donde se pueda |
| CapEff | `0000000000000000` |
| NoNewPrivs | `1` |
| Seccomp | `2` |

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
