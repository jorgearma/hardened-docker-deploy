# Verificar un contenedor

Cómo comprobar que un contenedor está bien endurecido **antes** de ponerlo en producción.

## Scripts (para pasar en el VPS con el contenedor ya arriba)

Automatizan las pruebas de esta página. Cada línea sale como `OK`, `FALLO`, `AVISO` o `MANUAL` (lo que un script no puede decidir), con el número de regla OWASP delante. Código de salida 1 si hay algún `FALLO`.

| Script | Qué comprueba | Reglas OWASP |
|---|---|---|
| [`contenedor.sh`](contenedor.sh) | Un contenedor en marcha: `docker inspect`, estado real del proceso (`/proc`) y pruebas activas de post-explotación | #1 #2 #3 #4 #5 #5a #6 #7 #8 #12 #13 |
| [`web.sh`](web.sh) | nginx visto desde fuera: cabeceras (ni 0 ni 2), rutas sensibles, métodos, filtro de Host, rate limit, 413 | — (OWASP Secure Headers) |
| [`host.sh`](host.sh) | El VPS y el daemon: API por TCP, `docker.sock`, puertos publicados fuera de localhost, seccomp/AppArmor, rootless | #0 #1 #5a #6 #10 #11 |
| [`herramientas.sh`](herramientas.sh) | Lanza trivy, dockle, hadolint, gixy, testssl.sh, gitleaks y docker-bench-security | #9 #13 |

```bash
cd verificacion
./contenedor.sh mi-app mi-app-db mi-app-proxy        # o: ./contenedor.sh --todos
./web.sh -H www.example.com -l /auth/login -b 2 http://127.0.0.1:8081   # proxy + app
./web.sh -e http://127.0.0.1:8090                    # web estática
./web.sh -l /auth/login https://www.example.com      # desde fuera, por Cloudflare / nginx del host
sudo ./host.sh
./herramientas.sh imagen mi-app:latest
./herramientas.sh nginx ../nginx/proxy.conf
```

- Las pruebas activas de `contenedor.sh` crean un fichero temporal dentro del contenedor y lo borran en el mismo comando.
- `web.sh -l` deja tu IP limitada en el login durante un minuto.
- Quedan fuera (siempre manuales): `nmap` desde fuera del VPS, versiones al día (#0) y el CI (#9).

---

## Paso 0: identificar un contenedor ya desplegado

Si el contenedor no lo has montado tú ahora (auditoría de algo que ya está en marcha), antes del checklist confirma **qué es y de dónde sale**. El nombre del contenedor no tiene por qué coincidir con el proyecto (`container_name:` en el compose).

```bash
# 1. Identidad y origen (etiquetas que pone docker compose)
docker inspect C1 C2 --format \
'{{.Name}}
  imagen-config = {{.Config.Image}}
  imagen-id     = {{.Image}}
  creado        = {{.Created}}
  proyecto      = {{index .Config.Labels "com.docker.compose.project"}}
  compose-dir   = {{index .Config.Labels "com.docker.compose.project.working_dir"}}
  compose-file  = {{index .Config.Labels "com.docker.compose.project.config_files"}}
'

# 2. ¿La etiqueta sigue apuntando a la imagen que corre el contenedor?
docker image inspect <imagen-config> --format '{{index .RepoTags 0}}  id={{.Id}}  creada={{.Created}}'
```

| Qué ves | Qué significa |
|---|---|
| Nombre del contenedor ≠ `proyecto` | El código y el compose están en `compose-dir`, no en una carpeta con el nombre del contenedor |
| `proyecto` / `compose-dir` vacíos | No se lanzó con compose (`docker run` a mano): buscar cómo se arrancó |
| `docker ps` muestra un ID en la columna IMAGE en vez del nombre | La etiqueta se movió a otra imagen: se reconstruyó sin recrear el contenedor |
| `id` de la etiqueta (comando 2) ≠ `imagen-id` (comando 1) | Confirmado: el contenedor corre una **imagen huérfana**. El código en disco no es el que está corriendo; auditar la imagen del contenedor (`imagen-id`), no la etiqueta |

> Caso real (2026-11-18): `ssh-rain-backend` / `ssh-rain-frontend` resultaron ser el proyecto `siege-map` en `/opt/apps/siege-map`, y `docker ps` mostraba el backend como `542084c660bd` en vez de `siege-map-backend`.

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
docker exec $C sh -c 'id; grep -E "CapEff|CapBnd|NoNewPrivs|Seccomp:" /proc/self/status'
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
| CapBnd | `0000000000000000` (es el que demuestra `cap_drop: ALL`; CapEff ya es 0 en cualquier proceso sin root) |
| NoNewPrivs | `1` |
| Seccomp | `2` |

---

## Pruebas: web estática

Las mismas que se pasaron al portfolio. Arrancar con `docker compose up -d --build` y:

```bash
C=mi-web; P=8090

# 1. Arranca y está healthy (esperar ~35 s)
docker ps --filter name=$C --format '{{.Status}}'

# 2. Cabeceras
curl -sI http://127.0.0.1:$P/

# 3. Endurecimiento del proceso
docker exec $C sh -c 'id; grep -E "CapEff|CapBnd|NoNewPrivs|Seccomp:" /proc/self/status'
#    esperado: uid=101 · CapEff 0000000000000000 · NoNewPrivs 1 · Seccomp 2

# 4. Post-explotación: todo debe FALLAR
docker exec $C sh -c 'echo pwn > /usr/share/nginx/html/shell.html'          # Read-only / Permission denied
docker exec $C sh -c 'echo x > /etc/nginx/conf.d/evil.conf'                  # Read-only
docker exec $C sh -c 'cp /bin/busybox /tmp/bb && /tmp/bb echo exec'          # Permission denied (noexec)
docker exec $C sh -c 'find / -xdev -perm -4000 2>/dev/null'                  # vacío (sin SUID)
docker exec $C sh -c 'which curl nc node npm'                                # solo deberían salir los que esperas

# 5. Permisos sin read_only (la segunda capa también aguanta)
docker run --rm --entrypoint sh mi-web:latest -c 'touch /usr/share/nginx/html/x'   # Permission denied

# 6. Rutas sensibles → 404 / métodos → 405
for p in /.git/config /.env /Dockerfile /nginx.conf /README.md; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$P$p)"; done
curl -s -o /dev/null -w 'TRACE -> %{http_code}\n' -X TRACE http://127.0.0.1:$P/
curl -s -o /dev/null -w 'POST  -> %{http_code}\n' -X POST  http://127.0.0.1:$P/

# 7. Lint y CVEs
docker run --rm -i hadolint/hadolint < Dockerfile
trivy image --severity HIGH,CRITICAL --ignore-unfixed mi-web:latest

# 8. Desde FUERA del VPS: el puerto del contenedor NO debe verse
nmap -p 8090 <IP_PUBLICA_VPS>      # filtered/closed
```

### Web con paso de build: que no se cuele nada
```bash
docker run --rm --entrypoint sh mi-web:latest -c 'which node npm; ls /usr/share/nginx/html'
# node y npm NO deben aparecer; en html solo lo que había en dist/
```

---

---

## Pruebas: app + base de datos

Resultado esperado = lo que salió en la prueba del 2026-11-16.

```bash
docker compose up -d --build

# 1. Los dos healthy y /health OK (comprueba también la conexión a la BD)
docker compose ps
curl -s http://127.0.0.1:8000/health                         # {"status":"ok"}

# 2. Endurecimiento (app y db)
docker compose exec app sh -c 'id; grep -E "CapEff|NoNewPrivs|Seccomp:" /proc/self/status; cat /proc/1/comm'
#   uid=10001 · CapEff 0 · NoNewPrivs 1 · Seccomp 2 · docker-init
docker compose exec db  sh -c 'id; grep -E "CapEff|NoNewPrivs" /proc/self/status'
#   uid=70 · CapEff 0 · NoNewPrivs 1

# 3. La app no puede modificarse a sí misma ni a sus librerías
docker compose exec app sh -c 'echo x > /app/app/__init__.py'                                  # Read-only
docker compose exec app sh -c 'echo x > /opt/venv/lib/python3.12/site-packages/flask/__init__.py' # Read-only
docker run --rm --entrypoint sh mi-app:latest -c 'touch /app/x'                                 # Permission denied (sin read_only también)

# 4. Secretos: en fichero, NO en variables ni en la imagen
docker compose exec app sh -c 'ls -la /run/secrets/'
docker compose exec app sh -c 'env | grep -iE "pass|secret"'          # vacío (GPG_KEY de la imagen python es pública, no cuenta)
docker history --no-trunc mi-app:latest | grep -iE 'secret|pass'      # vacío

# 5. Aislamiento de red
docker compose exec db sh -c 'wget -q -T 3 -O /dev/null http://example.com && echo SI || echo NO'   # NO (red internal)
docker run --rm --network mi-app_frontend alpine nc -z -w 2 db 5432 && echo ALCANZABLE || echo "NO alcanzable"   # NO
docker compose ps --format '{{.Service}} {{.Ports}}'                 # db SIN 0.0.0.0 ni 127.0.0.1

# 6. Herramientas de build fuera de la imagen final
docker run --rm --entrypoint sh mi-app:latest -c 'which gcc curl wget; python -m pip --version'   # nada / "No module named pip"

# 7. Lint, CVEs, consumo
docker run --rm -i hadolint/hadolint < Dockerfile
trivy image --severity HIGH,CRITICAL --ignore-unfixed mi-app:latest
docker stats --no-stream            # en la prueba: app ~70 MB, db ~26 MB

# 8. Desde FUERA del VPS
nmap -p 8000,5432 <IP_PUBLICA_VPS>  # ambos filtered/closed
```

### Resultados de la prueba real (2026-11-16)

| Prueba | Resultado |
|---|---|
| app / db healthy, `/health` con consulta a la BD | ✅ |
| app: uid 10001, CapEff 0, NoNewPrivs 1, Seccomp 2, PID 1 `docker-init` | ✅ |
| db: uid 70, CapEff 0, NoNewPrivs 1, read-only | ✅ |
| Modificar código o librerías de la app | ✅ Bloqueado (read-only **y** permisos) |
| Secretos solo en `/run/secrets`, no en env ni en `docker history` | ✅ |
| BD sin salida a Internet | ✅ (`bad address`) |
| BD inalcanzable desde `frontend_net` | ✅ |
| BD sin puerto publicado en el host | ✅ |
| `pip` eliminado del venv | ✅ |
| **App con salida a Internet** | ⚠️ Sí (está en `frontend_net`). Normal si llama a APIs externas; si no, se puede restringir con reglas en `DOCKER-USER` |

---

## Pruebas: proxy + app + base de datos

Para [`compose.proxy-app-db.yml`](../compose/compose.proxy-app-db.yml) + [`proxy.conf`](../nginx/proxy.conf). Además de las de la sección anterior (endurecimiento, secretos, BD aislada):

```bash
U=http://127.0.0.1:8081; H='Host: www.example.com'
code(){ curl -s -o /dev/null -w '%{http_code}\n' "$@"; }

# 1. Filtro de Host: el dominio propio pasa, lo demás se corta (000 = conexión cerrada, 444)
code -H "$H" $U/                    # 200
code -H 'Host: evil.com' $U/        # 000
code $U/                            # 000 (Host = 127.0.0.1)

# 2. Rutas sensibles: 404 de nginx, sin llegar a la app
for p in /.git/config /.env /x.sql /backup.bak; do code -H "$H" $U$p; done

# 3. Rate limit del login: 6 pasan (1 + burst 5), el resto 429
for i in $(seq 20); do curl -s -o /dev/null -w '%{http_code} ' -H "$H" -X POST $U/auth/login; done; echo

# 4. Subida mayor que client_max_body_size → 413
head -c 2000000 /dev/zero | code -H "$H" --data-binary @- $U/

# 5. IP real: desde el host (gateway) se acepta la cabecera...
curl -s -o /dev/null -H "$H" -H 'X-Real-IP: 203.0.113.7' "$U/?ok"
# ...desde otro contenedor de la misma red, NO (en el log sale su IP 172.30.80.x, no 6.6.6.6)
docker run --rm --network mi-app_web alpine wget -qO /dev/null \
  --header "$H" --header 'X-Real-IP: 6.6.6.6' 'http://proxy:8080/?spoof'
docker compose logs --no-log-prefix proxy | grep -E '\?(ok|spoof)'

# 6. La app no publica puerto y el proxy no ve la BD
docker compose ps --format '{{.Service}} {{.Ports}}'            # solo proxy con 127.0.0.1
docker compose exec proxy sh -c 'nc -z -w 2 db 5432 && echo ALCANZABLE || echo "NO alcanzable"'

# 7. Lint de la config de nginx
docker run --rm -v ./nginx.conf:/etc/nginx/conf.d/default.conf:ro getpagespeed/gixy /etc/nginx/conf.d/default.conf
```

### nginx del host (`host-vhost.conf`)

```bash
nginx -t
curl -sI  http://www.example.com/            # 301 → https://www.example.com/
curl -sI  https://example.com/               # 301 → https://www.example.com/
curl -sI  https://www.example.com/ | grep -ci strict-transport-security   # 1 (ni 0 ni 2)
curl -skI https://<IP_PUBLICA_VPS>/          # falla el handshake (ssl_reject_handshake)
curl -sI  http://<IP_PUBLICA_VPS>/           # conexión cerrada (444)
curl -s --tls-max 1.1 https://www.example.com/   # falla: solo TLS 1.2 y 1.3
# Nota externa: https://www.ssllabs.com/ssltest/
```

### Resultados de la prueba real (2026-11-17)

Stack levantado con la imagen `mi-app:latest` y, delante, `host-vhost.conf` con certificado autofirmado y puertos altos (no en un VPS con dominio real).

| Prueba | Resultado |
|---|---|
| proxy / app / db healthy | ✅ |
| Host propio → 200 · Host falso o sin Host válido → conexión cerrada | ✅ |
| `/.git/config`, `/.env`, `.sql`, `.bak` → 404 | ✅ |
| Login: 6 peticiones pasan, las 14 siguientes → 429 | ✅ |
| POST de 2 MB → 413 | ✅ |
| `X-Real-IP` aceptada desde el gateway (`172.30.80.1`) | ✅ |
| `X-Real-IP` falsa desde otro contenedor de `web_net` | ✅ Ignorada (se registra `172.30.80.4`) |
| proxy uid 101 · app uid 10001 · db uid 70; los tres CapEff 0, NoNewPrivs 1, Seccomp 2 | ✅ |
| Escribir en `/etc/nginx/conf.d` del proxy | ✅ Bloqueado (read-only) |
| proxy → db | ✅ No alcanzable (ni resuelve el nombre) |
| db → Internet | ✅ Sin salida |
| Solo el proxy publica puerto, en `127.0.0.1` | ✅ |
| Host: HTTP → 301 HTTPS · sin www → 301 www · reto ACME servido | ✅ |
| Host: acceso por IP (HTTP y HTTPS) y TLS 1.1 | ✅ Rechazados |
| Host + contenedor: HSTS una vez, resto de cabeceras una vez, HTTP/2 | ✅ |
| Visitante manda `X-Real-IP` falsa a través de las dos capas | ✅ Sobrescrita por la IP de la conexión |
| gixy en `proxy.conf` y `host-vhost.conf` | ✅ Sin avisos |
| Consumo | proxy ~17 MB · app ~70 MB · db ~26 MB |

---

## Checklist de proyecto nuevo: web estática

- [ ] Elegir plantilla A o B (¿hay `npm run build`?)
- [ ] Digest real en los `FROM`
- [ ] `COPY` con los ficheros reales del proyecto
- [ ] `nginx.conf`: CSP ajustada (probar primero en Report-Only), variante SPA si aplica
- [ ] `set_real_ip_from` solo si hay proxy delante, con la subred del compose
- [ ] security.txt con email y Expires
- [ ] Compose: puerto del host y subred únicos
- [ ] Logs al host: dir con dueño 101 + logrotate con `su 101 101`
- [ ] nginx del host / Cloudflare: HTTPS, HSTS, `default_server` que rechace otros dominios
- [ ] Pasar las pruebas de la sección anterior
- [ ] CI: hadolint + gitleaks + trivy + Dependabot

## Checklist de proyecto nuevo: app + base de datos

- [ ] Digest real en los dos `FROM` (iguales) y en la imagen de Postgres
- [ ] `requirements.txt` con `==` (mejor con hashes)
- [ ] `COPY` con las carpetas reales del proyecto
- [ ] Endpoint `/health` que compruebe la BD
- [ ] Secretos: `secrets/` 700, ficheros 444, en `.gitignore` y `.dockerignore`
- [ ] Ningún secreto en `environment:`
- [ ] `user:` de la BD correcto (70 Alpine / 999 Debian)
- [ ] BD solo en `backend_net` (`internal: true`), sin `ports:`
- [ ] Subidas de usuarios → volumen propio, nunca ejecutables
- [ ] Puerto del host único por proyecto, en `127.0.0.1`
- [ ] Proxy del host / Cloudflare: HTTPS, HSTS, cabeceras + `ProxyFix` en Flask
- [ ] Backups del volumen `db_data` (`pg_dump` programado) — no es seguridad de Docker pero sin esto no hay producción
- [ ] Pasar las pruebas de la sección anterior
- [ ] CI: hadolint + gitleaks + trivy + Dependabot (pip y docker)
