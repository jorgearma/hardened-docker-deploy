# Verificar un contenedor

Cómo comprobar que un contenedor está bien endurecido **antes** de ponerlo en producción.

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

## Pruebas: web estática

Las mismas que se pasaron al portfolio. Arrancar con `docker compose up -d --build` y:

```bash
C=mi-web; P=8090

# 1. Arranca y está healthy (esperar ~35 s)
docker ps --filter name=$C --format '{{.Status}}'

# 2. Cabeceras
curl -sI http://127.0.0.1:$P/

# 3. Endurecimiento del proceso
docker exec $C sh -c 'id; grep -E "CapEff|NoNewPrivs|Seccomp:" /proc/self/status'
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
