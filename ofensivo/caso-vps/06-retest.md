# 6. Retest

Las mismas pruebas de las fases 1 y 2, después de la remediación. Salidas completas en [`evidencias/despues/`](evidencias/despues/).

- **Fecha:** 2026-11-17 (retest parcial: H-07 y H-11)

## Antes / después

| Prueba | Antes | Después |
|---|---|---|
| Usuario del proceso (web) | uid 101 | uid 101 |
| Usuario del túnel | root (systemd en el host) | **uid 65532** (contenedor) |
| Sistema de ficheros read-only | ✅ | ✅ (web y túnel) |
| `cap_drop: ALL` | ✅ | ✅ (web y túnel) |
| `no-new-privileges` | ✅ | ✅ (web y túnel) |
| Puertos en el host | `127.0.0.1:<puerto>` | **Ninguno** |
| Red de la web | con salida | **`internal`** |
| Salida a Internet desde la web | sí | **no** (`bad address`) |
| Secretos en `ENV` | no | no (token como Docker secret) |
| Imagen fijada por digest | web ✅ | web ✅ · túnel ✅ |
| Límites de memoria / CPU / pids | ✅ | ✅ (web y túnel) |
| Cabeceras de seguridad | ✅ | ✅ (sin cambios) |
| Web accesible desde fuera | 200 | **200** (`@` y `www`) |

## Evidencias

### Salida a Internet desde el portfolio (H-11)

```text
$ sudo docker exec <portfolio> wget -q -T 5 -O /dev/null http://<dominio>
wget: bad address '<dominio>'
código: 1
```

Ni siquiera resuelve nombres: la red `internal` no tiene DNS externo ni ruta hacia fuera.

### Red y puertos

```text
$ sudo docker network inspect portfolio_internal --format 'internal={{.Internal}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
internal=true <subred>

$ sudo ss -tlnp
LISTEN 127.0.0.1:<otro-proyecto-1>   docker-proxy
LISTEN 127.0.0.1:<otro-proyecto-2>   docker-proxy
LISTEN 127.0.0.1:<otro-proyecto-3>   docker-proxy
LISTEN 0.0.0.0:80                    nginx          ← H-06, pendiente
LISTEN 0.0.0.0:22                    sshd
LISTEN 127.0.0.1:20241               cloudflared    ← métricas del túnel COMPARTIDO del host
(el puerto del portfolio ya no aparece)
```

Las métricas del cloudflared nuevo (`127.0.0.1:20241` dentro del contenedor) no salen en el `ss` del host: cada contenedor tiene su propio namespace de red.

### Túnel nuevo

```text
$ sudo docker inspect <portfolio>-tunnel --format 'User={{.Config.User}}'
User=65532:65532

$ sudo docker compose logs cloudflared | grep 'Registered tunnel connection'
Registered tunnel connection connIndex=0 ... protocol=quic
Registered tunnel connection connIndex=1 ... protocol=quic
Registered tunnel connection connIndex=2 ... protocol=quic
Registered tunnel connection connIndex=3 ... protocol=quic

$ sudo docker compose logs cloudflared | grep 'Updated to new configuration'
... "ingress":[{"hostname":"<dominio>","service":"http://portfolio:8080"},
              {"hostname":"www.<dominio>","service":"http://portfolio:8080"},
              {"service":"http_status:404"}] ... version=2
```

### `contenedor.sh`

```text
== Contenedor: <portfolio> ==
  [  OK  ] #2  proceso principal sin root (uid 101, User='101')
  [  OK  ] #3  CapBnd = 0 · CapEff = 0
  [  OK  ] #4  no-new-privileges activo
  [ INFO ] #5  redes: portfolio_internal(internal)                 ← antes: (con salida)
  [  OK  ] #5a no publica puertos en el host                       ← antes: 127.0.0.1:<puerto>->8080
  [  OK  ] #6  seccomp en modo filtro · AppArmor: docker-default
  [  OK  ] #7  límite de memoria / pids_limit / CPU
  [  OK  ] #8  sistema de ficheros read-only
  [ AVISO] #8  bind mounts con escritura: <logs>->/var/log/nginx   ← H-03, pendiente
  [ AVISO] #13 <portfolio>:latest sin versión en la etiqueta        ← H-05, pendiente
  [ AVISO] #8  activa: se puede ejecutar desde volúmenes escribibles ← H-03, pendiente

== Contenedor: <portfolio>-tunnel ==
  [  OK  ] #2  proceso principal sin root (uid 65532, User='65532:65532')
  [  OK  ] #3  CapBnd = 0 · CapEff = 0
  [  OK  ] #4  no-new-privileges activo
  [ INFO ] #5  redes: portfolio_internal(internal) portfolio_tunnel_egress(con salida)
  [  OK  ] #5a no publica puertos en el host
  [  OK  ] #6  seccomp en modo filtro · AppArmor: docker-default
  [  OK  ] #7  límite de memoria / pids_limit / CPU
  [  OK  ] #8  sistema de ficheros read-only
  [  OK  ] #12 ninguna variable de entorno con pinta de secreto
  [  OK  ] #13 imagen fijada por digest
  [  OK  ] healthcheck: healthy
  [MANUAL] sin shell dentro del contenedor: pruebas activas no ejecutadas (bueno para la seguridad)

Resumen: 38 OK · 0 FALLO · 3 AVISO · 2 MANUAL
```

### Desde fuera

```text
$ curl --resolve <dominio>:443:<IP-Cloudflare> https://<dominio>/      → 200
$ curl --resolve www.<dominio>:443:<IP-Cloudflare> https://www.<dominio>/ → 200
(CSP, X-Frame-Options, nosniff, Permissions-Policy, COOP, CORP, Referrer-Policy, HSTS: presentes)
```

## Estado de los hallazgos

| ID | Antes | Después |
|---|---|---|
| H-01 | Abierto | Abierto (pendiente) |
| H-02 | Abierto | Abierto (pendiente) |
| H-03 | Abierto | Abierto (pendiente) |
| H-04 | Abierto | Abierto (pendiente). Ahora solo cloudflared llega al nginx, lo que reduce su alcance |
| H-05 | Abierto | Abierto (pendiente) |
| H-06 | Abierto | Abierto (pendiente) |
| H-07 | Abierto | **Mitigado** para el portfolio; el túnel compartido del host sigue como root |
| H-08 | Abierto | Abierto (pendiente) |
| H-09 | Abierto | Abierto (pendiente) |
| H-10 | Abierto | Abierto (pendiente) |
| H-11 | Abierto | **Cerrado** |

## Riesgo residual

- **Túnel compartido del host (H-07):** sigue sirviendo los demás proyectos como root. Se cierra migrándolos uno a uno con [`compose.static-tunnel.yml`](../../compose/compose.static-tunnel.yml) y apagando `cloudflared.service`.
- **cloudflared con salida a Internet:** necesario para conectar con Cloudflare. Está aislado (sin root, sin shell, read-only) y no tiene ningún puerto expuesto.
- **Sin pruebas activas en el túnel:** la imagen no tiene shell; el endurecimiento se comprueba por configuración (`docker inspect`, `/proc` del host) y no ejecutando dentro.
