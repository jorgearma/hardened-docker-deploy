# nginx dentro de Docker

Configs de referencia comentadas línea a línea (probadas):

| Fichero | Dónde corre | Para qué |
|---|---|---|
| [`static.conf`](static.conf) | Contenedor | Web estática sin root |
| [`proxy.conf`](proxy.conf) | Contenedor | nginx delante de una app (gunicorn...). Sacada de panchi-bot |
| [`host-vhost.conf`](host-vhost.conf) | **Host** (VPS) | Termina el HTTPS y reenvía a `127.0.0.1:<puerto>` |

## Quién hace qué

```
Internet ─► [ Cloudflare Tunnel  |  nginx del host (host-vhost.conf) ] ─► 127.0.0.1:8081 ─► contenedor (proxy.conf | static.conf) ─► app
              HTTPS · HSTS · redirecciones                                                   cabeceras · rate limit · filtro de Host
```

- **Donde se termina el TLS:** certificado, HSTS, HTTP→HTTPS. Nada más.
- **nginx del contenedor:** el resto de cabeceras, rate limit, rutas sensibles. Viaja con el proyecto → se comporta igual en local y en el VPS.
- Las cabeceras de seguridad en **un solo sitio**: si las ponen los dos, el navegador las recibe duplicadas.
- Con Cloudflare Tunnel no hace falta `host-vhost.conf` (así está panchi-bot).

## Qué cubre `proxy.conf`

| Bloque | Qué hace |
|---|---|
| `set_real_ip_from <gateway>` / `real_ip_header` | IP real del visitante, aceptada **solo** desde el gateway de `web_net` |
| `limit_req_zone` + `location = /auth/login` | Rate limit del login: 10/min por IP real, `burst=5`, responde 429 |
| `map $uri $cache_control` | `no-store` en todo menos `/static/` |
| `server` con `default_server` | Host desconocido → 444 (corta la conexión). Responde al healthcheck en `/nginx-health` |
| `server` principal | Solo el dominio propio (+ `localhost` para probar) |
| `add_header ... always` | Cabeceras de seguridad; CSP en Report-Only para empezar |
| `proxy_set_header` en el `server` | Host, IP real (un solo valor) y `X-Forwarded-Proto https` para todas las `location` |
| `client_max_body_size`, `*_timeout` | Tamaño de subida y tiempos (clientes lentos, backend colgado) |
| `location ~ /\.(?!well-known)` y extensiones | `.git`, `.env`, `.sql`, `.bak`... → 404 sin llegar a la app |
| `location = /health` | Health de la app sin ensuciar el log |
| `location ^~ /ws/` (comentado) | WebSocket |

`X-Real-IP` es el valor por defecto porque encaja con `host-vhost.conf`, que la sobrescribe. Con Cloudflare Tunnel → `real_ip_header CF-Connecting-IP`.

### Trampas del proxy

- **`proxy_set_header` se hereda igual que `add_header`:** si una `location` define uno, pierde todos los del `server`. Por eso la de WebSocket los repite enteros.
- **`proxy_pass` no se hereda:** cada `location` que reenvía lleva el suyo.
- **nginx resuelve `app` una sola vez, al arrancar.** Si se recrea solo la app (`docker compose up -d --build app`) y cambia de IP → 502 hasta `docker compose restart proxy`. Por lo mismo, el proxy lleva `depends_on: app`: si `app` no existe al arrancar, nginx no arranca (`host not found in upstream`).
- **Subidas:** el cuerpo se guarda en `/tmp` (tmpfs) → `client_max_body_size` siempre por debajo del `size=` del tmpfs.
- **Fiarse de una subred entera** (`172.16.0.0/12`, o la `/24` del compose) permite a cualquier contenedor de esa red falsear su IP. Comprobado: desde otro contenedor de `web_net` la cabecera se ignora.
- **`ProxyFix(x_for=1, x_proto=1)`** en Flask: nginx manda un único valor en `X-Forwarded-For`, la app se fía de un único proxy.

## Qué cubre `host-vhost.conf`

| Bloque | Qué hace |
|---|---|
| `default_server` + `ssl_reject_handshake on` + `return 444` | Escaneos por IP y dominios ajenos: sin respuesta y sin enseñar certificado. **Uno por VPS** |
| `server` en el 80 | Reto de certbot (`/.well-known/acme-challenge/`) y redirección a HTTPS |
| `server` sin www | Redirección a `www` |
| `ssl_*` | TLS 1.2/1.3, perfil *intermediate* de Mozilla, sin session tickets |
| `Strict-Transport-Security` | HSTS, la única cabecera de seguridad que va aquí |
| `proxy_set_header X-Real-IP $remote_addr` | Sobrescribe lo que mande el visitante; el contenedor se fía de ella |

- `http2 on;` es de nginx ≥ 1.25.1 (`nginx -v` en el VPS). En versiones anteriores: `listen 443 ssl http2;`.
- Sin OCSP stapling a propósito: Let's Encrypt dejó de dar servicio OCSP en 2025.
- Varios proyectos en el VPS → un fichero por dominio, cada uno con su puerto; el bloque `default_server` solo en uno.

## Qué cubre `static.conf`

| Bloque | Qué hace |
|---|---|
| `listen 8080` | Puerto > 1024 → el contenedor no necesita capabilities |
| `server_tokens off` | No anuncia la versión de nginx |
| `set_real_ip_from` / `real_ip_header` | IP real del visitante si hay proxy/CDN delante (comentado por defecto) |
| `if ($request_method ...)` | Solo GET/HEAD; el resto → 405 |
| `add_header ... always` | Cabeceras de seguridad (CSP, XFO, nosniff, Referrer, Permissions, COOP, CORP) |
| `gzip` | Compresión |
| `location = /.well-known/security.txt` | Contacto de seguridad (RFC 9116) |
| `location ~ /\.(?!well-known)` | Ficheros ocultos (`.git`, `.env`) → 404 |
| `location ~* \.(env\|bak\|sql\|map...)$` | Extensiones sensibles → 404 |
| `location ^~ /assets/` | Assets con hash → caché 1 año |
| `location /` | HTML con caché corta; lo que no existe → 404 real |

## Trampas

- **`add_header` no se hereda** si una `location` define su propio `add_header` → todas las cabeceras en el `server`, ninguna en las `location`.
- **Prioridad de `location`:** `=` exacta → `^~` prefijo (corta la búsqueda) → regex `~`/`~*` en orden → prefijo más largo. Por eso `/assets/` lleva `^~`: si no, la regex de extensiones se lo quedaría.
- **CSP:** empezar con `Content-Security-Policy-Report-Only`, revisar la consola del navegador y después activarla.
- **HSTS** va donde se termina el HTTPS (Cloudflare o nginx del host), no en el contenedor.

### Variante SPA (React Router, Vue Router...)
Las rutas como `/about` no existen como fichero → hay que devolver `index.html` y que el JS decida:
```nginx
    location / {
        expires 5m;
        try_files $uri $uri/ /index.html;   # en vez de =404
    }
```
Con build de Vite los assets llevan hash en el nombre (`app.3f9a1c.js`) → se puede subir la caché:
```nginx
    location ^~ /assets/ {      # ^~ o la regex de extensiones se lo queda (7d)
        expires 1y;
        try_files $uri =404;
    }
```

> `.map` en la lista de extensiones bloqueadas: los *source maps* exponen el código fuente original. Mejor aún: no generarlos en producción (`build.sourcemap: false` en Vite, que es el valor por defecto).

---
