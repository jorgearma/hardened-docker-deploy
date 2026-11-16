# nginx dentro de Docker

> Config de referencia comentada línea a línea: [`static.conf`](static.conf) (web estática sin root, probada).
> Pendiente: `proxy.conf` (nginx delante de un backend: `real_ip`, rate limit, WebSocket, `^~ /api/`) a partir de siege-map.

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
