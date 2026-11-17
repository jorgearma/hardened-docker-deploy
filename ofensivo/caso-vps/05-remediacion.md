# 5. Remediación

Cambios aplicados usando las plantillas del repo.

| Hallazgo | Plantilla usada | Cambio clave | Estado |
|---|---|---|---|
| H-11 | [`compose/compose.static-tunnel.yml`](../../compose/compose.static-tunnel.yml) (nace de este cambio) | Portfolio en red `internal: true`, sin `ports:` | Aplicado 2026-11-17 |
| H-07 | Ídem | Túnel propio del portfolio en un contenedor sin root | Aplicado para el portfolio; el resto de proyectos sigue en el túnel del host |
| H-01 · H-02 · H-03 · H-04 · H-05 · H-06 · H-08 · H-09 · H-10 | — | — | Pendiente |

---

## H-07 + H-11: cloudflared dentro del compose del proyecto

Un único cambio de arquitectura cierra los dos.

**Antes:**

```text
Internet → Cloudflare → túnel compartido → cloudflared (host, systemd, root)
                                             ├─► 127.0.0.1:<puerto> → portfolio (red con salida)
                                             ├─► 127.0.0.1:<puerto> → <otro proyecto>
                                             └─► ...
```

**Después (portfolio):**

```text
Internet → Cloudflare → túnel "portfolio" → cloudflared (contenedor, uid 65532)
                                              │ red internal (sin salida)
                                              ▼ http://portfolio:8080
                                            portfolio (sin salida, sin puertos en el host)
```

### Cambios en el `docker-compose.yml` del portfolio

```diff
 services:
   portfolio:
     ...
-    ports:
-      - "127.0.0.1:<puerto>:8080"
+    # Sin ports: solo lo alcanza cloudflared por la red interna
     networks:
-      - portfolio_net
+      - portfolio_internal
 
+  cloudflared:
+    image: cloudflare/cloudflared:2026.11.0@sha256:<digest>
+    command: >-
+      tunnel --no-autoupdate --metrics 127.0.0.1:20241
+      run --token-file /run/secrets/tunnel_token
+    secrets: [tunnel_token]
+    read_only: true
+    cap_drop: [ALL]
+    security_opt: [no-new-privileges:true]
+    mem_limit: 128m · cpus: 0.5 · pids_limit: 100 · logging con tope
+    networks: [portfolio_internal, tunnel_egress]
+    healthcheck: cloudflared tunnel --metrics 127.0.0.1:20241 ready
+    depends_on: { portfolio: { condition: service_healthy } }
 
 networks:
-  portfolio_net:
-    driver: bridge
+  portfolio_internal:
+    internal: true
     ipam: { config: [ { subnet: <misma subred> } ] }
+  tunnel_egress:
+    driver: bridge
+
+secrets:
+  tunnel_token:
+    file: ./secrets/tunnel_token
```

Otros ficheros del repo del portfolio:

- **`.gitignore` (no existía):** `secrets/`, `.env*`, `*.log`. Sin él, el token del túnel podía acabar en un repositorio público.
- **`.dockerignore`:** `secrets`.
- **`DEPLOY.md`:** arquitectura y pasos nuevos.

En Cloudflare: túnel nuevo `portfolio` con las rutas `<dominio>` y `www.<dominio>` → `http://portfolio:8080`, quitadas del túnel compartido.

### Por qué funciona

- **H-11:** Docker no da salida a Internet a una red `internal: true`. El portfolio solo comparte red con cloudflared, que es el único servicio con una segunda red con salida.
- **H-11 (efecto secundario):** en una red `internal` Docker no publica puertos, así que el puerto del host desaparece. No hace falta: cloudflared llega por la red interna.
- **H-07:** la imagen oficial corre como uid 65532 (distroless, sin shell). Con `read_only`, `cap_drop: ALL` y `no-new-privileges`, un fallo en cloudflared ya no da root en el host.
- **Aislamiento:** el túnel solo sirve a este proyecto. Si se compromete su token, no afecta a las demás webs.
- **Se conserva la IP real del visitante:** la red interna mantiene la misma subred, y nginx sigue fiándose de `CF-Connecting-IP` solo desde ella (cloudflared está dentro).
- **El token** va como Docker secret con `--token-file`: no aparece en `docker inspect`, en `ps` ni en el repo.

### Validación previa en local

Antes de tocar el VPS se levantó el compose en una copia con un token falso:

- portfolio healthy en la red interna
- `wget example.com` → `bad address`
- otro contenedor de la red → `http://portfolio:8080` → 200
- cloudflared como `65532:65532`, read-only, `CapDrop [ALL]`; lee el secreto 444 (lo rechaza por falso, no por permisos)
- `CF-Connecting-IP: 203.0.113.9` desde la subred → el log registra `203.0.113.9`

### Efectos secundarios / problemas encontrados

Los tres están en [`errores-vividos.md`](../../errores-vividos.md):

1. **Error 1016 al mover las rutas.** Al quitarlas del túnel compartido, Cloudflare borró los registros DNS `@` y `www` y no los recreó en el túnel nuevo. Se crearon a mano (CNAME `<tunnelID>.cfargotunnel.com`, proxied). La caché DNS de la red local tardó en caducar; con otra red cargaba enseguida. Unos minutos sin servicio.
2. **`Pool overlaps`.** La red vieja usaba la misma subred y el compose nuevo ya no la conocía, así que `down` no la borraba. Se borraron a mano el contenedor y la red antes del `up`.
3. **Salto de línea en el token** (`nano`). Detectado con `wc -l` y quitado con `truncate -s -1`.

### Lo que queda

- El túnel compartido del host (systemd, root) sigue sirviendo los demás proyectos del VPS. **H-07 queda mitigado para el portfolio, no cerrado.** Se cierra al migrar el último proyecto con la misma plantilla y apagar el servicio del host.
- El aviso `failed to sufficiently increase receive buffer size` de QUIC se ajusta en el host (`net.core.rmem_max`). Es rendimiento, no seguridad.
