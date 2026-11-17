# Errores vividos

Fallos reales que me he encontrado desplegando y cómo los resolví.

> Pendiente: pasar aquí los 11 errores de mi plantilla de despliegue.

## `ulimits.nproc` agota los procesos de todo el host

- **Síntoma:** el contenedor no llega a `healthy`; `docker exec` y el healthcheck fallan con `resource temporarily unavailable`.
- **Causa:** `nproc` no cuenta los procesos del contenedor, sino los de **ese UID en todo el host** (sin userns, el uid del contenedor es el mismo que en el host). El uid 101 es `nginx` en `nginx-unprivileged` **y** `messagebus` (dbus) en Debian/Ubuntu. Con varios nginx (uno por núcleo) se llegó a 64.
- **Arreglo:** quitar `ulimits.nproc` y limitar con `pids_limit`, que va por cgroup y cuenta solo los procesos del contenedor.
- **Lección:** un límite que funciona en el VPS (2 núcleos) puede romper en otra máquina (20 núcleos). Probar las configs fuera del entorno donde nacieron.

## Mover un hostname a otro túnel de Cloudflare deja el dominio sin DNS (error 1016)

- **Síntoma:** después de pasar `@` y `www` de un túnel a otro, la web da **Error 1016 – Origin DNS error**. El túnel nuevo está conectado y en sus logs aparece la ruta (`Updated to new configuration`).
- **Causa:** al borrar la ruta del túnel viejo, Cloudflare borró también los registros DNS de esos nombres; al añadir la ruta al túnel nuevo **no los volvió a crear**. En DNS → Records no estaban ni `@` ni `www`.
- **Arreglo:** crearlos a mano: CNAME `@` y `www` → `<tunnelID>.cfargotunnel.com`, **proxied**. El aviso de "CNAME flattening" en `@` es normal (no afecta al MX del correo). El ID sale en los logs: `docker compose logs cloudflared | grep -o 'tunnelID=[a-f0-9-]*'`.
- **Después:** el navegador siguió diciendo "no se puede acceder" un rato: el DNS de la red local había guardado el "no existe". `dig @1.1.1.1` ya resolvía; con datos móviles cargaba.
- **Lección:** tras mover rutas entre túneles, revisar **siempre** DNS → Records. Y distinguir "Cloudflare no sabe adónde ir" (página de error de Cloudflare) de "mi red no resuelve el nombre" (error del navegador).

## La red nueva no se crea: `Pool overlaps`

- **Síntoma:** al cambiar el nombre de la red en el compose y hacer `up`, Docker se niega a crearla porque la subred se solapa.
- **Causa:** la red vieja (con la misma subred fija) seguía existiendo. Si el compose ya es el nuevo, `docker compose down` no la borra: no la conoce.
- **Arreglo:** antes del `up`, `docker rm -f <contenedor-viejo>` y `docker network rm <red-vieja>` (o hacer `down` con el compose viejo **antes** del `git pull`).
- **Lección:** la subred fija (necesaria por `set_real_ip_from`) obliga a borrar la red vieja antes de crear la nueva.

## El secreto lleva un salto de línea al final

- **Síntoma:** `wc -l secrets/tunnel_token` da `1` en un fichero que solo debería tener el token.
- **Causa:** `nano` añade un `\n` al final al guardar.
- **Arreglo:** `truncate -s -1` (con `chmod 644` antes y `444` después), o escribirlo con `nano -L` o `read -rs T; printf '%s' "$T" > fichero`.
- **Lección:** comprobar los secretos con `wc -l` (debe ser 0) y `tail -c 2 | od -c`. Algunos programas recortan el salto; otros lo toman como parte del secreto.
