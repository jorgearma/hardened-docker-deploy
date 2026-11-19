# Errores vividos

Fallos reales que me he encontrado desplegando y cómo los resolví.

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

## La imagen Python seguía teniendo `pip` aunque el test decía que no

- **Síntoma:** la prueba `python -m pip --version` daba `No module named pip`, pero `contenedor.sh` seguía listando `pip` entre las herramientas del contenedor.
- **Causa:** `python:3.12-slim` trae **dos** `pip`: el del venv (`/opt/venv`) y el del sistema (`/usr/local/bin/pip`). La plantilla solo quitaba el del venv, y el test usaba `python`, que con `PATH=/opt/venv/bin:...` es el del venv. El del sistema seguía funcionando:
  ```text
  $ docker run --rm --entrypoint sh mi-app:latest -c 'python -m pip --version; /usr/local/bin/pip --version'
  /opt/venv/bin/python: No module named pip
  pip 25.0.1 from /usr/local/lib/python3.12/site-packages/pip (python 3.12)
  ```
- **Arreglo:** en la etapa final, antes del `ENV PATH` y del `USER`: `RUN /usr/local/bin/python -m pip uninstall -y pip`. Comprobar con `which pip pip3` y con los **dos** intérpretes.
- **Lección:** un test que mira en el sitio equivocado da un falso OK. Comprobar la herramienta (`which`), no solo un camino para llegar a ella.

## `noexec` en un volumen con nombre no hace nada

- **Síntoma:** volumen creado con `--opt type=none --opt o=bind,noexec,nosuid,nodev`, y dentro del contenedor se sigue pudiendo ejecutar un binario copiado ahí.
- **Causa:** en Linux, las opciones de un bind mount (`noexec`, `nosuid`…) solo se aplican con un **segundo** `mount -o remount`; en la primera llamada se ignoran. El driver `local` de Docker no hace ese remount:
  ```text
  $ grep " /d " /proc/mounts
  /dev/nvme0n1p5 /d ext4 rw,relatime 0 0        ← sin noexec
  $ cp /bin/ls /d/ls && /d/ls
  EJECUTA
  ```
- **Arreglo:** si hace falta de verdad, montar en el **host** una carpeta con `noexec` (fstab: bind + remount) y pasarla como bind mount. En un contenedor con intérprete (`python`, `node`) aporta poco: `python /data/x.py` funciona igual con `noexec`.
- **Lección:** comprobar las opciones de montaje en `/proc/mounts` dentro del contenedor, no fiarse de lo que se pasó al crear el volumen.

## Rollback con un `TAG` que no existe: compose construye el código actual

- **Síntoma:** `TAG=<commit-viejo> docker compose up -d` (sin `--build`) arranca sin error, pero corre el código **actual**, etiquetado con el commit viejo.
- **Causa:** con `build:` + `image: app:${TAG}`, si esa imagen no existe en local, compose intenta descargarla y, al no encontrarla, la **construye** con el código que hay en disco. `pull_policy: never` tampoco lo evita (comprobado).
- **Arreglo:** comprobar antes que la imagen existe:
  ```bash
  T=<commit>; docker image inspect app:$T >/dev/null && TAG=$T docker compose up -d
  ```
- **Lección:** que un rollback "funcione" no significa que haya vuelto a la versión pedida. Mirar `docker inspect -f '{{.Config.Image}}'` y lo que hace la app.

## `web.sh` decía "sin rate limit" con el límite activo

- **Síntoma:** `[ FALLO] sin rate limit en /api/health: 20 POST seguidos y ningún 429`, con `limit_req zone=api burst=30 nodelay` en el nginx.
- **Causa:** con `burst=30`, las 20 peticiones del script caben enteras en el margen: el límite existe pero no llega a saltar.
- **Arreglo:** opción `-n` en `web.sh` (`-n 60`). Resultado: `27 de 60 peticiones → 429` (1 + 30 de burst + las que se recargan a 5 r/s durante la prueba).
- **Lección:** una prueba de rate limit tiene que superar el `burst`. Antes de dar un FALLO por bueno, mirar la config que se está probando.
