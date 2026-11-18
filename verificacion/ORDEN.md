# Orden de la verificación

Por dónde empezar al verificar un VPS con contenedores. Va **de fuera hacia dentro** y **de lo más grave a lo menos grave**, igual que un pentest: primero reconocimiento externo, luego enumeración interna.

```
fuera:  nmap  →  web.sh (URL pública)
dentro: Paso 0 → host.sh → contenedor.sh → web.sh (127.0.0.1) → herramientas.sh → manuales
```

Los comandos de cada paso y lo que se espera de ellos están en el [README](README.md).

---

## 1. `nmap` desde FUERA del VPS

Desde tu PC, **no** desde el propio VPS.

```bash
nmap -p- <IP_PUBLICA_VPS>
```

**Por qué primero:** es lo que ve un atacante. Si aparece un puerto de un contenedor (8000, 5432, 8090…), ya tienes el hallazgo más grave antes de entrar.

---

## 2. Paso 0: identificar qué hay corriendo

En el VPS, a mano (ningún script lo hace). Comandos en [README → Paso 0](README.md#paso-0-identificar-un-contenedor-ya-desplegado).

```bash
docker ps
docker inspect <contenedores> --format ...   # bloque del Paso 0
```

**Por qué:** para saber qué contenedores son, de qué proyecto vienen y si alguna imagen está huérfana. Sin esto no sabes qué nombres pasarle a `contenedor.sh` ni qué Dockerfile auditar (caso `ssh-rain` → `siege-map`).

---

## 3. `sudo ./host.sh`: el VPS y el daemon de Docker

```bash
sudo ./host.sh
```

**Por qué antes que los contenedores:** un `docker.sock` montado, la API de Docker por TCP o un `--privileged` le dan **root en el host** a quien entre en un contenedor. Un FALLO aquí anula todo lo demás: se arregla primero.

---

## 4. `./contenedor.sh`: el endurecimiento de cada contenedor

```bash
./contenedor.sh --todos          # o los nombres del Paso 0
```

Usuario, capabilities, read-only, no-new-privileges, seccomp, AppArmor, límites, puertos, secretos en variables y pruebas activas de post-explotación.

---

## 5. `./web.sh`: nginx por HTTP, dos veces

```bash
./web.sh -l /auth/login https://www.tudominio.com      # desde fuera: Cloudflare / nginx del host
./web.sh -H www.tudominio.com http://127.0.0.1:8081    # en el VPS, directo al contenedor
```

**Por qué dos veces:** una muestra lo que recibe el visitante y la otra lo que hace el contenedor por sí solo. Comparándolas ves qué capa pone cada cabecera (y si alguna sale duplicada o falta).

Opciones según el caso: `-e` web estática · `-l /ruta` rate limit del login (`-n 60` si el `burst` es de 20 o más) · `-b N` subida de N MB → 413.

---

## 6. `./herramientas.sh`: CVEs, lint y TLS

```bash
./herramientas.sh imagen mi-app:latest
./herramientas.sh dockerfile ../ruta/Dockerfile
./herramientas.sh nginx ../nginx/proxy.conf
./herramientas.sh tls www.tudominio.com
```

**Por qué al final:** es lo más lento y lo que más ruido da (trivy suele devolver muchos CVEs). Conviene revisarlo cuando ya sabes qué es grave de verdad.

---

## 7. Pruebas manuales

Las líneas marcadas `[❌ manual]` en el README que apliquen a tu stack, por ejemplo:

- Secretos: `ls /run/secrets` y `docker history | grep secret`
- Red de la BD: sin salida a Internet e inalcanzable desde `frontend_net` y desde el proxy
- `X-Real-IP` falsa desde otro contenedor
- Segunda capa sin `read_only`: `docker run --rm ... touch`
- nginx del host: `nginx -t`, sin www → www, acceso por IP

---

> El orden es un criterio, no una norma. Lo que sí es firme: `host.sh` va antes que el detalle de cada contenedor, porque un fallo del daemon anula todo lo demás.
