# Errores vividos

Fallos reales que me he encontrado desplegando y cómo los resolví.

> Pendiente: pasar aquí los 11 errores de mi plantilla de despliegue.

## `ulimits.nproc` agota los procesos de todo el host

- **Síntoma:** el contenedor no llega a `healthy`; `docker exec` y el healthcheck fallan con `resource temporarily unavailable`.
- **Causa:** `nproc` no cuenta los procesos del contenedor, sino los de **ese UID en todo el host** (sin userns, el uid del contenedor es el mismo que en el host). El uid 101 es `nginx` en `nginx-unprivileged` **y** `messagebus` (dbus) en Debian/Ubuntu. Con varios nginx (uno por núcleo) se llegó a 64.
- **Arreglo:** quitar `ulimits.nproc` y limitar con `pids_limit`, que va por cgroup y cuenta solo los procesos del contenedor.
- **Lección:** un límite que funciona en el VPS (2 núcleos) puede romper en otra máquina (20 núcleos). Probar las configs fuera del entorno donde nacieron.
