# Ofensivo: auditar y atacar mis propias configs

Caso real de auditoría sobre **mi propio VPS**: lo audito tal como estaba desplegado, documento los hallazgos, aplico las plantillas endurecidas de este repo y vuelvo a auditar para comprobar que los hallazgos quedan cerrados.

## Alcance

- **Objetivo:** únicamente mi VPS y los contenedores que despliego en él.
- **Fuera de alcance:** cualquier sistema de terceros, incluido el proveedor del VPS y Cloudflare.
- Los datos identificativos (IPs, dominios, usuarios, rutas, versiones) están **redactados**.
- Este caso se publicó **después** de corregir los hallazgos.

## Metodología

| Fase | Documento | Herramientas |
|---|---|---|
| 1. Reconocimiento externo | [`01-reconocimiento.md`](caso-vps/01-reconocimiento.md) | nmap, [`web.sh`](../verificacion/web.sh), curl |
| 2. Auditoría interna | [`02-auditoria-inicial.md`](caso-vps/02-auditoria-inicial.md) | [`contenedor.sh`](../verificacion/contenedor.sh), [`host.sh`](../verificacion/host.sh), [`herramientas.sh`](../verificacion/herramientas.sh) |
| 3. Hallazgos | [`03-hallazgos.md`](caso-vps/03-hallazgos.md) | CVSS 3.1, OWASP Docker Cheat Sheet |
| 4. Impacto | [`04-demostracion.md`](caso-vps/04-demostracion.md) | — |
| 5. Remediación | [`05-remediacion.md`](caso-vps/05-remediacion.md) | Plantillas de [`dockerfile/`](../dockerfile/), [`compose/`](../compose/), [`nginx/`](../nginx/) |
| 6. Retest | [`06-retest.md`](caso-vps/06-retest.md) | Los mismos scripts de la fase 2 |

## Resumen

> Pendiente: rellenar al terminar el caso.

| Severidad | Antes | Después |
|---|---|---|
| Crítica | – | – |
| Alta | – | – |
| Media | – | – |
| Baja | – | – |
