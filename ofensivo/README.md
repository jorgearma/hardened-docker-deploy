# Ofensivo: auditar y atacar mis propias configs

Caso real de auditoría sobre **mi propio VPS**: lo audito tal como estaba desplegado, documento los hallazgos, aplico las plantillas endurecidas de este repo y vuelvo a auditar para comprobar que los hallazgos quedan cerrados.

## Alcance

- **Objetivo:** únicamente mi VPS y los contenedores que despliego en él.
- **Fuera de alcance:** cualquier sistema de terceros, incluido el proveedor del VPS y Cloudflare.
- Los datos identificativos (IPs, dominios, usuarios, rutas, versiones) están **redactados**.
- El retest comprueba los hallazgos corregidos (H-07 y H-11); el resto queda documentado como abierto.

## Metodología

| Fase | Documento | Herramientas |
|---|---|---|
| 1. Reconocimiento externo | [`01-reconocimiento.md`](caso-vps/01-reconocimiento.md) | nmap, [`web.sh`](../verificacion/web.sh), curl |
| 2. Auditoría interna | [`02-auditoria-inicial.md`](caso-vps/02-auditoria-inicial.md) | [`contenedor.sh`](../verificacion/contenedor.sh), [`host.sh`](../verificacion/host.sh), [`herramientas.sh`](../verificacion/herramientas.sh) |
| 3. Hallazgos | [`03-hallazgos.md`](caso-vps/03-hallazgos.md) | CVSS 3.1, OWASP Docker Cheat Sheet |
| 4. Retest | [`04-retest.md`](caso-vps/04-retest.md) | Los mismos scripts de la fase 2 |
