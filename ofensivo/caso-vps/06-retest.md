# 6. Retest

Las mismas pruebas de las fases 1 y 2, después de la remediación. Salidas completas en [`evidencias/despues/`](evidencias/despues/).

- **Fecha:** AAAA-MM-DD

## Antes / después

| Prueba | Antes | Después |
|---|---|---|
| Usuario del proceso | | |
| Sistema de ficheros read-only | | |
| `cap_drop: ALL` | | |
| `no-new-privileges` | | |
| Puertos fuera de `127.0.0.1` | | |
| Secretos en `ENV` | | |
| Límites de memoria / CPU / pids | | |
| Cabeceras de seguridad | | |
| Rutas sensibles bloqueadas | | |

## Estado de los hallazgos

| ID | Antes | Después |
|---|---|---|
| H-01 | Abierto | Cerrado / Mitigado / Aceptado |

## Riesgo residual

Lo que queda y por qué se acepta.
