# 1. Reconocimiento externo

Lo que ve un atacante **desde fuera**, sin acceso al VPS. Ejecutado desde otra máquina.

- **Fecha:** AAAA-MM-DD
- **Origen:** máquina externa (no el propio VPS)
- **Objetivo:** `<VPS>` / `<dominio>`

## Puertos y servicios

```text
(salida de nmap redactada)
```

| Puerto | Servicio | ¿Debería estar expuesto? | Nota |
|---|---|---|---|
| | | | |

## Superficie web

```text
(salida de web.sh / cabeceras redactada)
```

| Prueba | Resultado | Esperado |
|---|---|---|
| Cabeceras de seguridad | | |
| Versión de nginx expuesta | | |
| Rutas sensibles (`/.git`, `/.env`…) | | |
| Métodos HTTP permitidos | | |
| Filtro de `Host` | | |
| Rate limit en login | | |

## Observaciones

-
