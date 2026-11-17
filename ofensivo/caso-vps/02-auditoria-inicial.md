# 2. Auditoría interna inicial

Estado del VPS **antes** de tocar nada. Salidas completas en [`evidencias/antes/`](evidencias/antes/).

- **Fecha:** AAAA-MM-DD
- **Copia de seguridad hecha:** sí / no

## Contenedores — `contenedor.sh`

```text
(salida redactada)
```

## Host y daemon — `host.sh`

```text
(salida redactada)
```

## Herramientas — `herramientas.sh`

| Herramienta | Objetivo | Resultado resumido |
|---|---|---|
| trivy | imagen | |
| dockle | imagen | |
| hadolint | Dockerfile | |
| gixy | nginx.conf | |
| testssl.sh | HTTPS | |
| gitleaks | repo de la app | |
| docker-bench-security | host | |

## Recuento

| Resultado | Número |
|---|---|
| OK | |
| FALLO | |
| AVISO | |
| MANUAL | |
