# 1. Reconocimiento externo

Lo que ve un atacante **desde fuera**, sin acceso al VPS. Ejecutado desde otra máquina.

- **Fecha:** 2026-11-17
- **Origen:** máquina externa (portátil, red doméstica; no el propio VPS)
- **Objetivo:** `<VPS>` (IP pública) / `<dominio>` (portfolio estático detrás de Cloudflare Tunnel)

## Puertos y servicios

TCP, los 65535 puertos:

```text
$ sudo nmap -Pn -sS -p- --min-rate 1000 --reason <VPS>
Not shown: 65533 filtered tcp ports (no-response), 1 filtered tcp ports (admin-prohibited)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 50
```

Versión del servicio y puertos web concretos:

```text
$ sudo nmap -Pn -sS -sV <VPS>
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu<redactado> (Ubuntu Linux; protocol 2.0)

$ nmap -Pn -p 8089,8080,80,443 <VPS>
80/tcp   filtered http
443/tcp  filtered https
8080/tcp filtered http-proxy
8089/tcp filtered unknown
```

| Puerto | Servicio | ¿Debería estar expuesto? | Nota |
|---|---|---|---|
| 22/tcp | SSH (OpenSSH 9.6p1, Ubuntu 24.04) | Sí | Único puerto abierto. **Acepta autenticación por contraseña** → H-01 |
| 80, 443/tcp | HTTP/HTTPS | No | `filtered`: la web solo entra por el túnel de Cloudflare |
| 8089/tcp | Puerto del contenedor en el host | No | `filtered`: publicado en `127.0.0.1`, Docker no se ha saltado UFW |
| 1 puerto TCP | — | — | `admin-prohibited` (ICMP 3/13) generado por la **red de origen**, no por el VPS (ver abajo) |
| Resto (65532) | — | No | `filtered (no-response)` |

Origen del ICMP *admin-prohibited*:

```text
$ sudo nmap -Pn -sS -p- --min-rate 1000 --packet-trace <VPS> | grep -i prohibited
RCVD ICMP [100.115.x.x > 192.168.x.x Communication administratively prohibited by filtering (type=3/code=13) ] IP [ttl=63 ...]
```

El rechazo lo envía `100.115.x.x` (espacio CGNAT, 100.64.0.0/10) con `ttl=63`, es decir, a **un salto** de la máquina de origen: es el operador de la red doméstica bloqueando ese puerto en salida (lo típico es el 25/SMTP), no una regla del VPS. Descartado como hallazgo.

SSH:

<!-- TODO: sustituir por la salida real de evidencias/antes/bruto/externo/1-ssh.txt -->

```text
$ nmap -Pn -p22 --script ssh-auth-methods <VPS>
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

Acceso directo por IP, sin pasar por Cloudflare:

```text
$ curl -m 5 -sI  http://<VPS>/     → sin respuesta (timeout)
$ curl -m 5 -skI https://<VPS>/    → sin respuesta (timeout)
```

## Superficie web

```text
$ ./web.sh -e https://<dominio>
  [  OK  ] responde (200)
  [  OK  ] x-content-type-options: nosniff
  [  OK  ] referrer-policy: strict-origin-when-cross-origin
  [  OK  ] permissions-policy: accelerometer=(), camera=(), geolocation=(), ...
  [  OK  ] cross-origin-opener-policy: same-origin
  [  OK  ] cross-origin-resource-policy: same-site
  [  OK  ] CSP activa
  [  OK  ] protección contra clickjacking (X-Frame-Options / frame-ancestors)
  [  OK  ] HSTS: max-age=2592000
  [  OK  ] Server sin versión (cloudflare)
  [  OK  ] sin X-Powered-By
  [  OK  ] las cabeceras también salen en páginas de error (always)
  [  OK  ] rutas sensibles (.git, .env, copias, configs) no se sirven
  [  OK  ] TRACE rechazado (405)
  [  OK  ] web estática: POST/PUT/DELETE/PATCH rechazados
  [  OK  ] Host inventado rechazado (403; 000 = conexión cortada)
  [MANUAL] rate limit del login no probado (usar -l /ruta/login)
  [  OK  ] HTTP redirige a HTTPS (301)
  [MANUAL] protocolos y cifrados TLS: ./herramientas.sh tls <dominio>

Resumen: 17 OK · 0 FALLO · 0 AVISO · 2 MANUAL
```

| Prueba | Resultado | Esperado |
|---|---|---|
| Cabeceras de seguridad | ✅ Todas presentes, también en páginas de error | Presentes, una sola vez |
| HSTS | ⚠️ `max-age=2592000` (30 días), lo pone Cloudflare | ≥ 1 año (`31536000`) + `includeSubDomains` |
| Versión de nginx expuesta | ✅ No (`Server: cloudflare`) | Sin versión |
| Rutas sensibles (`/.git`, `/.env`…) | ✅ No se sirven | 404 |
| Métodos HTTP permitidos | ✅ TRACE, POST, PUT, DELETE y PATCH → 405 | Solo GET/HEAD |
| Filtro de `Host` | ⚠️ 403, pero lo da **Cloudflare**, no el nginx del contenedor | Rechazo en el propio nginx (se comprueba en la fase 2 contra `127.0.0.1:8089`) |
| Rate limit en login | N/A | Web estática, sin login |
| HTTP → HTTPS | ✅ 301 | 301 |
| TLS | ✅ Solo TLS 1.2 y 1.3 (+ QUIC/h3); certificado ECDSA P-256 de Let's Encrypt emitido por Cloudflare | Solo TLS 1.2/1.3 |

## TLS (testssl.sh)

Lo que se ve es el borde de **Cloudflare** (dos IPs anycast), no el VPS. Lo que se puede cambiar está en el panel de Cloudflare.

```text
 SSLv2 / SSLv3 / TLS 1 / TLS 1.1   not offered
 TLS 1.2                           offered (OK)
 TLS 1.3                           offered (OK): final
 Server key size                   EC 256 bits (curve P-256)
 Issuer                            YE1 (Let's Encrypt from US)
 Strict Transport Security         2592000 s = 30 days is too short (>= 15552000 seconds recommended), just this domain
 BREACH (CVE-2013-3587)            potentially NOT ok, "br gzip" HTTP compression detected
                                   Can be ignored for static pages or if no secrets in the page
 LUCKY13 (CVE-2013-0169)           potentially VULNERABLE, uses cipher block chaining (CBC) ciphers with TLS
 OCSP stapling                     not offered
 (resto de vulnerabilidades: not vulnerable)
```

| Resultado de testssl | Valoración |
|---|---|
| Solo TLS 1.2 y 1.3 | ✅ |
| HSTS 30 días, sin `includeSubDomains` | ⚠️ → H-02 |
| BREACH | No aplica: página estática, sin cookies ni secretos en la respuesta |
| LUCKY13 (CBC en TLS 1.2) | Informativo: suites CBC que ofrece Cloudflare por compatibilidad; ataque de canal lateral no práctico hoy. Se acepta |
| OCSP stapling no ofrecido | No aplica: Let's Encrypt dejó de dar servicio OCSP en 2025 |

## Observaciones

- La superficie externa se reduce a **SSH**. La web no es accesible por IP: el VPS no abre 80/443 y todo el tráfico entra por `cloudflared`.
- El puerto del contenedor (8089) no es alcanzable desde fuera, así que publicarlo solo en `127.0.0.1` cumple su función (OWASP #5a).
- HSTS de 30 días: candidato a hallazgo **bajo** (H-02). Se corrige en el panel de Cloudflare, no en el repo.
- El 403 ante un `Host` inventado no prueba el filtro de nginx, porque Cloudflare corta antes. Se valida en la fase 2.
- **SSH acepta contraseña** además de clave pública: expone el único servicio abierto a fuerza bruta y credential stuffing. Candidato a hallazgo **medio** (H-01).
- El ICMP *admin-prohibited* lo genera la red desde la que se escaneaba (CGNAT del operador, un salto), no el VPS. Lección: comprobar de dónde viene una respuesta antes de atribuirla al objetivo.

### Pendiente para cerrar la fase

- [x] Identificar el origen del *admin-prohibited*
- [x] Métodos de autenticación SSH
- [x] `./herramientas.sh tls <dominio>`
- [ ] `nmap -sU --top-ports 50`
