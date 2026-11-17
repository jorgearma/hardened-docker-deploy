#!/usr/bin/env bash
# Comprueba desde fuera lo que configura nginx: cabeceras, rutas sensibles, métodos,
# filtro de Host, rate limit y tamaño de subida.
#
# Uso:  ./web.sh [opciones] URL
#   -H dominio   cabecera Host a enviar (cuando la URL es 127.0.0.1:<puerto>)
#   -l ruta      ruta del login: lanza 20 POST y espera algún 429
#   -b MB        envía un POST de ese tamaño y espera 413 (poner más que client_max_body_size)
#   -e           web estática: POST/PUT/DELETE no deben aceptarse (405)
#   -k           aceptar certificado autofirmado
#
# Ejemplos:
#   ./web.sh -H www.example.com -l /auth/login -b 2 http://127.0.0.1:8081
#   ./web.sh -e http://127.0.0.1:8090
#   ./web.sh -l /auth/login https://www.example.com      # a través de Cloudflare / nginx del host
#
# OJO: -l deja tu IP limitada en el login durante un minuto.
set -u
. "$(dirname "$0")/lib.sh"
necesita curl

host=; login=; cuerpo=; estatica=0; extra=()
while getopts 'H:l:b:ek' o; do
  case $o in
    H) host=$OPTARG ;;
    l) login=$OPTARG ;;
    b) cuerpo=$OPTARG ;;
    e) estatica=1 ;;
    k) extra+=(-k) ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))
if [ $# -ne 1 ]; then
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
url=${1%/}
[ -n "$host" ] || host=$(sed -E 's#^https?://([^/]+).*#\1#' <<<"$url")

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

pet()    { curl -s -m 10 "${extra[@]}" -H "Host: $host" "$@"; }
codigo() { pet -o /dev/null -w '%{http_code}' "$@"; }

titulo "Web: $url (Host: $host)"

c=$(codigo "$url/")
case $c in
  000) fallo "no responde (¿URL, puerto o Host correctos?)"; resumen; exit 1 ;;
  2* | 3*) ok "responde ($c)" ;;
  *) aviso "la raíz responde $c" ;;
esac

# ── Cabeceras ──
cab=$(pet -D - -o /dev/null "$url/" | tr -d '\r')
veces() { grep -ci "^$1:" <<<"$cab"; }
valor() { grep -i "^$1:" <<<"$cab" | head -1 | cut -d: -f2- | sed 's/^ *//'; }

# cabecera <nombre> <fallo|aviso>: debe aparecer exactamente una vez
cabecera() {
  local n
  n=$(veces "$1")
  case $n in
    1) ok "$1: $(valor "$1" | cut -c1-70)" ;;
    0) "$2" "falta la cabecera $1" ;;
    *) fallo "$1 duplicada ($n veces): la ponen dos capas a la vez" ;;
  esac
}
cabecera x-content-type-options fallo
cabecera referrer-policy fallo
cabecera permissions-policy aviso
cabecera cross-origin-opener-policy aviso
cabecera cross-origin-resource-policy aviso

n=$(veces content-security-policy)
if [ "$n" -eq 1 ]; then
  ok "CSP activa"
elif [ "$n" -gt 1 ]; then
  fallo "CSP duplicada ($n veces)"
elif [ "$(veces content-security-policy-report-only)" -ge 1 ]; then
  aviso "CSP solo en Report-Only: avisa pero no bloquea"
else
  fallo "sin CSP"
fi

if [ "$(veces x-frame-options)" -gt 1 ]; then
  fallo "x-frame-options duplicada"
elif [ "$(veces x-frame-options)" -eq 1 ] || valor content-security-policy | grep -q frame-ancestors; then
  ok "protección contra clickjacking (X-Frame-Options / frame-ancestors)"
else
  fallo "sin protección contra clickjacking"
fi

n=$(veces strict-transport-security)
case $url in
  https://*)
    case $n in
      1) ok "HSTS: $(valor strict-transport-security)" ;;
      0) fallo "falta HSTS en HTTPS" ;;
      *) fallo "HSTS duplicada ($n veces)" ;;
    esac
    ;;
  *)
    if [ "$n" -eq 0 ]; then
      info "sin HSTS (correcto en HTTP: va donde se termina el TLS)"
    else
      aviso "HSTS enviada por HTTP: debería ponerla solo quien termina el TLS"
    fi
    ;;
esac

v=$(valor server)
if grep -q '[0-9]' <<<"$v"; then
  fallo "la cabecera Server muestra la versión: $v"
else
  ok "Server sin versión (${v:-ausente})"
fi
if [ "$(veces x-powered-by)" -eq 0 ]; then
  ok "sin X-Powered-By"
else
  fallo "X-Powered-By: $(valor x-powered-by)"
fi

while IFS= read -r linea; do
  [ -n "$linea" ] || continue
  nombre=$(cut -d: -f2- <<<"$linea" | cut -d= -f1 | tr -d ' ')
  falta=
  for f in secure httponly samesite; do
    grep -qi "; *$f" <<<"$linea" || falta="$falta $f"
  done
  if [ -z "$falta" ]; then
    ok "cookie $nombre con Secure, HttpOnly y SameSite"
  else
    aviso "cookie $nombre sin:$falta"
  fi
done < <(grep -i '^set-cookie:' <<<"$cab")

# Las cabeceras también deben salir en los errores ("always")
noexiste="/verif-$RANDOM$RANDOM-noexiste"
if pet -D - -o /dev/null "$url$noexiste" | grep -qi '^x-content-type-options:'; then
  ok "las cabeceras también salen en páginas de error (always)"
else
  aviso "las cabeceras no salen en páginas de error: falta 'always' en add_header"
fi

# ── Rutas sensibles ──
# Una SPA devuelve index.html (200) para cualquier ruta: se compara con una ruta inventada.
fb_code=$(codigo "$url$noexiste")
fb_hash=$(pet "$url$noexiste" | md5sum)
mal=
for p in /.git/config /.git/HEAD /.env /.env.production /.htpasswd /.DS_Store \
  /Dockerfile /docker-compose.yml /compose.yml /nginx.conf /requirements.txt \
  /backup.sql /db.sql /backup.bak /backup.zip /config.ini /app.log; do
  c=$(pet -o "$tmp" -w '%{http_code}' "$url$p")
  [ "$c" = 200 ] || continue
  if [ "$fb_code" = 200 ] && [ "$(md5sum <"$tmp")" = "$fb_hash" ]; then
    continue
  fi
  mal="$mal $p"
done
if [ -z "$mal" ]; then
  ok "rutas sensibles (.git, .env, copias, configs) no se sirven"
else
  fallo "rutas sensibles accesibles (200):$mal"
fi

# ── Métodos ──
c=$(codigo -X TRACE "$url/")
case $c in
  2*) fallo "TRACE aceptado ($c)" ;;
  *)  ok "TRACE rechazado ($c)" ;;
esac
if [ "$estatica" -eq 1 ]; then
  mal=
  for m in POST PUT DELETE PATCH; do
    c=$(codigo -X "$m" "$url/")
    case $c in 2*) mal="$mal $m=$c" ;; esac
  done
  if [ -z "$mal" ]; then
    ok "web estática: POST/PUT/DELETE/PATCH rechazados"
  else
    fallo "web estática acepta métodos de escritura:$mal"
  fi
fi

# ── Filtro de Host ──
c=$(curl -s -m 10 "${extra[@]}" -o /dev/null -w '%{http_code}' -H 'Host: verif-invalido.example' "$url/")
case $c in
  2* | 3*)
    if [ "$estatica" -eq 1 ]; then
      aviso "responde $c a un Host inventado (poco impacto en una web estática)"
    else
      fallo "responde $c a un Host inventado: llega a la app (envenenamiento de enlaces y caché)"
    fi
    ;;
  *) ok "Host inventado rechazado ($c; 000 = conexión cortada)" ;;
esac

# ── Rate limit del login ──
if [ -n "$login" ]; then
  n=0
  for _ in $(seq 20); do
    [ "$(codigo -X POST "$url$login")" != 429 ] || n=$((n + 1))
  done
  if [ "$n" -gt 0 ]; then
    ok "rate limit en $login: $n de 20 peticiones → 429"
  else
    fallo "sin rate limit en $login: 20 POST seguidos y ningún 429"
  fi
else
  manual "rate limit del login no probado (usar -l /ruta/login)"
fi

# ── Tamaño de subida ──
if [ -n "$cuerpo" ]; then
  c=$(head -c "$((cuerpo * 1024 * 1024))" /dev/zero | codigo -X POST --data-binary @- "$url/")
  if [ "$c" = 413 ]; then
    ok "POST de $cuerpo MB → 413"
  else
    fallo "POST de $cuerpo MB → $c (se esperaba 413: revisar client_max_body_size)"
  fi
fi

# ── HTTPS ──
case $url in
  https://*)
    if ! grep -q ':[0-9]' <<<"${url#https://}"; then
      r=$(curl -s -m 10 -o /dev/null -w '%{http_code} %{redirect_url}' "http://${url#https://}/")
      case $r in
        30[178]\ https://*) ok "HTTP redirige a HTTPS (${r%% *})" ;;
        *) fallo "HTTP no redirige a HTTPS (respuesta: $r)" ;;
      esac
    fi
    manual "protocolos y cifrados TLS: ./herramientas.sh tls ${url#https://}"
    ;;
esac

resumen
