#!/usr/bin/env bash
# Funciones comunes de los scripts de verificación. No se ejecuta: se carga con "source".
#
# Salida:
#   - Terminal: banner, secciones en árbol, etiquetas de color y resumen con barra y veredicto.
#   - Redirigida a fichero / pipe, o con NO_COLOR=1: el mismo formato sin códigos de color.
#   - Cada línea mantiene la etiqueta en texto (OK, FALLO, AVISO, MANUAL, INFO) para grep.
#   - Código de salida 1 si hubo algún FALLO (lo devuelve resumen).

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _C=1
  X=$'\e[0m'; N=$'\e[1m'; G=$'\e[38;5;244m'
  V=$'\e[38;5;46m'; R=$'\e[38;5;196m'; A=$'\e[38;5;214m'; Z=$'\e[38;5;45m'; B=$'\e[38;5;39m'
  # Etiquetas con fondo de color
  BV=$'\e[1;38;5;16;48;5;46m'; BR=$'\e[1;38;5;231;48;5;196m'
  BA=$'\e[1;38;5;16;48;5;214m'; BZ=$'\e[1;38;5;16;48;5;45m'; BG=$'\e[38;5;252;48;5;238m'
else
  _C=
  X=; N=; G=; V=; R=; A=; Z=; B=; BV=; BR=; BA=; BZ=; BG=
fi

n_ok=0; n_fallo=0; n_aviso=0; n_manual=0
s_ok=0; s_fallo=0; s_aviso=0; s_manual=0
_sec_abierta=; _sec_nombre=; _filas=(); _banner_hecho=

ANCHO=${COLUMNS:-$(tput cols 2>/dev/null)}
[ "${ANCHO:-0}" -gt 0 ] 2>/dev/null || ANCHO=80
[ "$ANCHO" -le 100 ] || ANCHO=100

_rep() { local s=$1 n=$2 out=; while [ "$n" -gt 0 ]; do out+=$s; n=$((n - 1)); done; printf '%s' "$out"; }

# ── Banner (una vez por ejecución, en el primer titulo) ──
_banner() {
  [ -z "$_banner_hecho" ] || return 0
  _banner_hecho=1
  local logo=(
    ' █████╗  ██╗   ██╗ ██████╗  ██╗ ████████╗'
    '██╔══██╗ ██║   ██║ ██╔══██╗ ██║ ╚══██╔══╝'
    '███████║ ██║   ██║ ██║  ██║ ██║    ██║   '
    '██╔══██║ ██║   ██║ ██║  ██║ ██║    ██║   '
    '██║  ██║ ╚██████╔╝ ██████╔╝ ██║    ██║   '
    '╚═╝  ╚═╝  ╚═════╝  ╚═════╝  ╚═╝    ╚═╝   '
  )
  local grad=(51 45 39 33 27 63)
  local modulo usuario
  modulo=$(basename "$0" .sh)
  usuario=$(id -un 2>/dev/null)
  local meta=(
    ''
    "${N}DOCKER · NGINX · HOST HARDENING${X}"
    "${G}OWASP Docker Security Cheat Sheet${X}"
    "${G}módulo  ${X} ${B}${modulo}${X}"
    "${G}objetivo${X} $(uname -n) ${G}como${X} ${usuario:-?}"
    "${G}fecha   ${X} $(date '+%Y-%m-%d %H:%M:%S %Z')"
  )
  local i lado=
  [ "$ANCHO" -ge 86 ] && lado=1
  printf '\n'
  for i in "${!logo[@]}"; do
    if [ -n "$_C" ]; then printf '  \e[1;38;5;%sm%s%s' "${grad[i]}" "${logo[i]}" "$X"
    else printf '  %s' "${logo[i]}"; fi
    if [ -n "$lado" ]; then printf '   %s\n' "${meta[i]}"; else printf '\n'; fi
  done
  if [ -z "$lado" ]; then
    printf '\n'
    for i in 1 2 3 4 5; do printf '  %s\n' "${meta[i]}"; done
  fi
}

# ── Secciones ──
_cerrar_seccion() {
  [ -n "$_sec_abierta" ] || return 0
  printf ' %s└─%s %s✔ %s%s %s·%s %s✘ %s%s %s·%s %s▲ %s%s %s·%s %s? %s%s\n' \
    "$G" "$X" "$V" "$s_ok" "$X" "$G" "$X" "$R" "$s_fallo" "$X" "$G" "$X" \
    "$A" "$s_aviso" "$X" "$G" "$X" "$Z" "$s_manual" "$X"
  _filas+=("$s_ok|$s_fallo|$s_aviso|$s_manual|$_sec_nombre")
  _sec_abierta=
}

titulo() {
  _banner
  _cerrar_seccion
  local txt=$* etiqueta objetivo cab relleno
  if [[ $txt == *': '* ]]; then
    etiqueta=${txt%%: *}; objetivo=${txt#*: }
  else
    etiqueta=${txt%% *}; objetivo=${txt#"$etiqueta"}; objetivo=${objetivo# }
  fi
  etiqueta=${etiqueta^^}
  cab=" ┌──[ $etiqueta ]── $objetivo "
  relleno=$((ANCHO - ${#cab} - 1))
  [ "$relleno" -ge 3 ] || relleno=3
  printf '\n %s┌──[%s %s%s%s %s]──%s %s%s%s %s%s%s\n' \
    "$G" "$X" "$N$B" "$etiqueta" "$X" "$G" "$X" "$N" "$objetivo" "$X" "$G" "$(_rep ─ "$relleno")" "$X"
  printf ' %s│%s\n' "$G" "$X"
  _sec_abierta=1; _sec_nombre=$txt
  s_ok=0; s_fallo=0; s_aviso=0; s_manual=0
}

# Una línea de resultado. Separa el número de regla OWASP ("#5a ...") en su propia columna.
_re_regla='^(#[0-9]+[a-z]?)[[:space:]]+(.*)$'
_linea() {
  local badge=$1 icono=$2 col=$3 tag=$4; shift 4
  local msg=$* regla=
  if [[ $msg =~ $_re_regla ]]; then regla=${BASH_REMATCH[1]}; msg=${BASH_REMATCH[2]}; fi
  if [ -n "$_C" ]; then
    printf ' %s│%s %s%s%s %s %-6s %s %s%-4s%s %s%s%s\n' \
      "$G" "$X" "$col" "$icono" "$X" "$badge" "$tag" "$X" "$G" "$regla" "$X" "$col" "$msg" "$X"
  else
    printf ' │ %s [%-6s] %-4s %s\n' "$icono" "$tag" "$regla" "$msg"
  fi
}

ok()     { n_ok=$((n_ok + 1));         s_ok=$((s_ok + 1));         _linea "$BV" '✔' "" '  OK  ' "$@"; }
fallo()  { n_fallo=$((n_fallo + 1));   s_fallo=$((s_fallo + 1));   _linea "$BR" '✘' "$N$R" ' FALLO' "$@"; }
aviso()  { n_aviso=$((n_aviso + 1));   s_aviso=$((s_aviso + 1));   _linea "$BA" '▲' "$A" ' AVISO' "$@"; }
manual() { n_manual=$((n_manual + 1)); s_manual=$((s_manual + 1)); _linea "$BZ" '?' "$Z" 'MANUAL' "$@"; }
info()   { _linea "$BG" '·' "$G" ' INFO ' "$@"; }

# Resumen final. Código de salida 1 si hubo algún FALLO.
resumen() {
  _cerrar_seccion
  local tot=$((n_ok + n_fallo + n_aviso)) pct=100 llenas largo=30 colbar veredicto f a b c d nombre
  [ "$tot" -eq 0 ] || pct=$((n_ok * 100 / tot))
  llenas=$((pct * largo / 100))
  if   [ "$n_fallo" -gt 0 ]; then colbar=$R
    veredicto="${N}${R}✘ VULNERABLE${X}  ${N}${R}$n_fallo fallo(s): corregir antes de producción${X}"
  elif [ "$n_aviso" -gt 0 ]; then colbar=$A
    veredicto="${N}${A}▲ REVISAR${X}  ${A}sin fallos, $n_aviso aviso(s) por valorar${X}"
  else colbar=$V
    veredicto="${N}${V}✔ ENDURECIDO${X}  ${V}sin fallos ni avisos${X}"
  fi

  printf '\n %s┌──[%s %sRESUMEN%s %s]%s%s\n' "$G" "$X" "$N$B" "$X" "$G" "$(_rep ─ $((ANCHO - 16)))" "$X"
  # Todo el bloque lleva el mismo margen "│" que las secciones
  {
  printf '\n'

  # Tabla por sección (solo si hay más de una: p. ej. contenedor.sh --todos)
  if [ "${#_filas[@]}" -gt 1 ]; then
    printf '  %s   ✔    ✘    ▲    ?   sección%s\n' "$G" "$X"
    for f in "${_filas[@]}"; do
      IFS='|' read -r a b c d nombre <<<"$f"
      printf '  %s%4s%s %s%4s%s %s%4s%s %s%4s%s   %s\n' \
        "$V" "$a" "$X" "$R" "$b" "$X" "$A" "$c" "$X" "$Z" "$d" "$X" "$nombre"
    done
    printf '\n'
  fi

  printf '  %scomprobaciones%s  %s✔ %s OK%s   %s✘ %s FALLO%s   %s▲ %s AVISO%s   %s? %s MANUAL%s\n' \
    "$G" "$X" "$V" "$n_ok" "$X" "$R" "$n_fallo" "$X" "$A" "$n_aviso" "$X" "$Z" "$n_manual" "$X"
  printf '  %ssuperadas     %s  %s%s%s%s%s %3s%%  %s(OK / OK+FALLO+AVISO)%s\n' \
    "$G" "$X" "$colbar" "$(_rep █ "$llenas")" "$G" "$(_rep ░ $((largo - llenas)))" "$X" "$pct" "$G" "$X"
  printf '  %sveredicto     %s  %s\n' "$G" "$X" "$veredicto"
  [ "$n_manual" -eq 0 ] || printf '  %s                %s%s punto(s) MANUAL: el script no puede decidirlos, revisar a mano%s\n' "$G" "$Z" "$n_manual" "$X"
  printf '  %sduración      %s  %ss\n' "$G" "$X" "$SECONDS"
  printf '\n'
  } | while IFS= read -r f; do printf ' %s│%s%s\n' "$G" "$X" "$f"; done
  printf ' %s└%s%s\n\n' "$G" "$(_rep ─ $((ANCHO - 3)))" "$X"
  [ "$n_fallo" -eq 0 ]
}

necesita() {
  command -v "$1" >/dev/null 2>&1 || { echo "Falta el comando: $1" >&2; exit 2; }
}

# Sin acceso al daemon, "docker ps" sale vacío y las comprobaciones darían OK falsos.
necesita_daemon() {
  necesita docker
  docker info >/dev/null 2>&1 ||
    { echo "Sin acceso al daemon de Docker (¿sudo? ¿grupo docker? ¿está arrancado?)" >&2; exit 2; }
}
