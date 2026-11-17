#!/usr/bin/env bash
# Funciones comunes de los scripts de verificación. No se ejecuta: se carga con "source".

if [ -t 1 ]; then
  V=$'\e[32m'; R=$'\e[31m'; A=$'\e[33m'; Z=$'\e[36m'; N=$'\e[1m'; X=$'\e[0m'
else
  V=; R=; A=; Z=; N=; X=
fi

n_ok=0; n_fallo=0; n_aviso=0; n_manual=0

titulo() { printf '\n%s== %s ==%s\n' "$N" "$*" "$X"; }
ok()     { n_ok=$((n_ok + 1));         printf '  %s[  OK  ]%s %s\n' "$V" "$X" "$*"; }
fallo()  { n_fallo=$((n_fallo + 1));   printf '  %s[ FALLO]%s %s\n' "$R" "$X" "$*"; }
aviso()  { n_aviso=$((n_aviso + 1));   printf '  %s[ AVISO]%s %s\n' "$A" "$X" "$*"; }
manual() { n_manual=$((n_manual + 1)); printf '  %s[MANUAL]%s %s\n' "$Z" "$X" "$*"; }
info()   { printf '  [ INFO ] %s\n' "$*"; }

# Resumen final. Código de salida 1 si hubo algún FALLO.
resumen() {
  printf '\n%sResumen:%s %s OK · %s FALLO · %s AVISO · %s MANUAL\n' \
    "$N" "$X" "$n_ok" "$n_fallo" "$n_aviso" "$n_manual"
  [ "$n_fallo" -eq 0 ]
}

necesita() {
  command -v "$1" >/dev/null 2>&1 || { echo "Falta el comando: $1" >&2; exit 2; }
}
