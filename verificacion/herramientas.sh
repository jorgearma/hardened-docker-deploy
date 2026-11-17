#!/usr/bin/env bash
# Lanza las herramientas externas de auditoría. Usa el binario si está instalado y,
# si no, la imagen de Docker (no hay que instalar nada en el VPS).
#
# Uso:
#   ./herramientas.sh imagen <imagen>           trivy (CVEs HIGH/CRITICAL) + dockle (lint de la imagen)
#   ./herramientas.sh dockerfile <Dockerfile>   hadolint + trivy config
#   ./herramientas.sh nginx <fichero.conf>      gixy
#   ./herramientas.sh tls <dominio>             testssl.sh
#   ./herramientas.sh secretos <directorio>     gitleaks (secretos en el repo y su historial)
#   ./herramientas.sh host                      docker-bench-security (CIS, como root)
#
# Las imágenes se pueden fijar por digest (regla #13) con variables de entorno:
#   TRIVY_IMG=aquasec/trivy@sha256:... ./herramientas.sh imagen mi-app:latest
#
# OJO: trivy y dockle en Docker montan docker.sock para leer la imagen local. Es un
# contenedor de un solo uso, pero es justo lo que prohíbe la regla #1: fijar el digest
# o instalar el binario.
set -u
. "$(dirname "$0")/lib.sh"
necesita docker

TRIVY_IMG=${TRIVY_IMG:-aquasec/trivy:latest}
DOCKLE_IMG=${DOCKLE_IMG:-goodwithtech/dockle:latest}
HADOLINT_IMG=${HADOLINT_IMG:-hadolint/hadolint:latest}
GIXY_IMG=${GIXY_IMG:-getpagespeed/gixy:latest}
TESTSSL_IMG=${TESTSSL_IMG:-ghcr.io/testssl/testssl.sh:latest}
GITLEAKS_IMG=${GITLEAKS_IMG:-zricethezav/gitleaks:latest}
BENCH_DIR=${BENCH_DIR:-$HOME/docker-bench-security}
SOCK=/var/run/docker.sock

# veredicto <nombre> <código de salida>
veredicto() {
  if [ "$2" -eq 0 ]; then ok "$1: sin hallazgos"; else fallo "$1: hallazgos o error (código $2), ver arriba"; fi
}

trivy_() {
  if command -v trivy >/dev/null 2>&1; then
    trivy "$@"
  else
    docker run --rm -v "$SOCK:$SOCK:ro" -v trivy-cache:/root/.cache "$TRIVY_IMG" "$@"
  fi
}

cmd=${1:-}
arg=${2:-}
case $cmd in
  imagen)
    [ -n "$arg" ] || { echo "Falta la imagen" >&2; exit 2; }
    titulo "trivy image $arg"
    trivy_ image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$arg"
    veredicto trivy $?
    titulo "dockle $arg"
    # KEY_SHA512: hash de la clave PÚBLICA de firma de nginx, en una capa de la imagen
    # base oficial (nginx, nginx-unprivileged). No es un secreto, pero CIS-DI-0010 marca
    # cualquier nombre con "KEY" → FATAL con todas las imágenes de nginx.
    if command -v dockle >/dev/null 2>&1; then
      dockle --exit-code 1 --accept-key KEY_SHA512 "$arg"
    else
      docker run --rm -v "$SOCK:$SOCK:ro" "$DOCKLE_IMG" --exit-code 1 --accept-key KEY_SHA512 "$arg"
    fi
    veredicto dockle $?
    ;;

  dockerfile)
    [ -f "$arg" ] || { echo "No existe el Dockerfile: $arg" >&2; exit 2; }
    titulo "hadolint $arg"
    if command -v hadolint >/dev/null 2>&1; then
      hadolint "$arg"
    else
      docker run --rm -i "$HADOLINT_IMG" <"$arg"
    fi
    veredicto hadolint $?
    titulo "trivy config $arg"
    if command -v trivy >/dev/null 2>&1; then
      trivy config --exit-code 1 "$arg"
    else
      docker run --rm -v "$(realpath "$arg"):/src/Dockerfile:ro" "$TRIVY_IMG" config --exit-code 1 /src
    fi
    veredicto "trivy config" $?
    ;;

  nginx)
    [ -f "$arg" ] || { echo "No existe el fichero: $arg" >&2; exit 2; }
    titulo "gixy $arg"
    docker run --rm -v "$(realpath "$arg"):/etc/nginx/conf.d/default.conf:ro" "$GIXY_IMG" \
      /etc/nginx/conf.d/default.conf
    veredicto gixy $?
    ;;

  tls)
    [ -n "$arg" ] || { echo "Falta el dominio" >&2; exit 2; }
    titulo "testssl.sh $arg"
    docker run --rm "$TESTSSL_IMG" --quiet --protocols --server-defaults --headers --vulnerable "$arg"
    manual "testssl: revisar el informe (esperado: solo TLS 1.2 y 1.3, sin vulnerabilidades)"
    ;;

  secretos)
    [ -d "$arg" ] || { echo "No existe el directorio: $arg" >&2; exit 2; }
    titulo "gitleaks $arg"
    docker run --rm -v "$(realpath "$arg"):/repo:ro" "$GITLEAKS_IMG" detect --source /repo --redact
    veredicto gitleaks $?
    ;;

  host)
    titulo "docker-bench-security (CIS Docker Benchmark)"
    if [ -x "$BENCH_DIR/docker-bench-security.sh" ]; then
      (cd "$BENCH_DIR" && sh docker-bench-security.sh)
      manual "docker-bench: revisar los [WARN] (muchos son del host: auditd, particiones, userns)"
    else
      echo "  No está en $BENCH_DIR. Instalarlo:"
      echo "    git clone https://github.com/docker/docker-bench-security.git $BENCH_DIR"
      exit 2
    fi
    ;;

  *)
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

resumen
