#!/usr/bin/env bash
# Audita contenedores EN MARCHA contra las reglas de la OWASP Docker Security Cheat Sheet
# que se pueden comprobar por contenedor (#1 #2 #3 #4 #5 #5a #6 #7 #8 #12 #13).
#
# Uso:  ./contenedor.sh <contenedor> [<contenedor>...]
#       ./contenedor.sh --todos
#
# Las pruebas activas (escribir, ejecutar desde /tmp) crean un fichero temporal dentro
# del contenedor y lo borran en el mismo comando. No reinicia ni modifica nada más.
set -u
. "$(dirname "$0")/lib.sh"
necesita docker

if [ $# -eq 0 ]; then
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
if [ "$1" = --todos ]; then
  # shellcheck disable=SC2046
  set -- $(docker ps --format '{{.Names}}')
fi

ins() { docker inspect -f "$2" "$1" 2>/dev/null; }

revisar() {
  local c=$1 st pid uid user capdrop capadd capeff nnp sec aa v linea nombre valor
  titulo "Contenedor: $c"

  if [ "$(ins "$c" '{{.State.Running}}')" != true ]; then
    fallo "no existe o no está en marcha"
    return
  fi

  # Estado real del proceso principal: se lee de /proc del host (no necesita nada
  # dentro del contenedor); si no se puede, con docker exec.
  pid=$(ins "$c" '{{.State.Pid}}')
  st=$(cat "/proc/$pid/status" 2>/dev/null)
  [ -n "$st" ] || st=$(docker exec "$c" cat /proc/1/status 2>/dev/null)
  campo() { awk -v k="$1:" '$1 == k { print $2; exit }' <<<"$st"; }

  # ── #1 Socket del daemon ──
  if ins "$c" '{{range .Mounts}}{{.Source}} {{end}}' | grep -q 'docker\.sock'; then
    fallo "#1  monta docker.sock (equivale a root en el host)"
  else
    ok "#1  no monta el socket de Docker"
  fi

  # ── #2 Usuario ──
  user=$(ins "$c" '{{.Config.User}}')
  uid=$(campo Uid)
  if [ -z "$uid" ]; then
    manual "#2  no se pudo leer el uid del proceso principal (User='$user')"
  elif [ "$uid" = 0 ]; then
    fallo "#2  el proceso principal corre como root (User='${user:-vacío}')"
  else
    ok "#2  proceso principal sin root (uid $uid, User='${user:-vacío}')"
  fi
  if [ "$(ins "$c" '{{.HostConfig.Privileged}}')" = false ]; then
    ok "#2  no es --privileged"
  else
    fallo "#2  contenedor --privileged"
  fi

  # ── #3 Capabilities ──
  capdrop=$(ins "$c" '{{.HostConfig.CapDrop}}' | tr -d '[]')
  capadd=$(ins "$c" '{{.HostConfig.CapAdd}}' | tr -d '[]')
  capeff=$(campo CapEff)
  if grep -qiw all <<<"$capdrop"; then
    ok "#3  cap_drop: ALL"
  else
    fallo "#3  falta cap_drop: [ALL] (CapDrop='$capdrop')"
  fi
  [ -z "$capadd" ] || aviso "#3  capabilities añadidas: $capadd (justificar cada una)"
  if [ "$capeff" = 0000000000000000 ]; then
    ok "#3  CapEff = 0 (el proceso no tiene ninguna capability)"
  elif [ -n "$capadd" ]; then
    aviso "#3  CapEff = $capeff (capsh --decode=$capeff)"
  else
    fallo "#3  CapEff = ${capeff:-desconocido} (capsh --decode=$capeff)"
  fi

  # ── #4 Escalada ──
  nnp=$(campo NoNewPrivs)
  if [ "$nnp" = 1 ]; then
    ok "#4  no-new-privileges activo"
  else
    fallo "#4  falta security_opt: no-new-privileges:true"
  fi

  # ── #5 / #5a Red y puertos ──
  v=$(ins "$c" '{{.HostConfig.NetworkMode}}')
  case $v in
    host)           fallo "#5  network_mode: host (sin aislamiento de red)" ;;
    default|bridge) aviso "#5  usa la red bridge por defecto (compartida con otros contenedores)" ;;
    *)              ok "#5  red propia" ;;
  esac
  [ "$(ins "$c" '{{.HostConfig.PidMode}}')" != host ] || fallo "#5  pid: host (ve los procesos del host)"
  [ "$(ins "$c" '{{.HostConfig.IpcMode}}')" != host ] || fallo "#5  ipc: host"
  v=
  for linea in $(ins "$c" '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}'); do
    nombre=$(docker network inspect -f '{{.Name}}' "$linea" 2>/dev/null)
    if [ "$(docker network inspect -f '{{.Internal}}' "$linea" 2>/dev/null)" = true ]; then
      v="$v $nombre(internal)"
    else
      v="$v $nombre(con salida)"
    fi
  done
  info "#5  redes:${v:- ninguna}"

  # shellcheck disable=SC2016
  v=$(ins "$c" '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}')
  if [ -z "$v" ]; then
    ok "#5a no publica puertos en el host"
  else
    local mal=
    for linea in $v; do
      case $linea in
        127.0.0.1:* | ::1:*) ;;
        *) mal="$mal ${linea/#:/0.0.0.0:}" ;;
      esac
    done
    if [ -z "$mal" ]; then
      ok "#5a puertos solo en localhost: $v"
    else
      fallo "#5a puertos abiertos a Internet (Docker se salta UFW):$mal"
    fi
  fi

  # ── #6 seccomp / AppArmor ──
  sec=$(campo Seccomp)
  if [ "$sec" = 2 ]; then
    ok "#6  seccomp en modo filtro"
  else
    fallo "#6  seccomp desactivado (Seccomp=${sec:-desconocido})"
  fi
  aa=$(ins "$c" '{{.AppArmorProfile}}')
  case $aa in
    unconfined) fallo "#6  AppArmor: unconfined" ;;
    '')         aviso "#6  sin perfil AppArmor (¿el host no usa AppArmor? si usa SELinux, comprobarlo aparte)" ;;
    *)          ok "#6  AppArmor: $aa" ;;
  esac

  # ── #7 Recursos ──
  v=$(ins "$c" '{{.HostConfig.Memory}}')
  if [ "${v:-0}" -gt 0 ] 2>/dev/null; then
    ok "#7  límite de memoria: $((v / 1024 / 1024)) MB"
  else
    fallo "#7  sin límite de memoria"
  fi
  v=$(ins "$c" '{{.HostConfig.PidsLimit}}')
  if [ "${v:-0}" -gt 0 ] 2>/dev/null; then
    ok "#7  pids_limit: $v"
  else
    fallo "#7  sin pids_limit (una fork bomb tumba el host)"
  fi
  if [ "$(ins "$c" '{{.HostConfig.NanoCpus}}')" = 0 ] && [ "$(ins "$c" '{{.HostConfig.CpuQuota}}')" = 0 ]; then
    aviso "#7  sin límite de CPU"
  else
    ok "#7  límite de CPU"
  fi
  if ins "$c" '{{range .HostConfig.Ulimits}}{{.Name}} {{end}}' | grep -qw nproc; then
    aviso "#7  usa ulimits.nproc: cuenta los procesos de ese UID en TODO el host → usar pids_limit"
  fi
  if [ "$(ins "$c" '{{.HostConfig.LogConfig.Type}}')" = json-file ] &&
     [ -z "$(ins "$c" '{{index .HostConfig.LogConfig.Config "max-size"}}')" ]; then
    aviso "#7  logs json-file sin max-size (crecen hasta llenar el disco, salvo límite en daemon.json)"
  fi

  # ── #8 Sistema de ficheros ──
  if [ "$(ins "$c" '{{.HostConfig.ReadonlyRootfs}}')" = true ]; then
    ok "#8  sistema de ficheros read-only"
  else
    fallo "#8  falta read_only: true"
  fi
  # Sin opciones Docker ya aplica noexec,nosuid,nodev; solo es problema un "exec" explícito
  # shellcheck disable=SC2016
  while IFS= read -r linea; do
    [ -n "$linea" ] || continue
    ! grep -qE '[:,]exec(,|$)' <<<"$linea" || aviso "#8  tmpfs montado con exec: $linea"
  done < <(ins "$c" '{{range $k, $v := .HostConfig.Tmpfs}}{{$k}}:{{$v}}{{"\n"}}{{end}}')
  v=$(ins "$c" '{{range .Mounts}}{{if and .RW (eq .Type "bind")}}{{.Source}}->{{.Destination}} {{end}}{{end}}')
  [ -z "$v" ] || aviso "#8  bind mounts con escritura: $v"
  v=$(ins "$c" '{{range .Mounts}}{{if and .RW (eq .Type "volume")}}{{.Destination}} {{end}}{{end}}')
  [ -z "$v" ] || info "#8  volúmenes con escritura: $v"

  # ── #12 Secretos ──
  v=
  while IFS= read -r linea; do
    nombre=${linea%%=*}
    valor=${linea#*=}
    [ -n "$valor" ] || continue
    case $nombre in *_FILE | GPG_KEY) continue ;; esac
    if grep -qiE 'PASS|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL' <<<"$nombre"; then
      v="$v $nombre"
    fi
  done < <(ins "$c" '{{range .Config.Env}}{{println .}}{{end}}')
  if [ -z "$v" ]; then
    ok "#12 ninguna variable de entorno con pinta de secreto"
  else
    fallo "#12 posibles secretos en variables de entorno (se ven con docker inspect):$v"
  fi

  # ── #13 Imagen ──
  v=$(ins "$c" '{{.Config.Image}}')
  if grep -q '@sha256:' <<<"$v"; then
    ok "#13 imagen fijada por digest"
  elif [ "$(docker image inspect -f '{{len .RepoDigests}}' "$v" 2>/dev/null)" = 0 ]; then
    manual "#13 imagen construida en local ($v): comprobar que el FROM lleva @sha256"
  else
    aviso "#13 imagen sin digest: $v"
  fi

  # ── Healthcheck ──
  v=$(ins "$c" '{{if .State.Health}}{{.State.Health.Status}}{{else}}ninguno{{end}}')
  case $v in
    healthy) ok "healthcheck: healthy" ;;
    ninguno) aviso "sin healthcheck" ;;
    *)       fallo "healthcheck: $v" ;;
  esac

  # ── Pruebas activas (lo que intentaría alguien que ya está dentro) ──
  if ! docker exec "$c" sh -c true 2>/dev/null; then
    manual "sin shell dentro del contenedor: pruebas activas no ejecutadas (bueno para la seguridad)"
    return
  fi

  # shellcheck disable=SC2016
  v=$(docker exec "$c" sh -c '
    for d in "$@"; do
      [ -d "$d" ] || continue
      f="$d/.verif_$$"
      if ( : > "$f" ) 2>/dev/null; then rm -f "$f"; printf "%s " "$d"; fi
    done' sh / /etc /usr/local/bin /usr/share/nginx/html /app /opt/venv 2>/dev/null)
  if [ -z "$v" ]; then
    ok "#8  activa: no se puede escribir en /, /etc, código ni librerías"
  else
    fallo "#8  activa: se pudo escribir en: $v(ya borrado)"
  fi

  # Se copia el shell a /tmp/…/sh (con ese nombre para que busybox lo acepte) y se ejecuta.
  # shellcheck disable=SC2016
  v=$(docker exec "$c" sh -c '
    d=/tmp/.verif_$$
    mkdir "$d" 2>/dev/null || { echo NOESCRIBE; exit; }
    cp "$(command -v sh)" "$d/sh" 2>/dev/null && "$d/sh" -c "echo EJECUTA" 2>/dev/null
    rm -rf "$d"' 2>/dev/null)
  case $v in
    EJECUTA)   fallo "#8  activa: se puede ejecutar un binario copiado a /tmp (falta noexec)" ;;
    NOESCRIBE) ok "#8  activa: /tmp no es escribible" ;;
    *)         ok "#8  activa: /tmp no permite ejecutar (noexec)" ;;
  esac

  v=$(docker exec "$c" sh -c 'find / -xdev -perm -4000 -type f 2>/dev/null' 2>/dev/null | tr '\n' ' ')
  if [ -z "$v" ]; then
    ok "#4  activa: sin binarios SUID"
  elif [ "$nnp" = 1 ]; then
    info "#4  binarios SUID presentes pero anulados por no-new-privileges: $v"
  else
    aviso "#4  binarios SUID utilizables: $v"
  fi

  # shellcheck disable=SC2016
  v=$(docker exec "$c" sh -c '
    for t in curl wget nc ncat socat gcc cc make pip apk apt-get git ssh; do
      command -v "$t" >/dev/null 2>&1 && printf "%s " "$t"
    done' 2>/dev/null)
  info "herramientas disponibles para un atacante: ${v:-ninguna}"
}

for c in "$@"; do
  revisar "$c"
done
resumen
