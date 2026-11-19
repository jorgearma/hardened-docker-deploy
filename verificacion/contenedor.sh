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
necesita_daemon

if [ $# -eq 0 ]; then
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
if [ "$1" = --todos ]; then
  # shellcheck disable=SC2046
  set -- $(docker ps --format '{{.Names}}')
  # Sin esto saldría "0 FALLO" y código 0 sin haber comprobado nada.
  [ $# -gt 0 ] || { echo "No hay contenedores en marcha: nada que auditar" >&2; exit 2; }
fi

ins() { docker inspect -f "$2" "$1" 2>/dev/null; }

revisar() {
  local c=$1 st pid uid user capdrop capadd capeff capbnd nnp sec aa v linea nombre valor
  local tmpfs_dirs vol_dirs dirs item d ej_tmp ej_vol noexec nocopia
  local salida= t red_t comp_t paq_t ro motivo
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
  # CapBnd es lo que de verdad refleja cap_drop: un proceso sin root tiene CapEff = 0
  # aunque no se haya quitado nada; CapBnd es el techo de lo que podría llegar a tener
  # (root con docker exec, un binario con file capabilities...).
  capbnd=$(campo CapBnd)
  if [ -z "$capbnd" ]; then
    manual "#3  no se pudo leer CapBnd del proceso principal"
  elif [ "$capbnd" = 0000000000000000 ]; then
    ok "#3  CapBnd = 0 (ninguna capability alcanzable dentro del contenedor)"
  elif [ -n "$capadd" ]; then
    aviso "#3  CapBnd = $capbnd (capsh --decode=$capbnd)"
  else
    fallo "#3  CapBnd = $capbnd: capabilities alcanzables (capsh --decode=$capbnd)"
  fi
  if [ "$capeff" = 0000000000000000 ]; then
    ok "#3  CapEff = 0 (el proceso principal no tiene ninguna capability activa)"
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
      salida=1
    fi
  done
  info "#5  redes:${v:- ninguna}"

  # shellcheck disable=SC2016
  # NetworkSettings.Ports = puertos publicados de verdad (HostConfig.PortBindings no ve "-P")
  v=$(ins "$c" '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}')
  if [ -z "$v" ]; then
    ok "#5a no publica puertos en el host"
  else
    local mal=
    for linea in $v; do
      case $linea in
        127.0.0.1:* | ::1:*) ;;
        :[0-9]*) mal="$mal 0.0.0.0$linea" ;;
        *) mal="$mal $linea" ;;
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

  # #12 Secretos en las capas de la imagen: ENV/ARG con valor y build-args de RUN quedan en
  # "docker history" aunque el compose no los pase. Solo se muestran los nombres, no los valores.
  v=$(docker history --no-trunc --format '{{.CreatedBy}}' "$(ins "$c" '{{.Image}}')" 2>/dev/null)
  if [ -z "$v" ]; then
    manual "#12 no se pudo leer docker history de la imagen: secretos en capas sin comprobar"
  else
    nombre=$(grep -oE '(^|[[:space:]|])[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+' <<<"$v" |
      sed 's/^[[:space:]|]*//' |
      awk -F= '$1 ~ /PASS|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL/ &&
               $1 !~ /_FILE$/ && $1 != "GPG_KEY" && $2 !~ "^/run/secrets/" { print $1 }' |
      sort -u | tr '\n' ' ')
    # Formatos de clave conocidos, aunque no vayan en una variable
    grep -qE -- '-----BEGIN [A-Z ]*PRIVATE KEY' <<<"$v" && nombre="${nombre}clave-privada-PEM "
    grep -qE 'AKIA[0-9A-Z]{16}' <<<"$v" && nombre="${nombre}clave-AWS "
    grep -qE 'gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}' <<<"$v" && nombre="${nombre}token-GitHub "
    grep -qE 'glpat-[A-Za-z0-9_-]{20}' <<<"$v" && nombre="${nombre}token-GitLab "
    grep -qE 'xox[baprs]-[A-Za-z0-9-]{10,}' <<<"$v" && nombre="${nombre}token-Slack "
    if [ -z "$nombre" ]; then
      ok "#12 ningún secreto a la vista en las capas de la imagen (docker history)"
    else
      fallo "#12 posibles secretos dentro de la imagen: ${nombre}(docker history --no-trunc; usar RUN --mount=type=secret)"
    fi
  fi

  # #12 Ficheros de secretos (compose sin Swarm = bind mount): el contenido está en el host.
  # Basta con que otro usuario no pueda llegar a él: fichero 444 dentro de secrets/ 700 es
  # correcto (el uid del contenedor necesita leerlo). Expuesto = fichero legible por "otros"
  # Y todos los directorios de la ruta atravesables por "otros".
  while IFS= read -r linea; do
    [ -n "$linea" ] || continue
    d=${linea%% *}
    if ! valor=$(stat -c '%a' "$d" 2>/dev/null); then
      manual "#12 secreto $d: no se pudo leer sus permisos (¿ejecutar con sudo?)"
      continue
    fi
    item=
    if [ $((0$valor & 4)) -ne 0 ]; then
      item=$d
      while [ "$item" != / ]; do
        item=$(dirname "$item")
        t=$(stat -c '%a' "$item" 2>/dev/null) || { item=?; break; }
        [ $((0$t & 1)) -ne 0 ] || break
      done
    fi
    case $item in
      '') ok "#12 secreto ${linea#* } protegido en el host ($d, $valor: no legible por otros)" ;;
      /)  fallo "#12 secreto ${linea#* } legible por cualquier usuario del host: $d ($valor; poner su directorio a 700)" ;;
      \?) manual "#12 secreto ${linea#* }: no se pudo comprobar la ruta $d (¿ejecutar con sudo?)" ;;
      *)  ok "#12 secreto ${linea#* } protegido en el host ($d, $valor, pero $item no es atravesable por otros)" ;;
    esac
  done < <(ins "$c" '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} {{.Destination}}{{"\n"}}{{end}}{{end}}' | grep ' /run/secrets/')

  # ── #13 Imagen ──
  v=$(ins "$c" '{{.Config.Image}}')
  if grep -q '@sha256:' <<<"$v"; then
    ok "#13 imagen fijada por digest"
  # Construida en local: no se puede fijar por digest en el compose (el digest nace al
  # construir); lo que cuenta es el FROM. Se detecta por la etiqueta que pone
  # "docker compose build" y, si no, por RepoDigests vacío. RepoDigests solo no basta:
  # con el containerd image store las imágenes construidas en local también tienen.
  elif [ -n "$(docker image inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$v" 2>/dev/null)" ] ||
       [ "$(docker image inspect -f '{{len .RepoDigests}}' "$v" 2>/dev/null)" = 0 ]; then
    manual "#13 imagen construida en local ($v): comprobar que el FROM lleva @sha256"
    # Sin etiqueta o con :latest (':[^/]+$' = hay tag; los ':' de host:puerto/ van antes de una '/')
    if ! grep -qE ':[^/]+$' <<<"$v" || grep -q ':latest$' <<<"$v"; then
      aviso "#13 $v sin versión en la etiqueta: no se sabe qué build está en marcha ni se puede volver atrás (etiquetar p. ej. con el commit de git)"
    fi
  else
    aviso "#13 imagen sin digest: $v"
  fi

  # ── Healthcheck ──
  v=$(ins "$c" '{{if .State.Health}}{{.State.Health.Status}}{{else}}ninguno{{end}}')
  case $v in
    healthy) ok "healthcheck: healthy" ;;
    ninguno) aviso "sin healthcheck" ;;
    starting) aviso "healthcheck: starting (recién arrancado: volver a pasarlo cuando acabe el primer intervalo)" ;;
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

  # Ejecución desde cualquier sitio escribible, no solo /tmp: en cada uno se copia el shell
  # a …/sh (con ese nombre para que busybox lo acepte) y se ejecuta. Se distingue "no se
  # pudo copiar" de "no se pudo ejecutar" para no dar por bueno un noexec sin comprobar.
  # shellcheck disable=SC2016
  tmpfs_dirs="/tmp /var/tmp /dev/shm $(ins "$c" '{{range $k, $v := .HostConfig.Tmpfs}}{{$k}} {{end}}{{range .Mounts}}{{if eq .Type "tmpfs"}}{{.Destination}} {{end}}{{end}}')"
  vol_dirs=$(ins "$c" '{{range .Mounts}}{{if and .RW (ne .Type "tmpfs")}}{{.Destination}} {{end}}{{end}}')
  # shellcheck disable=SC2086
  dirs=$(printf '%s\n' $tmpfs_dirs $vol_dirs | sort -u)
  # shellcheck disable=SC2016,SC2086
  v=$(docker exec "$c" sh -c '
    for d in "$@"; do
      [ -d "$d" ] || continue
      t="$d/.verif_$$"
      mkdir "$t" 2>/dev/null || continue
      if ! cp "$(command -v sh)" "$t/sh" 2>/dev/null; then echo "NOCOPIA:$d"
      elif "$t/sh" -c : 2>/dev/null; then echo "EJECUTA:$d"
      else echo "NOEXEC:$d"; fi
      rm -rf "$t"
    done' sh $dirs 2>/dev/null)
  ej_tmp=; ej_vol=; noexec=; nocopia=
  for item in $v; do
    d=${item#*:}
    case $item in
      NOEXEC:*)  noexec="$noexec $d" ;;
      NOCOPIA:*) nocopia="$nocopia $d" ;;
      EJECUTA:*)
        case " $vol_dirs " in
          *" $d "*) ej_vol="$ej_vol $d" ;;
          *)        ej_tmp="$ej_tmp $d" ;;
        esac
        ;;
    esac
  done
  [ -n "$v" ] || ok "#8  activa: ningún directorio escribible donde dejar un binario (/tmp, tmpfs, volúmenes)"
  [ -z "$noexec" ] || ok "#8  activa: escribible pero sin ejecución (noexec):$noexec"
  [ -z "$ej_tmp" ] || fallo "#8  activa: se puede ejecutar un binario copiado a:$ej_tmp (falta noexec)"
  [ -z "$ej_vol" ] || aviso "#8  activa: se puede ejecutar desde volúmenes escribibles:$ej_vol (ahí dejaría su binario un atacante)"
  [ -z "$nocopia" ] || manual "#8  activa: no se pudo copiar el shell a:$nocopia (¿sin espacio?): noexec sin comprobar"

  v=$(docker exec "$c" sh -c 'find / -xdev -perm -4000 -type f 2>/dev/null' 2>/dev/null | tr '\n' ' ')
  if [ -z "$v" ]; then
    ok "#4  activa: sin binarios SUID"
  elif [ "$nnp" = 1 ]; then
    info "#4  binarios SUID presentes pero anulados por no-new-privileges: $v"
  else
    aviso "#4  binarios SUID utilizables: $v"
  fi
  # El compose solo puede anularlos (no-new-privileges); quitarlos es cosa del build.
  # Vienen de la imagen base (p. ej. python:*-slim es Debian) y la app no los usa.
  [ -z "$v" ] || info "#4  quitarlos en el Dockerfile (antes de USER): RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true"

  # shellcheck disable=SC2016
  v=$(docker exec "$c" sh -c '
    for t in curl wget nc ncat socat gcc cc make pip apk apt-get git ssh; do
      command -v "$t" >/dev/null 2>&1 && printf "%s " "$t"
    done' 2>/dev/null)

  # La gravedad depende de si el resto del endurecimiento las deja sin uso:
  #  - red (nc/socat: reverse shell; curl/wget: payloads y exfiltración; "wget -O- | sh"
  #    no escribe en disco, así que noexec no lo para) → solo sirven con salida a Internet
  #  - compiladores → siempre sobran en producción
  #  - gestores de paquetes → solo instalan algo como root o con el rootfs escribible
  # En Alpine, wget y nc son applets de busybox, y muchos healthchecks usan wget.
  red_t=; comp_t=; paq_t=
  for t in $v; do
    case $t in
      curl | wget | nc | ncat | socat) red_t="$red_t $t" ;;
      gcc | cc | make)                 comp_t="$comp_t $t" ;;
      pip | apk | apt-get)             paq_t="$paq_t $t" ;;
    esac
  done
  ro=$(ins "$c" '{{.HostConfig.ReadonlyRootfs}}')
  [ -z "$red_t" ] || [ -z "$salida" ] ||
    aviso "herramientas de red con salida a Internet:$red_t (reverse shell, descarga de payloads, exfiltración)"
  [ -z "$comp_t" ] ||
    aviso "compiladores en un contenedor de producción:$comp_t (compilar exploits dentro)"
  [ -z "$paq_t" ] || { [ "$uid" != 0 ] && [ -n "$uid" ] && [ "$ro" = true ]; } ||
    aviso "gestor de paquetes utilizable:$paq_t (corre como root o el rootfs es escribible: puede instalar más herramientas)"

  # Lo que queda sin uso práctico sale como INFO, con el motivo
  motivo=
  [ -z "$red_t" ] || [ -n "$salida" ] || motivo="$motivo$red_t (red internal)"
  if [ -n "$paq_t" ] && [ "$uid" != 0 ] && [ -n "$uid" ] && [ "$ro" = true ]; then
    motivo="$motivo$paq_t (sin root + read-only)"
  fi
  if [ -z "$v" ]; then
    info "herramientas disponibles para un atacante: ninguna"
  elif [ -n "$motivo" ]; then
    info "herramientas presentes sin uso práctico:$motivo"
  fi
}

for c in "$@"; do
  revisar "$c"
done
resumen
