#!/usr/bin/env bash
# Comprueba el HOST y el daemon de Docker: las reglas OWASP que no dependen de un
# contenedor concreto (#0 #1 #5a #6 #10 #11). Ejecutar en el VPS, mejor como root.
#
# Uso:  sudo ./host.sh
set -u
. "$(dirname "$0")/lib.sh"
necesita_daemon

dj=/etc/docker/daemon.json

titulo "Host: $(hostname)"

# ── #0 Versiones ──
manual "#0  Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) · kernel $(uname -r): comprobar que están al día (apt list --upgradable)"

# ── #1 Socket y API del daemon ──
if pgrep -a dockerd | grep -q 'tcp://' || grep -qs 'tcp://' "$dj"; then
  fallo "#1  el daemon escucha por TCP (API de Docker en red = root remoto)"
else
  ok "#1  el daemon no escucha por TCP"
fi
if [ -S /var/run/docker.sock ]; then
  v=$(stat -c '%a %U:%G' /var/run/docker.sock)
  case $v in
    '660 root:docker' | '600 root:root') ok "#1  permisos de docker.sock: $v" ;;
    *) fallo "#1  permisos de docker.sock: $v (esperado 660 root:docker)" ;;
  esac
fi
v=$(getent group docker | cut -d: -f4)
[ -z "$v" ] || aviso "#1  usuarios en el grupo docker (equivalen a root): $v"
mal=
for c in $(docker ps -q); do
  if docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$c" | grep -q 'docker\.sock'; then
    mal="$mal $(docker inspect -f '{{.Name}}' "$c")"
  fi
done
if [ -z "$mal" ]; then
  ok "#1  ningún contenedor monta docker.sock"
else
  fallo "#1  contenedores que montan docker.sock:$mal"
fi

# ── #5a Puertos ──
# Todo lo que no sea loopback cuenta: 0.0.0.0, [::] y también una IP concreta del host
# (p. ej. "203.0.113.5:80:80"), que un grep de "0.0.0.0" dejaría pasar como OK.
mal=
for c in $(docker ps -q); do
  nombre=$(docker inspect -f '{{.Name}}' "$c")
  # shellcheck disable=SC2016
  for p in $(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}' "$c"); do
    case $p in
      127.*:* | ::1:*) ;;
      :[0-9]*) mal="$mal ${nombre#/}=0.0.0.0$p" ;;
      *)       mal="$mal ${nombre#/}=$p" ;;
    esac
  done
done
if [ -z "$mal" ]; then
  ok "#5a ningún contenedor publica puertos fuera de localhost"
else
  fallo "#5a contenedores con puertos abiertos a Internet (Docker se salta UFW):$mal"
fi
if command -v ss >/dev/null 2>&1; then
  v=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | tr '\n' ' ')
  info "#5a puertos TCP escuchando en interfaces públicas: ${v:-ninguno}"
  manual "#5a confirmarlo desde FUERA: nmap -p- <IP_PUBLICA_VPS>"
fi

# ── #6 / #11 Opciones de seguridad del daemon ──
v=$(docker info -f '{{.SecurityOptions}}' 2>/dev/null)
if grep -q seccomp <<<"$v"; then ok "#6  seccomp disponible en el daemon"; else fallo "#6  daemon sin seccomp"; fi
if grep -qE 'apparmor|selinux' <<<"$v"; then
  ok "#6  AppArmor/SELinux disponible en el daemon"
else
  aviso "#6  daemon sin AppArmor ni SELinux"
fi
if grep -qE 'rootless|userns' <<<"$v"; then
  ok "#11 daemon rootless o con userns-remap"
else
  manual "#11 daemon como root, sin userns-remap (opcional; lo compensan #2 #3 #4 en cada contenedor)"
fi

# ── #10 Log del daemon ──
if [ "$(docker info -f '{{.Debug}}' 2>/dev/null)" = true ]; then
  fallo "#10 daemon en modo debug"
else
  ok "#10 daemon sin modo debug (log en info)"
fi
if grep -qs 'max-size' "$dj"; then
  ok "#7  límite de tamaño de logs por defecto en daemon.json"
else
  info "#7  sin max-size en daemon.json: cada compose debe llevar su bloque logging"
fi

# ── Contenedores privilegiados ──
mal=
for c in $(docker ps -q); do
  [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$c")" = false ] ||
    mal="$mal $(docker inspect -f '{{.Name}}' "$c")"
done
if [ -z "$mal" ]; then
  ok "#2  ningún contenedor --privileged"
else
  fallo "#2  contenedores --privileged:$mal"
fi

info "auditoría completa del host (CIS): ./herramientas.sh host"
info "cada contenedor: ./contenedor.sh --todos"
resumen
