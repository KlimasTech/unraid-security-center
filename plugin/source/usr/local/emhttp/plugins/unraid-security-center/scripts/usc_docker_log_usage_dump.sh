#!/bin/bash
# unRaid Security Center Plugin - zajetosc logow kontenerow Docker.
#
# unRAID NIE udostepnia gotowej wartosci "% zajetosci logow Docker" (ani w
# GraphQL, ani w webGUI) - liczymy sami: suma realnych rozmiarow plikow
# *-json.log, podzielona przez teoretyczny limit wynikajacy z polityki
# rotacji w docker.cfg (DOCKER_LOG_SIZE x DOCKER_LOG_FILES x liczba
# kontenerow). Wywolywane WYLACZNIE przez dyspozytor (usc_dispatch.sh,
# akcja "docker_log_usage") przez ograniczony klucz SSH "ops".
set -euo pipefail

CFG="/boot/config/docker.cfg"

LOG_SIZE_RAW=""
LOG_FILES="1"
if [ -f "$CFG" ]; then
  LOG_SIZE_RAW=$(sed -n 's/^DOCKER_LOG_SIZE="\(.*\)"/\1/p' "$CFG")
  LOG_FILES=$(sed -n 's/^DOCKER_LOG_FILES="\(.*\)"/\1/p' "$CFG")
fi
[ -z "$LOG_FILES" ] && LOG_FILES=1

parse_size() {
  local s="$1" num unit
  if [ -z "$s" ]; then echo 0; return; fi
  num=$(echo "$s" | grep -oE '^[0-9]+')
  unit=$(echo "$s" | grep -oE '[a-zA-Z]+$' || true)
  case "$(echo "${unit:-}" | tr 'A-Z' 'a-z')" in
    k) echo $((num * 1024)) ;;
    m) echo $((num * 1024 * 1024)) ;;
    g) echo $((num * 1024 * 1024 * 1024)) ;;
    *) echo "${num:-0}" ;;
  esac
}

LOG_SIZE_BYTES=$(parse_size "$LOG_SIZE_RAW")
# Fallback: domyslny limit dockerd (bez konfiguracji rotacji) to 10MB
[ "$LOG_SIZE_BYTES" -eq 0 ] && LOG_SIZE_BYTES=10485760

CONTAINER_COUNT=$(/usr/bin/docker ps -aq | wc -l)
MAX_BYTES=$((LOG_SIZE_BYTES * LOG_FILES * CONTAINER_COUNT))

USED_BYTES=0
for f in /var/lib/docker/containers/*/*-json.log; do
  [ -f "$f" ] || continue
  SZ=$(stat -c%s "$f" 2>/dev/null || echo 0)
  USED_BYTES=$((USED_BYTES + SZ))
done

if [ "$MAX_BYTES" -gt 0 ]; then
  USED_PCT=$(( USED_BYTES * 100 / MAX_BYTES ))
else
  USED_PCT=0
fi

printf '{"used_bytes": %s, "max_bytes": %s, "used_pct": %s, "container_count": %s}\n' \
  "$USED_BYTES" "$MAX_BYTES" "$USED_PCT" "$CONTAINER_COUNT"
