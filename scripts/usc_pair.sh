#!/bin/bash
# USC - jednokomendowe parowanie z pluginem na unRAID (alternatywa CLI).
#
# UWAGA: od wersji z wizardem, najlatwiejszy sposob parowania jest w panelu
# web: zaloguj sie na http://<host>:8420/wizard i wpisz IP + haslo roota
# unRAID - backend zrobi wszystko sam, bez zadnej komendy w terminalu.
# Ten skrypt to alternatywa dla kogos, kto wolii CLI (lub nie ma jeszcze
# zalogowania do panelu skonfigurowanego).
#
# Dziala PRZEZ kontener usc-backend (docker exec) - klucze trafiaja prosto
# do wspoldzielonego wolumenu usc-keys-data, ktory kolektor juz uzywa.
# Wymaga: `docker compose up -d` juz wykonanego (kontener usc-backend dziala),
# plugin "unRaid Security Center Plugin" juz zainstalowany na unRAID, oraz
# dzialajacego dostepu SSH root do unRAID z TEGO hosta (hasło lub zaufany klucz).
#
# Uzycie: scripts/usc_pair.sh <IP_UNRAID>
set -euo pipefail

UNRAID_HOST="${1:-}"
if [ -z "$UNRAID_HOST" ]; then
  echo "Uzycie: $0 <IP_UNRAID>" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

if ! docker inspect usc-backend > /dev/null 2>&1; then
  echo "BLAD: kontener usc-backend nie istnieje/nie dziala." >&2
  echo "       Odpal najpierw: docker compose up -d --build" >&2
  exit 1
fi

PLUGIN_SCRIPTS="/usr/local/emhttp/plugins/unraid-security-center/scripts"

echo "==> Sprawdzam czy plugin USC jest zainstalowany na $UNRAID_HOST..."
if ! ssh -o ConnectTimeout=10 "root@$UNRAID_HOST" "test -x $PLUGIN_SCRIPTS/usc_dispatch.sh"; then
  echo "BLAD: plugin 'unRaid Security Center Plugin' nie jest zainstalowany" >&2
  echo "       (lub nie masz jeszcze dzialajacego dostepu SSH root do $UNRAID_HOST)." >&2
  echo "       Zainstaluj go najpierw - patrz docs/INSTALL.md krok 1." >&2
  exit 1
fi
echo "    OK - plugin znaleziony."

gen_key() {
  local name="$1"
  if docker exec usc-backend sh -c "[ -f /app/keys/$name ] && [ -f /app/keys/$name.pub ]"; then
    echo "==> Klucz $name juz istnieje (prywatny+publiczny) w wolumenie, pomijam."
  elif docker exec usc-backend sh -c "[ -f /app/keys/$name ]"; then
    echo "==> Klucz $name istnieje, ale brakuje .pub - odtwarzam z prywatnego."
    docker exec usc-backend sh -c "ssh-keygen -y -f /app/keys/$name > /app/keys/$name.pub"
  else
    echo "==> Generuje klucz $name (w kontenerze usc-backend)..."
    docker exec usc-backend ssh-keygen -t ed25519 -f "/app/keys/$name" -N "" -C "$name" -q
  fi
}

gen_key usc_collector_key
gen_key usc_smart_key
gen_key usc_ops_key

install_key() {
  local name="$1" command="$2"
  local pubkey
  pubkey=$(docker exec usc-backend cat "/app/keys/$name.pub")
  if ssh "root@$UNRAID_HOST" "grep -qF \"$pubkey\" /root/.ssh/authorized_keys 2>/dev/null"; then
    echo "==> Klucz $name juz jest w authorized_keys, pomijam."
  else
    echo "==> Instaluje klucz $name w authorized_keys (wymuszona komenda: $command)..."
    ssh "root@$UNRAID_HOST" "mkdir -p /root/.ssh && echo 'command=\"$command\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty $pubkey # USC-managed' >> /root/.ssh/authorized_keys"
  fi
}

install_key usc_collector_key "tail -n0 -F /var/log/syslog"
install_key usc_smart_key     "/bin/bash $PLUGIN_SCRIPTS/usc_smart_dump.sh"
install_key usc_ops_key       "/bin/bash $PLUGIN_SCRIPTS/usc_dispatch.sh"

echo "==> Weryfikuje klucze (z kontenera usc-backend)..."
OPS_TEST=$(docker exec usc-backend sh -c "timeout 10 ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -i /app/keys/usc_ops_key root@$UNRAID_HOST docker_health 2>/dev/null" | head -1 || true)
if [ -z "$OPS_TEST" ]; then
  echo "    UWAGA: test klucza ops nie zwrocil danych - sprawdz recznie." >&2
else
  echo "    OK - klucze dzialaja."
fi

echo "==> Tworze/pobieram klucz API unRAID (rola VIEWER)..."
API_KEY_JSON=$(ssh "root@$UNRAID_HOST" "/usr/local/sbin/unraid-api apikey --create --name 'USC ReadOnly' --roles VIEWER --json" 2>&1) || true
API_KEY=$(echo "$API_KEY_JSON" | grep -oE '"key":"[a-f0-9]+"' | grep -oE '[a-f0-9]{32,}' || true)
if [ -z "$API_KEY" ]; then
  echo "    UWAGA: nie udalo sie automatycznie wyciagnac klucza API z wyniku:" >&2
  echo "$API_KEY_JSON" >&2
  echo "    Utworz go recznie i wklej w panelu /settings jako klucz API unRAID." >&2
else
  echo "    OK - klucz API gotowy (ten sam klucz jesli juz istnial - unraid-api jest idempotentny)."
fi

echo "==> Zapisuje ustawienia do panelu (wymaga USC_ADMIN_USER/PASSWORD z .env)..."
if [ -f .env ]; then
  ADMIN_USER=$(grep -E '^USC_ADMIN_USER=' .env | cut -d= -f2- || true)
  ADMIN_PASS=$(grep -E '^USC_ADMIN_PASSWORD=' .env | cut -d= -f2- || true)
  WEB_PORT=$(grep -E '^USC_WEB_PORT=' .env | cut -d= -f2- || true)
  WEB_PORT="${WEB_PORT:-8420}"
  if [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ]; then
    curl -s -u "$ADMIN_USER:$ADMIN_PASS" -X POST "http://localhost:${WEB_PORT}/settings" \
      --data-urlencode "unraid_host=$UNRAID_HOST" \
      --data-urlencode "unraid_api_key=$API_KEY" \
      --data-urlencode "telegram_bot_token=" \
      --data-urlencode "telegram_chat_id=" \
      -o /dev/null -w "    HTTP %{http_code}\n" || true
  else
    echo "    UWAGA: brak USC_ADMIN_USER/PASSWORD w .env - ustaw host/klucz API recznie w /settings." >&2
  fi
else
  echo "    UWAGA: brak .env - ustaw host/klucz API recznie w panelu /settings." >&2
fi

echo ""
echo "==> Gotowe."
