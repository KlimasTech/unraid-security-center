#!/bin/bash
# USC - jednokomendowe parowanie z pluginem na unRAID.
#
# Zastepuje reczne kroki 1, 3, 4 z docs/INSTALL.md: generuje 3 ograniczone
# klucze SSH, instaluje je w authorized_keys na unRAID (command= wymuszone
# server-side - zero shella), tworzy klucz API unRAID (rola VIEWER) i
# zapisuje USC_UNRAID_HOST/USC_UNRAID_API_KEY do .env.
#
# Wymaga: juz zainstalowanego pluginu "unRaid Security Center Plugin" na
# unRAID (docs/INSTALL.md krok 2) oraz dzialajacego dostepu SSH root do
# unRAID (hasło lub juz zaufany klucz) z TEGO hosta.
#
# Uzycie: scripts/usc_pair.sh <IP_UNRAID>
set -euo pipefail

UNRAID_HOST="${1:-}"
if [ -z "$UNRAID_HOST" ]; then
  echo "Uzycie: $0 <IP_UNRAID>" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
KEYS_DIR="collector/keys"
mkdir -p "$KEYS_DIR"

PLUGIN_SCRIPTS="/usr/local/emhttp/plugins/unraid-security-center/scripts"

echo "==> Sprawdzam czy plugin USC jest zainstalowany na $UNRAID_HOST..."
if ! ssh -o ConnectTimeout=10 "root@$UNRAID_HOST" "test -x $PLUGIN_SCRIPTS/usc_dispatch.sh"; then
  echo "BLAD: plugin 'unRaid Security Center Plugin' nie jest zainstalowany" >&2
  echo "       (lub nie masz jeszcze dzialajacego dostepu SSH root do $UNRAID_HOST)." >&2
  echo "       Zainstaluj go najpierw - patrz docs/INSTALL.md krok 2." >&2
  exit 1
fi
echo "    OK - plugin znaleziony."

gen_key() {
  local name="$1"
  if [ -f "$KEYS_DIR/$name" ] && [ -f "$KEYS_DIR/$name.pub" ]; then
    echo "==> Klucz $name juz istnieje (prywatny+publiczny), pomijam generowanie."
  elif [ -f "$KEYS_DIR/$name" ]; then
    echo "==> Klucz $name istnieje, ale brakuje .pub - odtwarzam z prywatnego."
    ssh-keygen -y -f "$KEYS_DIR/$name" > "$KEYS_DIR/$name.pub"
  else
    echo "==> Generuje klucz $name..."
    ssh-keygen -t ed25519 -f "$KEYS_DIR/$name" -N "" -C "$name" -q
  fi
}

gen_key usc_collector_key
gen_key usc_smart_key
gen_key usc_ops_key

install_key() {
  local name="$1" command="$2"
  local pubkey
  pubkey=$(cat "$KEYS_DIR/$name.pub")
  if ssh "root@$UNRAID_HOST" "grep -qF \"$pubkey\" /root/.ssh/authorized_keys 2>/dev/null"; then
    echo "==> Klucz $name juz jest w authorized_keys, pomijam."
  else
    echo "==> Instaluje klucz $name w authorized_keys (wymuszona komenda: $command)..."
    ssh "root@$UNRAID_HOST" "echo 'command=\"$command\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty $pubkey' >> /root/.ssh/authorized_keys"
  fi
}

install_key usc_collector_key "tail -n0 -F /var/log/syslog"
install_key usc_smart_key     "/bin/bash $PLUGIN_SCRIPTS/usc_smart_dump.sh"
install_key usc_ops_key       "/bin/bash $PLUGIN_SCRIPTS/usc_dispatch.sh"

echo "==> Weryfikuje klucze..."
timeout 5 ssh -o IdentitiesOnly=yes -i "$KEYS_DIR/usc_smart_key" "root@$UNRAID_HOST" > /dev/null 2>&1 || true
OPS_TEST=$( (timeout 10 ssh -o IdentitiesOnly=yes -i "$KEYS_DIR/usc_ops_key" "root@$UNRAID_HOST" "docker_health" 2>/dev/null || true) | head -1)
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
  echo "    Utworz go recznie (docs/INSTALL.md krok 4) i wklej do .env jako USC_UNRAID_API_KEY." >&2
else
  echo "    OK - klucz API gotowy (ten sam klucz jesli juz istnial - unraid-api jest idempotentny)."
fi

if [ ! -f .env ]; then
  echo "==> Tworze .env z .env.example..."
  cp .env.example .env
fi

update_env() {
  local key="$1" value="$2"
  if [ -z "$value" ]; then
    return
  fi
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    echo "${key}=${value}" >> .env
  fi
}

update_env "USC_UNRAID_HOST" "$UNRAID_HOST"
update_env "USC_UNRAID_API_KEY" "$API_KEY"

echo ""
echo "==> Gotowe. .env zaktualizowany (USC_UNRAID_HOST, USC_UNRAID_API_KEY)."
echo "    Pozostale wymagane wartosci (USC_DB_PASSWORD, USC_ADMIN_USER/PASSWORD,"
echo "    USC_INTERNAL_TOKEN) ustaw recznie w .env, potem: docker compose up -d --build"
