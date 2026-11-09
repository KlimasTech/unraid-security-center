#!/bin/bash
# unRaid Security Center Plugin - dyspozytor komend dla ograniczonego
# klucza SSH kolektora ("ops" key). Klucz w authorized_keys wymusza
# WYLACZNIE wywolanie tego skryptu (command=); klient przesyla nazwe
# akcji jako normalna komenda SSH, ktora SSH serwer udostepnia tu jako
# $SSH_ORIGINAL_COMMAND - ten skrypt porownuje ja z twarda biala lista i
# odrzuca kazda inna wartosc. Klient NIE MOZE wykonac nic poza
# zdefiniowanymi tutaj akcjami odczytu.
DIR="$(dirname "$0")"

case "$SSH_ORIGINAL_COMMAND" in
  docker_health)
    exec /bin/bash "$DIR/usc_docker_health_dump.sh"
    ;;
  syslog_previous)
    exec /bin/bash "$DIR/usc_syslog_previous_dump.sh"
    ;;
  vm_health)
    exec /bin/bash "$DIR/usc_vm_health_dump.sh"
    ;;
  vm_log_tail)
    exec /bin/bash "$DIR/usc_vm_log_tail.sh"
    ;;
  log_usage)
    exec /bin/bash "$DIR/usc_log_usage_dump.sh"
    ;;
  unpair)
    # Rozlaczenie z panelu USC: usuwa WSZYSTKIE 3 wpisy USC z
    # authorized_keys (oznaczone komentarzem "# USC-managed" przy
    # instalacji - patrz unraid_pair.py/usc_pair.sh) i usuwa klucz API
    # unRAID "USC ReadOnly". Dziala rowniez dla klucza, ktorym wlasnie
    # zostala wywolana ta komenda - usuniecie linii z authorized_keys NIE
    # przerywa juz trwajacej sesji SSH, tylko blokuje przyszle polaczenia.
    sed -i '/# USC-managed$/d' /root/.ssh/authorized_keys
    /usr/local/sbin/unraid-api apikey --delete --name "USC ReadOnly" --json 2>&1 || true
    echo "USC_UNPAIR_OK"
    ;;
  *)
    echo "USC_DISPATCH_REJECTED: nieznana akcja" >&2
    exit 1
    ;;
esac
