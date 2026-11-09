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
  *)
    echo "USC_DISPATCH_REJECTED: nieznana akcja" >&2
    exit 1
    ;;
esac
