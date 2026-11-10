#!/bin/bash
# unRaid Security Center Plugin - dyspozytor komend dla ograniczonego
# klucza SSH kolektora ("ops" key). Klucz w authorized_keys wymusza
# WYLACZNIE wywolanie tego skryptu (command=); klient przesyla nazwe
# akcji jako normalna komende SSH, ktora SSH serwer udostepnia tu jako
# $SSH_ORIGINAL_COMMAND - ten skrypt porownuje ja z twarda biala lista i
# odrzuca kazda inna wartosc. Klient NIE MOZE wykonac nic poza
# zdefiniowanymi tutaj akcjami odczytu.
#
# Tryb "daemon": JEDNA dlugotrwala sesja SSH dla calego zycia kolektora -
# klient nawiazuje SSH raz, wysyla nazwy akcji na stdin (po jednej na
# linie) i czyta ramkowane odpowiedzi USC_BEGIN/USC_END. Bez tego KAZDA
# akcja to nowy kanal sesji = minimum 2 linie logu sshd na unRAID
# ("Starting session"/"Close session") - przy odpytywaniu co kilka minut
# to realny spam w systemowym syslogu. Daemon pojawia sie w logu sshd
# TYLKO przy nawiazaniu i zerwaniu sesji.
DIR="$(dirname "$0")"

run_action() {
  case "$1" in
    docker_health)
      /bin/bash "$DIR/usc_docker_health_dump.sh"
      ;;
    syslog_previous)
      /bin/bash "$DIR/usc_syslog_previous_dump.sh"
      ;;
    vm_health)
      /bin/bash "$DIR/usc_vm_health_dump.sh"
      ;;
    vm_log_tail)
      /bin/bash "$DIR/usc_vm_log_tail.sh"
      ;;
    log_usage)
      /bin/bash "$DIR/usc_log_usage_dump.sh"
      ;;
    docker_log_usage)
      /bin/bash "$DIR/usc_docker_log_usage_dump.sh"
      ;;
    smart_dump)
      /bin/bash "$DIR/usc_smart_dump.sh"
      ;;
    *)
      echo "USC_DISPATCH_REJECTED: nieznana akcja" >&2
      return 1
      ;;
  esac
}

case "$SSH_ORIGINAL_COMMAND" in
  daemon)
    # Tryb dlugotrwalej sesji: akcje z stdin, odpowiedz ramkowana
    # USC_BEGIN <akcja> / USC_END <akcja> - ZAWSZE obydwie linie ramki,
    # nawet przy odrzuceniu akcji, zeby klient nigdy nie zawisil na
    # czekaniu na USC_END.
    while IFS= read -r action; do
      [ -z "$action" ] && continue
      echo "USC_BEGIN $action"
      run_action "$action"
      echo "USC_END $action"
    done
    ;;
  docker_health|syslog_previous|vm_health|vm_log_tail|log_usage|docker_log_usage|smart_dump)
    # Tryb jednorazowy (kompatybilnosc wstecz, np. reczny test po parowaniu)
    run_action "$SSH_ORIGINAL_COMMAND"
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
