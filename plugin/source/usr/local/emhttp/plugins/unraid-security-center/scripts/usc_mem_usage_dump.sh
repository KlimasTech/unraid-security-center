#!/bin/bash
# unRaid Security Center Plugin - zajetosc RAM hosta (free -m) jako JSON
# dla kolektora USC. Faza 2: poswiadczenie dla korelacji OOM kontenera
# (spadek dostepnego RAM w pomiarACH poprzednich = realny brak pamieci),
# plus klasyczny alarm wysokosci zajetosci.
#
# Uwaga: wysokie zuzycie RAM na unRAID jest normalne (page cache), decyduje
# dostepny RAM (MemAvailable), nie 'used'.
json_escape() {
  # brak zmiennych do escapowania - cale to co robimy to liczby; funkcja
  # pozostawiona dla spojnosci z pozostalymi skryptami dump
  :
}

total_mb=$(free -m | awk '/^Mem:/ {print $2}')
avail_mb=$(free -m | awk '/^Mem:/ {print $7}')

if [ -z "$total_mb" ] || [ -z "$avail_mb" ] || [ "$total_mb" -le 0 ]; then
  echo '{"error": "free -m zwrocil puste/dziwne dane"}' >&2
  exit 1
fi

used_pct=$(( (total_mb - avail_mb) * 100 / total_mb ))

printf '{"total_mb": %s, "available_mb": %s, "used_pct": %s}\n' \
  "$total_mb" "$avail_mb" "$used_pct"
