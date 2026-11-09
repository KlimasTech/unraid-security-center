#!/bin/bash
# unRaid Security Center Plugin - zrzut SMART wszystkich wykrytych dyskow
# (ATA + NVMe) w formacie JSON.
#
# Wywolywane zdalnie przez ograniczony klucz SSH kolektora USC - ten skrypt
# jest JEDYNA komenda jaka ten klucz moze wykonac (wymuszone przez
# command= w authorized_keys na unRAID), tylko odczyt, zero akcji
# destrukcyjnych na dyskach/macierzy.
echo "{"
first=1
for dev in $(smartctl --scan 2>/dev/null | awk '{print $1}'); do
  json=$(smartctl -a -j "$dev" 2>/dev/null)
  [ -z "$json" ] && continue
  if [ $first -eq 0 ]; then echo ","; fi
  first=0
  printf '"%s": %s' "$dev" "$json"
done
echo "}"
