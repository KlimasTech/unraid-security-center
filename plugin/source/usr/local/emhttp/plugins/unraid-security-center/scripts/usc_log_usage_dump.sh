#!/bin/bash
# unRaid Security Center Plugin - zrzut zajetosci /var/log (tmpfs, zwykle
# 128MB na unRAID - zapelnienie zatrzymuje logowanie i moze destabilizowac
# uslugi). Wywolywane WYLACZNIE przez dyspozytor (usc_dispatch.sh, akcja
# "log_usage") przez ograniczony klucz SSH "ops".
set -euo pipefail

df -B1 /var/log --output=pcent,used,size | tail -1 | awk '{
  gsub("%", "", $1)
  printf "{\"used_pct\": %s, \"used_bytes\": %s, \"total_bytes\": %s}\n", $1, $2, $3
}'
