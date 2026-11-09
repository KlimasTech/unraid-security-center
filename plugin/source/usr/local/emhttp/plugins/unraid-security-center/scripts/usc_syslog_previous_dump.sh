#!/bin/bash
# unRaid Security Center Plugin - zrzut ostatniej czesci syslog-previous.
#
# /boot/logs/syslog-previous jest tworzony przez unRAID przy kazdym
# (czystym) zamknieciu/restarcie - zawiera logi "sprzed" ostatniego bootu,
# wazne przy diagnozie crashu. Oddajemy ostatnie ~300KB (kernel panic
# zazwyczaj jest na koncu logu, przed restartem) jako plain text, linia po
# linii - backend sam przepuszcza kazda linie przez reguly (Call Trace,
# kernel panic, BUG:, Oops:).
FILE=/boot/logs/syslog-previous
if [ -f "$FILE" ]; then
  tail -c 300000 "$FILE"
else
  echo "USC_NO_SYSLOG_PREVIOUS"
fi
