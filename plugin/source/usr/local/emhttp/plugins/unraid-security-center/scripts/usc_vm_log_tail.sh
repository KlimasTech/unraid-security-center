#!/bin/bash
# unRaid Security Center Plugin - ostatnie linie logow QEMU per VM.
#
# Format wyjscia: "<nazwa_vm>\t<linia_logu>" - plain text (nie JSON), zeby
# uniknac problemow z escapowaniem cytatow/backslashy w surowych liniach
# qemu (np. linie komend startowych VM). Backend dzieli po pierwszym
# znaku tabulacji i skanuje kazda linie pod znane markery bledow.
for name in $(virsh list --all --name 2>/dev/null); do
  [ -z "$name" ] && continue
  logfile="/var/log/libvirt/qemu/${name}.log"
  [ -f "$logfile" ] || continue
  tail -n 100 "$logfile" | while IFS= read -r line; do
    printf '%s\t%s\n' "$name" "$line"
  done
done
