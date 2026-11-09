#!/bin/bash
# unRaid Security Center Plugin - stan maszyn wirtualnych (libvirt/QEMU).
# Jeden JSON na linie (JSONL): nazwa + aktualny stan domeny.
for name in $(virsh list --all --name 2>/dev/null); do
  [ -z "$name" ] && continue
  state=$(virsh domstate "$name" 2>/dev/null | tr -d '\n')
  printf '{"name":"%s","state":"%s"}\n' "$name" "$state"
done
