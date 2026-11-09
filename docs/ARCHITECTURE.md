# Architektura USC

## Przepływ danych

```
unRAID
  ├── GraphQL API (/graphql, x-api-key)       -> array, disks, shares, docker, parity
  └── unRaid Security Center Plugin (SSH)
        ├── usc_smart_dump.sh    -> SMART (ATA + NVMe) przez smartctl
        ├── usc_dispatch.sh      -> whitelist-dyspozytor:
        │     ├── docker_health    -> docker inspect (RestartCount/OOMKilled/Health)
        │     ├── syslog_previous  -> ostatnie ~300KB /boot/logs/syslog-previous
        │     ├── vm_health        -> virsh domstate per VM
        │     └── vm_log_tail      -> ostatnie 100 linii logu qemu per VM
        └── tail -F /var/log/syslog (osobny, ograniczony klucz)
              │
              ▼
        Collector (Python, kontener Docker)
          - 1 petla GraphQL (60s) + 5 niezaleznych watkow SSH
          - normalizuje dane, dedupikuje (hash/last-seen-line), POSTuje do backendu
              │
              ▼
        Backend (FastAPI + PostgreSQL)
          - Warstwa 1: reguly deterministyczne (per-typ danych)
          - zapisuje Incident, wysyla alert Telegram (plain text)
          - REST API (/incidents, /ingest/*) + dashboard HTML (desktop+mobile)
```

## Dlaczego trzy osobne klucze SSH, nie jeden

Każdy klucz jest **wymuszony server-side** (`command=` w `authorized_keys` na
unRAID) na jedną, konkretną, nieszkodliwą akcję odczytu:

- `usc_collector_key` -> wylacznie `tail -n0 -F /var/log/syslog`
- `usc_smart_key` -> wylacznie `usc_smart_dump.sh`
- `usc_ops_key` -> wylacznie `usc_dispatch.sh` (ktory sam, wewnetrznie,
  sprawdza biala liste akcji z `$SSH_ORIGINAL_COMMAND`)

Nawet gdyby którykolwiek plik prywatnego klucza wyciekł, atakujący nie
wykona nim NICZEGO poza odczytem telemetrii — serwer SSH ignoruje każdą
komendę klienta i zawsze wykonuje tylko wymuszoną. Zweryfikowane testem:
próba `ssh -i <klucz> root@unraid "rm -rf /"` kończy się wykonaniem
wymuszonej komendy (odczyt), nie usunięciem niczego.

Trzeci klucz (`ops`) multipleksuje kilka akcji przez jeden dyspozytor
(whitelist w bashu) zamiast mnożyć liczbę kluczy w nieskończoność przy
każdej nowej funkcji — rozsądny kompromis między granularnością a
utrzymywalnością.

## Dlaczego plugin, nie gołe skrypty na flashu

Pierwsza iteracja trzymała skrypty bezpośrednio na `/boot/config/`. Zostało
to zastąpione prawdziwym pakietem pluginu (`.plg` + `.txz`), zainstalowanym
przez natywny instalator unRAID (`/usr/local/sbin/plugin install`) — dzięki
temu: pliki żyją w standardowej lokalizacji
(`/usr/local/emhttp/plugins/unraid-security-center/`), plugin jest widoczny
na liście Pluginów (nazwa z pierwszej linii `README.md`), ma wersjonowany
changelog, i przetrwa reboot przez ten sam mechanizm co każdy inny plugin
CA (reinstalacja z `/boot/config/plugins/*.plg` przy starcie).

## Dlaczego GraphQL nie wystarcza (powód istnienia pluginu)

GraphQL API unRAID 7.x **nie udostępnia**:
- surowych atrybutów SMART (5/187/188/197/198/199) — tylko gotowe flagi
  `warning`/`critical`/`numErrors` wyliczone przez sam unRAID,
- `RestartCount`/`OOMKilled`/`Health.Status` kontenerów Docker — tylko
  `state`/`status`/`autoStart`,
- stanu maszyn wirtualnych libvirt/QEMU w ogóle,
- logów (`syslog-previous`, logi qemu).

Stąd plugin + SSH jako drugi, uzupełniający kanał danych.

## Warstwa 1: reguły deterministyczne

| Reguła | Źródło | Severity | Logika |
|---|---|---|---|
| `disk_critical_flag` / `disk_warning_flag` | GraphQL | CRITICAL/WARNING | flaga unRAID per dysk |
| `disk_errors_increasing` | GraphQL (trend) | WARNING | numErrors rośnie między odczytami |
| `smart_197_pending_sector` | plugin (smartctl) | CRITICAL | SMART 197 > 0 |
| `smart_199_cable_suspect` | plugin (trend) | WARNING | 199 rośnie, 197/198=0 → kabel, nie talerz |
| `nvme_critical_warning` / `nvme_media_errors` | plugin (smartctl) | CRITICAL/WARNING | pola NVMe health log |
| `docker_restarting` / `docker_exited_autostart` | GraphQL | ERROR | pętla restartu / exit≠0 mimo autostart |
| `docker_oom_killed` | plugin (docker inspect) | ERROR | OOMKilled=true |
| `docker_restart_spike` | plugin (trend) | ERROR | RestartCount +≥3 od ostatniego odczytu |
| `docker_unhealthy` | plugin (docker inspect) | WARNING | wlasny healthcheck = unhealthy |
| `parity_errors` | GraphQL | CRITICAL | Parity Check errors > 0 |
| `array_not_started` | GraphQL | ERROR | array state ≠ STARTED |
| `vm_paused_io_error` | plugin (virsh, trend) | CRITICAL | running→paused (auto-pauza QEMU przy błędzie I/O) |
| `vm_unexpected_stop` | plugin (virsh, trend) | WARNING | running→shut off/crashed |
| `qemu_error`/`vm_vfio_dma_failed`/... | plugin (logi qemu) | ERROR/WARNING | markery bledow w logu VM |
| `kernel_panic_marker` | syslog (live + previous) | CRITICAL | `Call Trace`/`kernel panic`/`BUG:`/`Oops:` |
| `disk_space_low` | GraphQL | WARNING | zajętość share/dysku ≥ próg |

Wszystkie reguły są **read-only w efekcie** — wykrywają i opisują problem,
nigdy nie wykonują żadnej akcji na macierzy/dyskach.

## Dlaczego alerty Telegram są plain text, nie Markdown

Pierwsza wersja używała `parse_mode=Markdown`. Telegram API zwraca błąd
`can't parse entities` dla nieescapowanych znaków specjalnych (`_`, `*`,
`` ` ``, `[`) w dynamicznej treści — a nazwy kontenerów, linie syslogu i
nazwy urządzeń regularnie je zawierają. Błąd był **cichy** (funkcja po
prostu zwracała `False`, bez logowania) — realne alerty gubiły się bez
żadnego śladu. Naprawione przez usunięcie `parse_mode` całkowicie (plain
text) + dodanie logowania każdej nieudanej wysyłki. Niezawodność dostawy
> ładne formatowanie.

## Deduplikacja — dlaczego jest krytyczna

Dwa źródła wymagają jej wprost, inaczej zalewają incydentami przy KAŻDYM
pollu:
- **syslog-previous**: ten sam plik nie zmienia się między restartami
  kolektora — kolektor liczy hash treści i wysyła ją ponownie tylko gdy
  się zmieniła (czyli po nowym restarcie unRAID).
- **logi qemu per VM**: `tail -n 100` zwraca też stare, już widziane linie
  — kolektor pamięta ostatnią znaną linię per VM i przepuszcza do backendu
  tylko to, co jest PO niej.

## Roadmapa (Faza 2 / Faza 3)

- **Faza 2 — korelacja wielomodułowa**: łączenie odseparowanych faktów w
  spójną diagnozę (np. `UDMA CRC` + `SATA reset` + rosnące 199 = wada toru
  transmisyjnego, nie dysku; `Docker restart` + `OOM` + skok RAM = wyciek
  pamięci kontenera, nie błąd aplikacji).
- **Faza 3 — AI jako doradca**: streszczanie logów, hierarchizacja hipotez,
  propozycje bezpiecznych komend diagnostycznych — **bez żadnych uprawnień
  wykonawczych** (zero dostępu do operacji na macierzy/dyskach/VM).
