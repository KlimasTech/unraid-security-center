# unRaid Security Center (USC)

Zintegrowany system monitorowania stanu zdrowia, bezpieczeństwa i incydentów dla
serwerów Unraid OS. Łączy w czasie rzeczywistym telemetrię z GraphQL API unRAID,
granularne atrybuty SMART (ATA + NVMe), zdrowie kontenerów Docker, stan maszyn
wirtualnych (libvirt/QEMU) oraz logi systemowe (w tym crash-persistent
`syslog-previous`) — i uruchamia nad tym silnik reguł deterministycznych, który
wykrywa realne problemy (degradujący dysk, kontener w crash-loop, błąd I/O VM,
kernel panic) i alertuje przez Telegram. Zasada naczelna: **pełna autonomia w
analizie i rekomendacjach, zero automatycznych akcji destrukcyjnych** na
dyskach/macierzy — USC tylko obserwuje i ostrzega, nigdy nie wykonuje napraw
samodzielnie.

Architektura ma dwie połówki:
- **unRaid Security Center Plugin** — lekki plugin instalowany na samym
  unRAID, udostępniający przez ograniczone, server-side wymuszone klucze SSH
  (`command=` w `authorized_keys`, zero shella) odczyt telemetrii niedostępnej
  przez GraphQL: SMART, `docker inspect`, stan VM, `syslog-previous`.
- **Backend + Collector (Docker)** — dwa kontenery stawiane GDZIEKOLWIEK
  (osobny host Docker, np. OMV) łączące się do unRAID przez GraphQL i SSH,
  normalizujące dane, odpalające reguły i wystawiające dashboard + REST API.

## Szybki start

```bash
git clone https://github.com/KlimasTech/unraid-security-center.git
cd unraid-security-center
cp .env.example .env
# wypelnij sekrety panelu (USC_DB_PASSWORD, USC_ADMIN_USER/PASSWORD,
# USC_INTERNAL_TOKEN) - patrz docs/INSTALL.md
docker compose up -d --build
```

Potem **zaloguj się do panelu** (`http://<IP_HOSTA_DOCKER>:8420/`) i otwórz
**"Połącz z unRAID"** (`/wizard`) — wpisz IP unRAID i hasło roota, backend
sam wygeneruje klucze SSH i klucz API. **Zero komend SSH** po Twojej
stronie. (Wymaga wcześniej zainstalowanego pluginu — krok 1 w INSTALL.md.)
Alternatywa z terminala: `scripts/usc_pair.sh <IP_UNRAID>`.

Plugin na samym unRAID instaluje się osobno — pełna procedura w
[`docs/INSTALL.md`](docs/INSTALL.md).

## Dokumentacja

| Plik | Zawartość |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | Pełna instalacja krok po kroku: plugin na unRAID, klucze SSH, docker compose, Telegram |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Architektura, przepływ danych, reguły detekcji, decyzje projektowe i ich powody |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Typowe problemy i jak je zdiagnozować |

## Co dokładnie monitoruje

| Źródło | Co zbiera | Przez co |
|---|---|---|
| Array/dyski/shares | stan macierzy, flagi warning/critical, numErrors, parity errors, zajętość | GraphQL API unRAID |
| SMART (ATA + NVMe) | atrybuty 5/187/188/197/198/199, critical_warning, media_errors, temperatura | SSH + `smartctl` (plugin) |
| Docker | state/status/autoStart (GraphQL) + RestartCount/OOMKilled/Health (plugin) | GraphQL + SSH + `docker inspect` |
| VM (libvirt/QEMU) | stan domeny, przejścia running→paused (błąd I/O), markery błędów w logu qemu | SSH + `virsh` + logi qemu |
| Logi systemowe | `tail -F /var/log/syslog` na żywo + `syslog-previous` po restarcie (crash-persistent) | SSH, dwa niezależne strumienie |
| RAM hosta | MemTotal/MemAvailable (`free -m`), co 300s | SSH + dyspozytor (plugin) |
| Korelacja (Faza 2) | rosnący SMART 199 + resety SATA w syslogu = wada toru transmisyjnego (jeden alert z dowodem); OOM kontenera + zniknięcie RAM hosta = wyciek pamięci | backend, nad historią z modułów powyżej |
| Alerty | Telegram (plain text, bez Markdown — patrz ARCHITECTURE.md) | Bot API |

## Konfiguracja

Dwa poziomy konfiguracji — **nie wszystko jest w `.env`**:

| Zmienna `.env` | Wymagana | Kiedy używana |
|---|---|---|
| `USC_DB_PASSWORD` | tak, **losowa** | hasło PostgreSQL — wygeneruj `openssl rand -hex 16` |
| `USC_ADMIN_USER` / `USC_ADMIN_PASSWORD` | tak, **losowe** | login do panelu (dashboard + `/settings`), HTTP Basic Auth |
| `USC_INTERNAL_TOKEN` | tak, losowy | wspólny token backend↔collector, chroni `/ingest/*` (port backendu jest wystawiony na hosta) |
| `USC_UNRAID_HOST` / `USC_UNRAID_API_KEY` | nie (seed) | **tylko pierwszy start** — potem edytuj w panelu `/settings` |
| `USC_TELEGRAM_BOT_TOKEN` / `USC_TELEGRAM_CHAT_ID` | nie (seed) | jak wyżej — panel `/settings` |
| `USC_WEB_PORT` | nie (domyślnie 8420) | port dashboardu — deploy-time, wymaga przebudowy kontenera |

Host/klucz unRAID i dane Telegrama **żyją w bazie**, edytowalne z panelu bez
restartu kontenerów — kolektor odpytuje backend o nie co ~60s
(`GET /internal/settings`, chronione `USC_INTERNAL_TOKEN`).

## Rozwiązywanie problemów

| Symptom | Zobacz |
|---|---|
| Kolektor nie łączy się z unRAID | [TROUBLESHOOTING.md § SSH](docs/TROUBLESHOOTING.md#ssh) |
| Alerty Telegram nie dochodzą | [TROUBLESHOOTING.md § Telegram](docs/TROUBLESHOOTING.md#telegram) |
| Plugin nie instaluje się / `not re-installing` | [TROUBLESHOOTING.md § Plugin](docs/TROUBLESHOOTING.md#plugin) |
| Fałszywe alarmy | [TROUBLESHOOTING.md § Reguły](docs/TROUBLESHOOTING.md#reguly) |

## Roadmapa

Faza 1 (fundament: GraphQL, SMART, Docker, VM, syslog, Telegram) — ✅ zrobione.
Faza 2 (korelacja wielomodułowa, trendy) — ✅ zrobione: korelacja SMART 199 +
resety SATA, OOM + RAM hosta, VM paused + błędy qemu; trendy SMART/RAM
(sparkline) na dashboardzie; monitoring RAM.
Faza 3 (AI-doradca) — ✅ infrastruktura gotowa: „API Agenta AI" w /settings
(dowolny endpoint OpenAI-compatible), przycisk „Diagnoza AI" przy każdym
incydencie (hipotezy z dowodami, whitelistowane komendy read-only, ostrzeżenia
„czego nie robić"), „Raport tygodnia" z opcją wysyłki na Telegram. Doradca
NIGDY nic nie wykonuje — zero uprawnień wykonawczych, wyłącznie analiza.

## Licencja

MIT — patrz [`LICENSE`](LICENSE).
