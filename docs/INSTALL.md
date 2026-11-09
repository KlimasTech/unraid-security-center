# Instalacja USC — krok po kroku

Zakłada: unRAID 7.2+ (wbudowane GraphQL API), dostęp root po SSH do unRAID,
oraz dowolny host z Dockerem (osobny host polecany — np. OMV, drugi unRAID,
VM) do uruchomienia backendu i kolektora.

## 1. Zainstaluj "unRaid Security Center Plugin" na unRAID

Na **unRAID** (przez SSH jako root), zbuduj pakiet pluginu z tego repo:

```bash
# Skopiuj plugin/source/ na unRAID (np. przez scp z maszyny deweloperskiej)
scp -r plugin/source/usr root@<IP_UNRAID>:/tmp/usc_pkg/

ssh root@<IP_UNRAID>
mkdir -p /boot/config/plugins/unraid-security-center
cd /tmp/usc_pkg && tar cJf /boot/config/plugins/unraid-security-center/unraid-security-center-$(date +%Y.%m.%d).txz usr
md5sum /boot/config/plugins/unraid-security-center/unraid-security-center-*.txz
```

Zaktualizuj `<!ENTITY version>` i `<!ENTITY packageMD5>` w
`plugin/unraid-security-center.plg` (wartość MD5 z powyższej komendy), potem:

```bash
scp plugin/unraid-security-center.plg root@<IP_UNRAID>:/boot/config/plugins/unraid-security-center.plg
ssh root@<IP_UNRAID> "xmllint --noout /boot/config/plugins/unraid-security-center.plg"
ssh root@<IP_UNRAID> "/usr/local/sbin/plugin install /boot/config/plugins/unraid-security-center.plg"
```

Jeśli instalator odmówi (`not re-installing same plugin` — typowe przy
aktualizacji tej samej wersji), użyj bezpośrednio:

```bash
ssh root@<IP_UNRAID> "upgradepkg --install-new /boot/config/plugins/unraid-security-center/unraid-security-center-<WERSJA>.txz"
ssh root@<IP_UNRAID> "chmod +x /usr/local/emhttp/plugins/unraid-security-center/scripts/*.sh"
```

Zweryfikuj:

```bash
ssh root@<IP_UNRAID> "bash /usr/local/emhttp/plugins/unraid-security-center/scripts/usc_smart_dump.sh | head -c 200"
```

## 2. Sparuj USC z pluginem (jedna komenda)

Na **hoście, na którym postawisz kontenery** (nie na unRAID), z działającym
dostępem SSH root do unRAID (hasło albo już zaufany klucz):

```bash
scripts/usc_pair.sh <IP_UNRAID>
```

To zastępuje wszystkie poniższe ręczne kroki naraz:
- generuje 3 ograniczone klucze SSH (`collector/keys/`),
- instaluje je w `/root/.ssh/authorized_keys` na unRAID (`command=`
  wymuszone server-side — zero shella),
- weryfikuje że działają,
- tworzy (albo pobiera, jeśli już istnieje — `unraid-api` jest
  idempotentny) klucz API unRAID z rolą VIEWER,
- zapisuje `USC_UNRAID_HOST`/`USC_UNRAID_API_KEY` do `.env`.

**Bezpiecznie uruchamiać wielokrotnie** — każdy krok sprawdza, czy coś już
istnieje, zanim je utworzy (idempotentny).

Jeśli wolisz zrobić to ręcznie krok po kroku (albo coś nie zadziała), pełna
procedura manualna jest niżej.

<details>
<summary>Ręczna procedura (bez skryptu)</summary>

### Wygeneruj klucze SSH

```bash
mkdir -p collector/keys
ssh-keygen -t ed25519 -f collector/keys/usc_collector_key -N "" -C "usc-collector"
ssh-keygen -t ed25519 -f collector/keys/usc_smart_key     -N "" -C "usc-smart"
ssh-keygen -t ed25519 -f collector/keys/usc_ops_key       -N "" -C "usc-ops"
```

### Podpięcie do `authorized_keys`

Na unRAID, dopisz do `/root/.ssh/authorized_keys` (zastąp `<PUBKEY_*>`
zawartością odpowiedniego `.pub`):

```
command="tail -n0 -F /var/log/syslog",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <PUBKEY_collector>
command="/bin/bash /usr/local/emhttp/plugins/unraid-security-center/scripts/usc_smart_dump.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <PUBKEY_smart>
command="/bin/bash /usr/local/emhttp/plugins/unraid-security-center/scripts/usc_dispatch.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <PUBKEY_ops>
```

Zweryfikuj każdy klucz (powinien zwrócić dane, a próba innej komendy — błąd):

```bash
ssh -i collector/keys/usc_smart_key root@<IP_UNRAID> | head -c 100
ssh -i collector/keys/usc_ops_key root@<IP_UNRAID> "docker_health" | head -3
ssh -i collector/keys/usc_ops_key root@<IP_UNRAID> "cat /etc/shadow"   # musi zostac odrzucone
```

### Klucz API unRAID

```bash
/usr/local/sbin/unraid-api apikey --create --name "USC ReadOnly" --roles VIEWER
```

Zapisz zwrócony klucz — potrzebny w `.env` jako `USC_UNRAID_API_KEY`.

</details>

## 3. (Opcjonalnie) Bot Telegram

1. W Telegramie napisz do `@BotFather` → `/newbot` → zapisz token.
2. **Napisz jako pierwszy** do swojego nowego bota cokolwiek (np. `/start`) —
   Telegram nie pozwala botowi wysłać wiadomości, zanim użytkownik nie
   zainicjował czatu.
3. Zdobądź swój `chat_id`: `curl "https://api.telegram.org/bot<TOKEN>/getUpdates"`
   po wysłaniu wiadomości do bota.

## 4. Konfiguracja i start

```bash
cp .env.example .env
```

Wypełnij `.env`:
- **Wygeneruj losowe sekrety** (nigdy nie wpisuj własnych prostych wartości):
  ```bash
  echo "USC_DB_PASSWORD=$(openssl rand -hex 16)"
  echo "USC_ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')"
  echo "USC_INTERNAL_TOKEN=$(openssl rand -hex 24)"
  ```
  Wklej wyniki do `.env` (`USC_ADMIN_USER` zostaw jako `admin` albo zmień).
- `USC_UNRAID_HOST`, `USC_UNRAID_API_KEY` — jeśli użyłeś `scripts/usc_pair.sh`
  z kroku 2, są już wypełnione. To tylko **jednorazowy seed** przy pierwszym
  starcie; po instalacji edytujesz je w panelu `/settings`.
- `USC_TELEGRAM_BOT_TOKEN`/`USC_TELEGRAM_CHAT_ID` — opcjonalnie, jak wyżej.

```bash
docker compose up -d --build
```

Zaloguj się na `http://<IP_HOSTA_DOCKER>:8420/` loginem/hasłem z
`USC_ADMIN_USER`/`USC_ADMIN_PASSWORD`. Panel `/settings` pozwala edytować
host/klucz unRAID i dane Telegrama bez przebudowy kontenerów (kolektor
odczytuje je z backendu co ~60s).

## 5. Weryfikacja

```bash
curl http://localhost:8420/health
curl http://localhost:8420/incidents
docker logs usc-collector --tail 20
```

Dashboard: `http://<IP_HOSTA_DOCKER>:8420/` (domyślny port 8420, zmień przez
`USC_WEB_PORT` w `.env`).

## Krok manualny alternatywny (bez `docker compose`)

Jeśli wolisz postawić kontenery ręcznie (np. inny orchestrator):

```bash
docker network create usc-net
docker run -d --name usc-postgres --network usc-net \
  -e POSTGRES_USER=usc -e POSTGRES_PASSWORD=<haslo> -e POSTGRES_DB=usc \
  -v usc-postgres-data:/var/lib/postgresql/data postgres:16-alpine
docker build -t usc-backend ./backend
docker run -d --name usc-backend --network usc-net -p 8420:8000 \
  -e USC_DATABASE_URL="postgresql://usc:<haslo>@usc-postgres:5432/usc" \
  usc-backend
docker build -t usc-collector ./collector
docker run -d --name usc-collector --network usc-net \
  -e USC_UNRAID_HOST=<IP_UNRAID> -e USC_UNRAID_URL="http://<IP_UNRAID>/graphql" \
  -e USC_UNRAID_API_KEY=<klucz> -e USC_BACKEND_URL="http://usc-backend:8000" \
  usc-collector
```
