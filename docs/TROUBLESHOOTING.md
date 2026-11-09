# Rozwiązywanie problemów

## Autoryzacja (401)

**Dashboard/panel zwraca 401 mimo poprawnego hasła.**
Sprawdź, czy `USC_ADMIN_USER`/`USC_ADMIN_PASSWORD` w `.env` nie mają
końcowej spacji/nowej linii (łatwo wkleić przypadkiem). Zweryfikuj:
`docker exec usc-backend printenv | grep ADMIN`.

**`/ingest/*` zwraca 401 (kolektor nie wysyła danych).**
`USC_INTERNAL_TOKEN` musi być **identyczny** w `.env` backendu i
kolektora — to jedna zmienna współdzielona przez obie usługi w
`docker-compose.yml`. Sprawdź logi kolektora: `BLAD wysylki do backendu` z
kodem 401 oznacza niezgodność tokenu.

**Panel `/settings` nie pokazuje zapisanych wartości / kolektor nie widzi
zmiany z panelu.**
Kolektor odświeża ustawienia co ~60s (`USC_SETTINGS_REFRESH_SECONDS`) —
sprawdź `docker logs usc-collector | grep "Czekam na skonfigurowanie"`
(oznacza że host/klucz unRAID wciąż są puste w bazie). Zweryfikuj wprost:
`docker exec usc-postgres psql -U usc -d usc -c "SELECT * FROM settings;"`.

## SSH

## Wizard parowania (`/wizard`)

**"Nieprawidłowe hasło roota unRAID"** mimo poprawnego hasła.
Sprawdź czy na unRAID nie jest ustawiony `PasswordAuthentication no` w
`/etc/ssh/sshd_config` (rzadkie, ale możliwe po ręcznym hardeningu) — jeśli
tak, wizard nie zadziała, użyj ręcznej procedury z `docs/INSTALL.md`
(klucz, który już masz zaufany, zamiast hasła).

**"Nie znaleziono pluginu"** mimo że plugin jest zainstalowany.
Sprawdź dokładną ścieżkę: `ssh root@<IP> "ls -la /usr/local/emhttp/plugins/unraid-security-center/scripts/"`
— jeśli katalog ma inną nazwę (np. literówka w wersji), wizard nie znajdzie
`usc_dispatch.sh`.

**Wizard działa, ale kolektor dalej nie widzi kluczy.**
Klucze trafiają do wolumenu `usc-keys-data`, montowanego w OBU kontenerach
(`usc-backend` i `usc-collector`). Jeśli dodałeś wolumen "na nowo" bez
`docker compose down -v` najpierw, sprawdź: `docker exec usc-collector ls -la /app/keys`
— powinny tam być te same pliki co w `docker exec usc-backend ls -la /app/keys`.

**Kolektor loguje `Connection refused` do backendu przy starcie.**
Normalne — to wyścig startowy `docker compose up`: kolektor czasem
wystartowuje szybciej niż backend zdąży otworzyć port. Kontenery mają
`restart: unless-stopped`, więc po chwili same się ustabilizują. Sprawdź
`docker logs usc-collector --tail 20` po ~20-30s.

**`usc_smart_dump.sh`/`usc_dispatch.sh` nie odpowiada / timeout.**
1. Zweryfikuj klucz manualnie: `ssh -i collector/keys/usc_smart_key root@<IP_UNRAID>` —
   powinien zwrócić dane i zawiesić się (bo niektóre akcje, np. `tail -F`,
   nie kończą się — to oczekiwane dla klucza syslog, nie dla smart/ops).
2. Sprawdź, czy wpis w `/root/.ssh/authorized_keys` na unRAID ma dokładnie
   taką samą ścieżkę do skryptu jak w `/usr/local/emhttp/plugins/unraid-security-center/scripts/`.
3. Sprawdź uprawnienia: `ls -la /usr/local/emhttp/plugins/unraid-security-center/scripts/` —
   musi być `rwxr-xr-x`, jeśli nie: `chmod +x .../scripts/*.sh`.

**Klucz SSH przyjmuje nieoczekiwaną komendę.**
To nie powinno się zdarzyć — każdy klucz ma `command=` w `authorized_keys`.
Jeśli się zdarza, sprawdź dokładnie linię w `authorized_keys` — literówka w
opcji (`no-pty` zamiast `no-pty,`) może ją unieważnić. Zweryfikuj testem:
`ssh -i <klucz> root@<IP_UNRAID> "whoami"` — wynik musi być wynikiem
wymuszonej komendy, NIE `root`.

## Telegram

**Alerty nie dochodzą, `notified=false` w bazie.**
1. **Najczęstsza przyczyna**: bot nigdy nie dostał pierwszej wiadomości od
   Ciebie. Telegram nie pozwala botowi pisać pierwszy — otwórz czat z botem
   i wyślij cokolwiek (np. `/start`), potem spróbuj ponownie.
2. Sprawdź `USC_TELEGRAM_BOT_TOKEN`/`USC_TELEGRAM_CHAT_ID` w `.env` —
   `docker exec usc-backend printenv | grep TELEGRAM`.
3. Sprawdź logi backendu: `docker logs usc-backend | grep telegram` —
   nieudane wysyłki są logowane z treścią błędu Telegram API.
4. Test manualny: `curl "https://api.telegram.org/bot<TOKEN>/sendMessage" -d "chat_id=<ID>&text=test"`.

## Plugin

**`plugin install` zwraca `not re-installing same plugin`.**
Manager porównuje z już zainstalowaną wersją, nie z nową `.plg`. Zainstaluj
`.txz` wprost: `upgradepkg --install-new <sciezka>.txz`. **Uwaga**: to
pomija hooki z `.plg` (seed konfiguracji, `chmod +x`) — wykonaj je ręcznie
po instalacji (patrz `docs/INSTALL.md` krok 2).

**`xmllint --noout` zwraca błąd parsowania `.plg`.**
Najczęściej: literalny `&` bez escapowania (`2>&1` w `<INLINE>` musi być
`2>&amp;1`), albo literalne `<`/`>` w `<CHANGES>`. Sprawdź dokładnie linię
wskazaną przez błąd.

## Reguły

**Fałszywy alarm na kontenerze jednorazowym (`Exited (0)` mimo autostart).**
Reguła `docker_exited_autostart` reaguje tylko na exit code ≠ 0 — jeśli
mimo to widzisz alert dla kontenera z exit code 0, sprawdź wersję
`backend/app/rules.py` (ten bug był naprawiony — kontenery "run-once i
wyjdź" z exit 0 nie powinny alarmować).

**Ten sam incydent (syslog-previous / log VM) powtarza się co restart kolektora.**
Deduplikacja (hash syslog-previous, last-seen-line per VM) jest w pamięci
procesu — restart kolektora resetuje ją, więc **pierwszy** poll po
restarcie zawsze wysyła wszystko ponownie. To oczekiwane; jeśli duplikaty
się powtarzają także BEZ restartu kolektora, to błąd — zgłoś przez issue.

**Chcę wyczyścić testowe/syntetyczne incydenty z bazy.**
```bash
docker exec usc-postgres psql -U usc -d usc -c "TRUNCATE TABLE incidents;"
```
Zostaw tabele `*_history` — przechowują trend potrzebny regułom
porównującym z poprzednim odczytem.
