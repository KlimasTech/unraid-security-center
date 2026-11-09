"""USC collector - odpytuje GraphQL API unRAID i wysyla znormalizowane dane
do backendu USC (/ingest/*). Dziala jako petla z interwalem POLL_SECONDS,
plus 5 niezaleznych watkow SSH (syslog tail, SMART, docker health,
syslog-previous, VM).

Host/klucz unRAID NIE sa brane ze zmiennych env tego kontenera - sa
ustawiane w panelu USC (zapisane w bazie) i pobierane stad okresowo przez
GET /internal/settings (chronione wspoldzielonym tokenem X-USC-Token), zeby
zmiana w panelu dzialala bez przebudowy/restartu kolektora.

Kazde polaczenie SSH idzie przez jeden z 3 kluczy ograniczonych server-side
(command= w authorized_keys na unRAID) - nawet w razie wycieku pliku klucza
nie da sie nim zrobic nic poza wymuszona akcja odczytu.
"""
import os
import sys
import time
import json
import threading
import subprocess
import urllib.request
import urllib.error

BACKEND_URL = os.environ.get("USC_BACKEND_URL", "http://usc-backend:8000")
INTERNAL_TOKEN = os.environ.get("USC_INTERNAL_TOKEN", "")
POLL_SECONDS = int(os.environ.get("USC_POLL_SECONDS", "60"))
SETTINGS_REFRESH_SECONDS = int(os.environ.get("USC_SETTINGS_REFRESH_SECONDS", "60"))

SSH_KEY_PATH = os.environ.get("USC_SSH_KEY_PATH", "/app/keys/usc_collector_key")
SYSLOG_ENABLED = os.environ.get("USC_SYSLOG_ENABLED", "1") == "1"
SYSLOG_BATCH_SECONDS = int(os.environ.get("USC_SYSLOG_BATCH_SECONDS", "10"))

SMART_KEY_PATH = os.environ.get("USC_SMART_KEY_PATH", "/app/keys/usc_smart_key")
SMART_ENABLED = os.environ.get("USC_SMART_ENABLED", "1") == "1"
SMART_POLL_SECONDS = int(os.environ.get("USC_SMART_POLL_SECONDS", "600"))

OPS_KEY_PATH = os.environ.get("USC_OPS_KEY_PATH", "/app/keys/usc_ops_key")
DOCKER_HEALTH_ENABLED = os.environ.get("USC_DOCKER_HEALTH_ENABLED", "1") == "1"
DOCKER_HEALTH_POLL_SECONDS = int(os.environ.get("USC_DOCKER_HEALTH_POLL_SECONDS", "300"))

_SSH_CM_DIR = "/tmp/ssh-cm"


def _ssh_multiplex_opts(key_tag: str) -> list[str]:
    """Opcje SSH ControlMaster/ControlPersist - wielokrotne wywolania przez
    TEN SAM klucz w krotkim oknie czasu wspoldziela JEDNO polaczenie TCP
    zamiast otwierac nowe za kazdym razem. Bez tego kazdy pojedynczy odczyt
    (SMART co 600s, dyspozytor co 180-900s w 3 niezaleznych petlach) generuje
    ~11 linii logu sshd na unRAID (Accepted publickey/session opened/closed/
    disconnect) - przy czestych odpytaniach to realny spam w syslogu serwera.
    ControlPath MUSI zawierac key_tag (nie tylko %r@%h:%p) zeby klucze
    'smart' i 'ops' (ten sam host/user, inny plik tozsamosci) nigdy nie
    dzielily tego samego gniazda - inaczej drugi klucz moglby po cichu
    uzyc juz otwartego polaczenia pierwszego."""
    os.makedirs(_SSH_CM_DIR, exist_ok=True)
    return [
        "-o", "StrictHostKeyChecking=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=15",
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=900",
        "-o", f"ControlPath={_SSH_CM_DIR}/{key_tag}-%r@%h:%p",
    ]


SYSLOG_PREVIOUS_ENABLED = os.environ.get("USC_SYSLOG_PREVIOUS_ENABLED", "1") == "1"
SYSLOG_PREVIOUS_POLL_SECONDS = int(os.environ.get("USC_SYSLOG_PREVIOUS_POLL_SECONDS", "900"))
VM_ENABLED = os.environ.get("USC_VM_ENABLED", "1") == "1"
VM_POLL_SECONDS = int(os.environ.get("USC_VM_POLL_SECONDS", "180"))

QUERY = """
{
  array {
    state
    parityCheckStatus { errors progress running }
    disks {
      device name status warning critical numErrors temp
    }
    caches {
      device name status warning critical numErrors temp
    }
  }
  shares { name free used size }
  docker {
    containers { names state status autoStart }
  }
  vms { domain { name state } }
}
"""

# Stan ustawien pobieranych z panelu (odswiezany okresowo) - czytany przez
# wszystkie watki. Prosty dict + GIL wystarcza dla naszych odczytow/zapisow
# pojedynczych stringow, nie potrzeba locka.
_settings = {"unraid_host": None, "unraid_api_key": None}


def log(msg: str):
    print(f"[usc-collector] {msg}", flush=True)


def backend_headers() -> dict:
    return {"Content-Type": "application/json", "X-USC-Token": INTERNAL_TOKEN}


def refresh_settings() -> bool:
    """Pobiera unraid_host/unraid_api_key z panelu (baza przez backend).
    Zwraca True gdy mamy kompletne ustawienia do pracy."""
    req = urllib.request.Request(
        f"{BACKEND_URL}/internal/settings", headers=backend_headers(), method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            _settings["unraid_host"] = data.get("unraid_host")
            _settings["unraid_api_key"] = data.get("unraid_api_key")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log(f"BLAD odswiezania ustawien z backendu: {e}")
    return bool(_settings["unraid_host"] and _settings["unraid_api_key"])


def graphql_query() -> dict | None:
    host = _settings["unraid_host"]
    api_key = _settings["unraid_api_key"]
    if not host or not api_key:
        return None
    body = json.dumps({"query": QUERY}).encode()
    req = urllib.request.Request(
        f"http://{host}/graphql", data=body,
        headers={"Content-Type": "application/json", "x-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log(f"BLAD zapytania GraphQL do unRAID: {e}")
        return None


def post_backend(path: str, payload: dict) -> None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{BACKEND_URL}{path}", data=body,
        headers=backend_headers(), method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read())
            n = resp.get("incidents_found", 0)
            if n:
                log(f"{path}: {n} nowych incydentów")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log(f"BLAD wysylki do backendu {path}: {e}")


def run_once():
    data = graphql_query()
    if not data or "data" not in data:
        log(f"Brak danych z unRAID GraphQL (host={_settings['unraid_host']}, odpowiedz: {data})")
        return
    d = data["data"]

    array = d.get("array") or {}
    disks = (array.get("disks") or []) + (array.get("caches") or [])
    disk_payload = {
        "disks": [
            {
                "device": disk.get("device") or disk.get("name"),
                "status": disk.get("status"),
                "warning": disk.get("warning"),
                "critical": disk.get("critical"),
                "num_errors": disk.get("numErrors"),
                "temperature": disk.get("temp"),
            }
            for disk in disks
            if disk
        ]
    }
    post_backend("/ingest/disks", disk_payload)

    parity = array.get("parityCheckStatus") or {}
    array_payload = {
        "array_state": array.get("state"),
        "parity_errors": parity.get("errors"),
    }
    post_backend("/ingest/array", array_payload)

    shares = d.get("shares") or []
    share_payload = {
        "shares": [
            {
                "name": s.get("name"),
                "used_pct": (
                    (float(s["used"]) / float(s["size"]) * 100.0)
                    if s.get("size") and float(s["size"]) > 0 and s.get("used") is not None
                    else None
                ),
                "free_gb": (float(s["free"]) / (1024 * 1024)) if s.get("free") is not None else None,
            }
            for s in shares
            if s
        ]
    }
    post_backend("/ingest/shares", share_payload)

    docker = d.get("docker") or {}
    containers = docker.get("containers") or []
    docker_payload = {
        "containers": [
            {
                "name": (c.get("names") or [None])[0],
                "state": c.get("state"),
                "status": c.get("status"),
                "auto_start": c.get("autoStart"),
            }
            for c in containers
            if c
        ]
    }
    post_backend("/ingest/docker", docker_payload)

    log(
        f"cykl OK: {len(disks)} dyskow, {len(shares)} shares, "
        f"{len(containers)} kontenerow, array={array.get('state')}"
    )


def post_syslog_lines(lines: list[str]) -> None:
    if not lines:
        return
    post_backend("/ingest/syslog", {"lines": lines})


def syslog_tail_loop():
    """Petla w osobnym watku: utrzymuje SSH tail -F na syslogu unRAID,
    batchuje linie co SYSLOG_BATCH_SECONDS i wysyla do backendu. Przy
    zerwaniu polaczenia reconnectuje po krotkiej przerwie.
    """
    log(f"Syslog tailer: start, klucz={SSH_KEY_PATH}")
    while True:
        host = _settings["unraid_host"]
        if not host:
            time.sleep(10)
            continue
        try:
            proc = subprocess.Popen(
                [
                    "ssh", "-i", SSH_KEY_PATH,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "IdentitiesOnly=yes",
                    "-o", "ServerAliveInterval=30",
                    "-o", "ServerAliveCountMax=3",
                    f"root@{host}",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            )
            buffer: list[str] = []
            last_flush = time.time()
            while True:
                line = proc.stdout.readline()
                if line == "" and proc.poll() is not None:
                    break
                if line:
                    buffer.append(line.rstrip("\n"))
                if buffer and (time.time() - last_flush >= SYSLOG_BATCH_SECONDS):
                    post_syslog_lines(buffer)
                    buffer = []
                    last_flush = time.time()
            stderr_out = proc.stderr.read()
            if stderr_out:
                log(f"Syslog tailer SSH zakonczyl sie: {stderr_out.strip()[:300]}")
            if buffer:
                post_syslog_lines(buffer)
        except Exception as e:  # noqa: BLE001 - watek nie moze umrzec na jednym bledzie
            log(f"Syslog tailer BLAD: {e!r}")
        log("Syslog tailer: polaczenie zerwane, ponawiam za 15s")
        time.sleep(15)


def fetch_smart_dump() -> dict | None:
    """Pobiera JSON SMART wszystkich dyskow przez ograniczony klucz SSH
    (server-side wymusza dokladnie jedna komende: usc_smart_dump.sh)."""
    host = _settings["unraid_host"]
    if not host:
        return None
    try:
        result = subprocess.run(
            ["ssh", "-i", SMART_KEY_PATH] + _ssh_multiplex_opts("smart") + [f"root@{host}"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            log(f"SMART dump SSH zwrocil kod {result.returncode}: {result.stderr.strip()[:300]}")
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        log(f"SMART dump BLAD: {e!r}")
        return None


def _ata_attr(table: list[dict], attr_id: int) -> int | None:
    for a in table:
        if a.get("id") == attr_id:
            raw = a.get("raw", {}).get("value")
            return int(raw) if raw is not None else None
    return None


def parse_smart_dump(dump: dict) -> list[dict]:
    disks = []
    for device, info in dump.items():
        if not isinstance(info, dict):
            continue
        model = info.get("model_name") or info.get("model_family") or info.get("device", {}).get("type")
        entry = {"device": device, "model": model}
        if "nvme_smart_health_information_log" in info:
            h = info["nvme_smart_health_information_log"]
            entry["nvme_media_errors"] = h.get("media_errors")
            entry["nvme_critical_warning"] = h.get("critical_warning")
            entry["temperature"] = h.get("temperature") or (info.get("temperature") or {}).get("current")
        else:
            table = (info.get("ata_smart_attributes") or {}).get("table", [])
            entry["attr_5"] = _ata_attr(table, 5)
            entry["attr_187"] = _ata_attr(table, 187)
            entry["attr_188"] = _ata_attr(table, 188)
            entry["attr_197"] = _ata_attr(table, 197)
            entry["attr_198"] = _ata_attr(table, 198)
            entry["attr_199"] = _ata_attr(table, 199)
            entry["temperature"] = (info.get("temperature") or {}).get("current")
        disks.append(entry)
    return disks


def smart_poll_loop():
    """Petla w osobnym watku: co SMART_POLL_SECONDS pobiera zrzut SMART
    wszystkich dyskow przez ograniczony klucz SSH i wysyla do backendu.
    """
    log(f"SMART poller: start, poll co {SMART_POLL_SECONDS}s")
    while True:
        try:
            dump = fetch_smart_dump()
            if dump:
                disks = parse_smart_dump(dump)
                post_backend("/ingest/smart", {"disks": disks})
                log(f"SMART poller: cykl OK, {len(disks)} dyskow")
        except Exception as e:  # noqa: BLE001 - watek nie moze umrzec na jednym bledzie
            log(f"SMART poller BLAD: {e!r}")
        time.sleep(SMART_POLL_SECONDS)


def run_ops_dispatch(action: str) -> str | None:
    """Wywoluje dyspozytor USC (usc_dispatch.sh) przez klucz 'ops' - klient
    wysyla `action` jako SSH command, serwer i tak zawsze wykonuje tylko
    dyspozytor (forced command), ktory sam sprawdza biala liste akcji."""
    host = _settings["unraid_host"]
    if not host:
        return None
    try:
        result = subprocess.run(
            ["ssh", "-i", OPS_KEY_PATH] + _ssh_multiplex_opts("ops") + [f"root@{host}", action],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            log(f"ops dispatch '{action}' zwrocil kod {result.returncode}: {result.stderr.strip()[:300]}")
            return None
        return result.stdout
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"ops dispatch '{action}' BLAD: {e!r}")
        return None


def docker_health_poll_loop():
    """Petla w osobnym watku: co DOCKER_HEALTH_POLL_SECONDS pobiera
    RestartCount/OOMKilled/Health z 'docker inspect' (plugin USC - GraphQL
    nie udostepnia tych pol) i wysyla do backendu."""
    log(f"Docker health poller: start, poll co {DOCKER_HEALTH_POLL_SECONDS}s")
    while True:
        try:
            raw = run_ops_dispatch("docker_health")
            if raw:
                containers = []
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                post_backend("/ingest/docker_health", {"containers": containers})
                log(f"Docker health poller: cykl OK, {len(containers)} kontenerow")
        except Exception as e:  # noqa: BLE001
            log(f"Docker health poller BLAD: {e!r}")
        time.sleep(DOCKER_HEALTH_POLL_SECONDS)


_last_syslog_previous_hash: str | None = None
_SYSLOG_PREVIOUS_STATE_FILE = "/app/keys/.state_syslog_previous_hash"


def _load_syslog_previous_hash() -> str | None:
    try:
        with open(_SYSLOG_PREVIOUS_STATE_FILE) as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def _save_syslog_previous_hash(h: str) -> None:
    try:
        os.makedirs(os.path.dirname(_SYSLOG_PREVIOUS_STATE_FILE), exist_ok=True)
        with open(_SYSLOG_PREVIOUS_STATE_FILE, "w") as f:
            f.write(h)
    except OSError as e:
        log(f"BLAD zapisu stanu dedup syslog-previous: {e!r}")


def syslog_previous_poll_loop():
    """Petla w osobnym watku: co SYSLOG_PREVIOUS_POLL_SECONDS sprawdza
    /boot/logs/syslog-previous (tworzony przy kazdym restarcie unRAID) -
    wysyla do backendu TYLKO gdy zawartosc sie zmienila (czyli po nowym
    restarcie), zeby nie generowac powtarzajacych sie incydentow za ten
    sam, juz przeanalizowany log. Hash zapisywany NA DYSKU (wolumen
    usc-keys-data) - bez tego kazdy restart kontenera kolektora resetowalby
    pamiec i powodowal ponowne zglaszanie tego samego, juz znanego zdarzenia
    jako nowego incydentu."""
    global _last_syslog_previous_hash
    import hashlib
    _last_syslog_previous_hash = _load_syslog_previous_hash()
    log(f"Syslog-previous poller: start, poll co {SYSLOG_PREVIOUS_POLL_SECONDS}s"
        f" (ostatni znany hash: {'brak' if not _last_syslog_previous_hash else _last_syslog_previous_hash[:8]})")
    while True:
        try:
            raw = run_ops_dispatch("syslog_previous")
            if raw and raw.strip() != "USC_NO_SYSLOG_PREVIOUS":
                h = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
                if h != _last_syslog_previous_hash:
                    _last_syslog_previous_hash = h
                    _save_syslog_previous_hash(h)
                    lines = raw.splitlines()
                    post_backend("/ingest/syslog", {"lines": lines})
                    log(f"Syslog-previous poller: NOWA zawartosc po restarcie, {len(lines)} linii wyslanych")
        except Exception as e:  # noqa: BLE001
            log(f"Syslog-previous poller BLAD: {e!r}")
        time.sleep(SYSLOG_PREVIOUS_POLL_SECONDS)


_vm_log_last_line: dict[str, str] = {}
_VM_LOG_STATE_FILE = "/app/keys/.state_vm_log_last_line.json"


def _load_vm_log_last_line() -> dict[str, str]:
    try:
        with open(_VM_LOG_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_vm_log_last_line(state: dict[str, str]) -> None:
    try:
        os.makedirs(os.path.dirname(_VM_LOG_STATE_FILE), exist_ok=True)
        with open(_VM_LOG_STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError as e:
        log(f"BLAD zapisu stanu dedup VM log: {e!r}")


def vm_poll_loop():
    """Petla w osobnym watku: co VM_POLL_SECONDS pobiera stan VM (virsh)
    oraz NOWE linie logow qemu per VM (dedupkikacja po ostatniej znanej
    linii - zeby nie alarmowac w kolko za te sama, juz widziana, historie
    logu przy kazdym tailu ostatnich 100 linii). Stan dedup zapisywany NA
    DYSKU (wolumen usc-keys-data) - przetrwa restart kontenera kolektora."""
    global _vm_log_last_line
    _vm_log_last_line = _load_vm_log_last_line()
    log(f"VM poller: start, poll co {VM_POLL_SECONDS}s")
    while True:
        try:
            raw_health = run_ops_dispatch("vm_health")
            if raw_health:
                vms = []
                for line in raw_health.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        vms.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                post_backend("/ingest/vm_health", {"vms": vms})

            raw_log = run_ops_dispatch("vm_log_tail")
            if raw_log:
                per_vm_lines: dict[str, list[str]] = {}
                for raw_line in raw_log.splitlines():
                    if "\t" not in raw_line:
                        continue
                    vm_name, line = raw_line.split("\t", 1)
                    per_vm_lines.setdefault(vm_name, []).append(line)

                new_pairs = []
                for vm_name, lines in per_vm_lines.items():
                    last_seen = _vm_log_last_line.get(vm_name)
                    if last_seen in lines:
                        idx = len(lines) - 1 - lines[::-1].index(last_seen)
                        new_lines = lines[idx + 1:]
                    else:
                        new_lines = lines[-1:] if lines else []
                    for line in new_lines:
                        new_pairs.append([vm_name, line])
                    if lines:
                        _vm_log_last_line[vm_name] = lines[-1]
                if new_pairs:
                    _save_vm_log_last_line(_vm_log_last_line)
                    post_backend("/ingest/vm_log", {"lines": new_pairs})
                log(f"VM poller: cykl OK, {len(per_vm_lines)} VM, {len(new_pairs)} nowych linii logu")
        except Exception as e:  # noqa: BLE001
            log(f"VM poller BLAD: {e!r}")
        time.sleep(VM_POLL_SECONDS)


LOG_USAGE_ENABLED = os.environ.get("USC_LOG_USAGE_ENABLED", "1") == "1"
LOG_USAGE_POLL_SECONDS = int(os.environ.get("USC_LOG_USAGE_POLL_SECONDS", "600"))


def log_usage_poll_loop():
    """Petla w osobnym watku: co LOG_USAGE_POLL_SECONDS sprawdza zajetosc
    /var/log na unRAID (tmpfs, zwykle 128MB) przez dyspozytor (klucz ops -
    dzieki ControlMaster z dyspozytorem docker_health/syslog_previous/vm
    to zwykle juz otwarte, cieple polaczenie, bez dodatkowego sshd-spamu)."""
    log(f"Log usage poller: start, poll co {LOG_USAGE_POLL_SECONDS}s")
    while True:
        try:
            raw = run_ops_dispatch("log_usage")
            if raw:
                data = json.loads(raw.strip())
                post_backend("/ingest/log_usage", data)
                log(f"Log usage poller: cykl OK, /var/log zajety {data.get('used_pct')}%")
        except Exception as e:  # noqa: BLE001
            log(f"Log usage poller BLAD: {e!r}")
        time.sleep(LOG_USAGE_POLL_SECONDS)


def settings_refresh_loop():
    """Odswieza host/klucz unRAID z panelu co SETTINGS_REFRESH_SECONDS -
    zmiana w panelu dziala bez przebudowy kolektora (max. opoznienie =
    ten interwal)."""
    while True:
        ok = refresh_settings()
        if not ok:
            log("Czekam na skonfigurowanie host/klucz unRAID w panelu (/settings)...")
        time.sleep(SETTINGS_REFRESH_SECONDS)


def main():
    if not INTERNAL_TOKEN:
        log("BRAK USC_INTERNAL_TOKEN - kolektor nie moze sie uwierzytelnic do backendu. Koncze.")
        sys.exit(1)
    log(f"Start. Poll co {POLL_SECONDS}s, backend={BACKEND_URL}")
    refresh_settings()  # pierwsze pobranie synchronicznie, zanim ruszą watki
    threading.Thread(target=settings_refresh_loop, daemon=True).start()
    if SYSLOG_ENABLED:
        threading.Thread(target=syslog_tail_loop, daemon=True).start()
    else:
        log("Syslog tailing wylaczony (USC_SYSLOG_ENABLED=0)")
    if SMART_ENABLED:
        threading.Thread(target=smart_poll_loop, daemon=True).start()
    else:
        log("SMART polling wylaczony (USC_SMART_ENABLED=0)")
    if DOCKER_HEALTH_ENABLED:
        threading.Thread(target=docker_health_poll_loop, daemon=True).start()
    else:
        log("Docker health polling wylaczony (USC_DOCKER_HEALTH_ENABLED=0)")
    if SYSLOG_PREVIOUS_ENABLED:
        threading.Thread(target=syslog_previous_poll_loop, daemon=True).start()
    else:
        log("Syslog-previous polling wylaczony (USC_SYSLOG_PREVIOUS_ENABLED=0)")
    if VM_ENABLED:
        threading.Thread(target=vm_poll_loop, daemon=True).start()
    else:
        log("VM polling wylaczony (USC_VM_ENABLED=0)")
    if LOG_USAGE_ENABLED:
        threading.Thread(target=log_usage_poll_loop, daemon=True).start()
    else:
        log("Log usage polling wylaczony (USC_LOG_USAGE_ENABLED=0)")
    while True:
        try:
            run_once()
        except Exception as e:  # noqa: BLE001 - kolektor nie moze sie wywalic na jednym cyklu
            log(f"NIEOCZEKIWANY BLAD cyklu: {e!r}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
