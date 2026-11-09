"""USC - Warstwa 1: Reguly deterministyczne (szybkie i bezblędne).

Każda funkcja reguły przyjmuje znormalizowane dane z kolektora i zwraca
listę wykrytych incydentów (puste gdy nic nie znaleziono).

UWAGA o danych: GraphQL API unRAID 7.3 NIE eksportuje surowych atrybutów
SMART (5/187/188/197/198/199) - tylko gotowe flagi `warning`/`critical`
(wyliczone przez sam unRAID na podstawie SMART) i licznik `numErrors`.
Granularna analiza trendu per-atrybut (np. rosnące 199 przy zerowym 197/198
= podejrzenie kabla, nie dysku) wymaga osobnego kolektora SSH + smartctl -
zaplanowane jako rozszerzenie Fazy 2, NIE jest częścią tego MVP. Reguły
poniżej pracują na realnych polach dostępnych teraz przez GraphQL.
"""
from __future__ import annotations
import re
from typing import Any

_SYSLOG_TS_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
_ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def _log_timestamp(line: str) -> str:
    """Wyciaga sam znacznik czasu z poczatku linii logu (format syslog
    'MMM D HH:MM:SS' albo ISO 'YYYY-MM-DDTHH:MM:SS') zamiast pokazywac cala,
    czesto dlugo, linie w alercie Telegram/panelu - tresc linii i tak jest
    juz w tytule incydentu."""
    m = _SYSLOG_TS_RE.match(line)
    if m:
        return m.group(0)
    m = _ISO_TS_RE.match(line)
    if m:
        return m.group(0)
    return line[:30]


def rule_disk_critical(disk: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """unRAID oznaczył dysk jako critical (jego własna ocena SMART) -> CRITICAL."""
    out = []
    if disk.get("critical"):
        out.append({
            "severity": "CRITICAL",
            "category": "disk",
            "source": disk.get("device") or disk.get("name"),
            "rule_id": "disk_critical_flag",
            "title": f"Dysk {disk.get('device') or disk.get('name')}: status CRITICAL",
            "detail": (
                f"unRAID oznaczył ten dysk jako critical (status={disk.get('status')}, "
                f"numErrors={disk.get('num_errors')}). Wykonaj natychmiast kopię zapasową "
                "danych z tego dysku i przygotuj wymianę."
            ),
        })
    return out


def rule_disk_warning(disk: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """unRAID oznaczył dysk jako warning (i nie jest już critical) -> WARNING."""
    out = []
    if disk.get("warning") and not disk.get("critical"):
        out.append({
            "severity": "WARNING",
            "category": "disk",
            "source": disk.get("device") or disk.get("name"),
            "rule_id": "disk_warning_flag",
            "title": f"Dysk {disk.get('device') or disk.get('name')}: status WARNING",
            "detail": f"unRAID oznaczył ten dysk jako warning (status={disk.get('status')}).",
        })
    return out


def rule_smart_197_critical(smart: dict[str, Any]) -> list[dict]:
    """ATA SMART 197 (Current Pending Sector) > 0 -> CRITICAL (z notatki projektowej)."""
    out = []
    v = smart.get("attr_197")
    if v is not None and v > 0:
        out.append({
            "severity": "CRITICAL",
            "category": "smart",
            "source": smart.get("device"),
            "rule_id": "smart_197_pending_sector",
            "title": f"{smart.get('device')}: SMART 197 (Current Pending Sector) = {v}",
            "detail": (
                f"Dysk {smart.get('device')} ({smart.get('model', '?')}) ma {v} sektorow "
                "oczekujacych na realokacje. Wykonaj NATYCHMIAST kopie zapasowa danych z tego "
                "dysku i przygotuj wymiane. NIE uruchamiaj parity rebuild na tym dysku bez "
                "wczesniejszej diagnozy."
            ),
        })
    return out


def rule_smart_199_cable(smart: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """SMART 199 (UDMA CRC) rosnie, a 197/198 == 0 -> WARNING: kabel/kontroler, nie talerz."""
    out = []
    cur_199 = smart.get("attr_199")
    if prev is None or cur_199 is None:
        return out
    prev_199 = prev.get("attr_199")
    if prev_199 is None or cur_199 <= prev_199:
        return out
    attr_197 = smart.get("attr_197") or 0
    attr_198 = smart.get("attr_198") or 0
    if attr_197 == 0 and attr_198 == 0:
        out.append({
            "severity": "WARNING",
            "category": "smart",
            "source": smart.get("device"),
            "rule_id": "smart_199_cable_suspect",
            "title": f"{smart.get('device')}: rosnacy SMART 199 (UDMA CRC) przy 197/198=0",
            "detail": (
                f"UDMA CRC Error Count wzroslo ({prev_199} -> {cur_199}) podczas gdy Pending/"
                "Offline Uncorrectable Sector = 0. To zazwyczaj wada toru transmisyjnego "
                "(kabel SATA, backplane, zasilanie) - NIE degradacja samego talerza. "
                "Sprawdz/wymien kabel SATA przed podejrzewaniem dysku."
            ),
        })
    return out


def rule_nvme_critical(smart: dict[str, Any]) -> list[dict]:
    """NVMe critical_warning != 0 -> CRITICAL, media_errors > 0 -> WARNING."""
    out = []
    cw = smart.get("nvme_critical_warning")
    if cw is not None and cw != 0:
        out.append({
            "severity": "CRITICAL",
            "category": "smart",
            "source": smart.get("device"),
            "rule_id": "nvme_critical_warning",
            "title": f"{smart.get('device')}: NVMe critical_warning={cw}",
            "detail": f"Dysk NVMe {smart.get('device')} zglasza critical_warning (bitmask {cw}). Sprawdz temperature i spare capacity.",
        })
    me = smart.get("nvme_media_errors")
    if me is not None and me > 0:
        out.append({
            "severity": "WARNING",
            "category": "smart",
            "source": smart.get("device"),
            "rule_id": "nvme_media_errors",
            "title": f"{smart.get('device')}: NVMe media_errors={me}",
            "detail": f"Dysk NVMe {smart.get('device')} zglasza {me} bledow nosnika.",
        })
    return out


SMART_RULES_SINGLE = [rule_smart_197_critical, rule_nvme_critical]
SMART_RULES_WITH_HISTORY = [rule_smart_199_cable]


def rule_disk_errors_increasing(disk: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """Licznik numErrors rośnie między odczytami -> WARNING (trend, nie jednorazowy próg)."""
    out = []
    cur = disk.get("num_errors")
    if prev is not None and cur is not None:
        prev_errors = prev.get("num_errors")
        if prev_errors is not None and cur > prev_errors:
            out.append({
                "severity": "WARNING",
                "category": "disk",
                "source": disk.get("device") or disk.get("name"),
                "rule_id": "disk_errors_increasing",
                "title": f"Dysk {disk.get('device') or disk.get('name')}: rosnący numErrors ({prev_errors} -> {cur})",
                "detail": "Licznik błędów dysku rośnie od ostatniego odczytu - obserwuj trend.",
            })
    return out


def rule_docker_not_running(container: dict[str, Any]) -> list[dict]:
    """Kontener w pętli restartu, lub zatrzymany z BŁĘDEM mimo autostartu -> ERROR.

    Exit code 0 ("Exited (0) ...") oznacza czyste, zamierzone zakończenie -
    typowe dla kontenerów jednorazowych (startup scripts) z autoStart=true,
    które mają wystartować raz i wyjść. To NIE jest incydent. Tylko exit code
    != 0 ("Exited (1) ...", "Exited (137) ..." itp.) oznacza realny błąd.
    """
    out = []
    status = (container.get("status") or "")
    state = (container.get("state") or "")
    if "Restarting" in status:
        out.append({
            "severity": "ERROR",
            "category": "docker",
            "source": container.get("name"),
            "rule_id": "docker_restarting",
            "title": f"Kontener {container.get('name')} w pętli restartu",
            "detail": f"Status: {status}",
        })
    elif state.upper() == "EXITED" and container.get("auto_start"):
        import re
        m = re.search(r"Exited \((-?\d+)\)", status)
        exit_code = int(m.group(1)) if m else None
        if exit_code not in (0, None):
            out.append({
                "severity": "ERROR",
                "category": "docker",
                "source": container.get("name"),
                "rule_id": "docker_exited_autostart",
                "title": f"Kontener {container.get('name')} zatrzymany z błędem (exit {exit_code}) mimo autostartu",
                "detail": f"Status: {status}",
            })
    return out


def rule_docker_oom(health: dict[str, Any]) -> list[dict]:
    """oom_killed=True -> ERROR. Dane z 'docker inspect' (plugin USC), GraphQL ich nie udostepnia."""
    out = []
    if health.get("oom_killed"):
        out.append({
            "severity": "ERROR",
            "category": "docker",
            "source": health.get("name"),
            "rule_id": "docker_oom_killed",
            "title": f"Kontener {health.get('name')}: zabity przez OOM Killer",
            "detail": (
                f"Kontener zostal zabity z powodu braku pamieci (exit_code={health.get('exit_code')}). "
                "Sprawdz limity pamieci kontenera i zuzycie RAM hosta."
            ),
        })
    return out


def rule_docker_restart_spike(health: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """RestartCount skoczyl o >=3 od ostatniego odczytu -> ERROR (podejrzenie crash loop)."""
    out = []
    cur = health.get("restart_count")
    if prev is None or cur is None:
        return out
    prev_count = prev.get("restart_count")
    if prev_count is not None and cur - prev_count >= 3:
        out.append({
            "severity": "ERROR",
            "category": "docker",
            "source": health.get("name"),
            "rule_id": "docker_restart_spike",
            "title": f"Kontener {health.get('name')}: RestartCount skoczyl ({prev_count} -> {cur})",
            "detail": "Kontener restartowal sie co najmniej 3 razy od ostatniego sprawdzenia - mozliwy crash loop.",
        })
    return out


def rule_docker_unhealthy(health: dict[str, Any]) -> list[dict]:
    """Docker healthcheck zglasza 'unhealthy' -> WARNING."""
    out = []
    if health.get("health_status") == "unhealthy":
        out.append({
            "severity": "WARNING",
            "category": "docker",
            "source": health.get("name"),
            "rule_id": "docker_unhealthy",
            "title": f"Kontener {health.get('name')}: healthcheck = unhealthy",
            "detail": "Wlasny healthcheck kontenera zglasza status unhealthy.",
        })
    return out


DOCKER_HEALTH_RULES_SINGLE = [rule_docker_oom, rule_docker_unhealthy]
DOCKER_HEALTH_RULES_WITH_HISTORY = [rule_docker_restart_spike]


def rule_vm_unexpected_state(vm: dict[str, Any], prev: dict[str, Any] | None) -> list[dict]:
    """Przejscie running -> paused/crashed/shut off bez znanego powodu -> alert.

    'paused' jest szczegolnie istotny: libvirt/QEMU automatycznie pauzuje
    domene przy bledzie I/O na dysku wirtualnym (vDisk/passthrough) ->
    CRITICAL (wskazuje na problem ze storage, nie z samym VM).
    Nieoczekiwane 'shut off'/'crashed' po wczesniejszym 'running' -> WARNING
    (moglo to byc rowniez zamierzone wylaczenie przez uzytkownika, wiec nie
    CRITICAL, ale warto wiedziec).
    """
    out = []
    cur_state = (vm.get("state") or "").lower()
    if prev is None:
        return out
    prev_state = (prev.get("state") or "").lower()
    if prev_state != "running":
        return out
    if cur_state == "paused":
        out.append({
            "severity": "CRITICAL",
            "category": "vm",
            "source": vm.get("name"),
            "rule_id": "vm_paused_io_error",
            "title": f"VM {vm.get('name')}: zapauzowana (prawdopodobny blad I/O)",
            "detail": (
                f"Maszyna wirtualna {vm.get('name')} przeszla z running do paused. "
                "Libvirt/QEMU automatycznie pauzuje domene przy bledzie zapisu/odczytu "
                "na dysku wirtualnym lub przekazanym urzadzeniu (passthrough). Sprawdz "
                "logi qemu tej VM i stan dysku/kontrolera, ktory jej uzywa."
            ),
        })
    elif cur_state in ("shut off", "crashed") and cur_state != prev_state:
        out.append({
            "severity": "WARNING",
            "category": "vm",
            "source": vm.get("name"),
            "rule_id": "vm_unexpected_stop",
            "title": f"VM {vm.get('name')}: przeszla z running do {cur_state}",
            "detail": (
                f"Maszyna wirtualna {vm.get('name')} nie dziala juz (stan: {cur_state}). "
                "Moglo to byc zamierzone wylaczenie - sprawdz logi qemu jesli nieoczekiwane."
            ),
        })
    return out


def rule_vm_log_errors(vm_lines: list[tuple[str, str]]) -> list[dict]:
    """Skanuje linie logow qemu per VM pod znane markery realnych bledow.

    (vm_name, line) pary. Ignoruje szum (np. 'libusb_release_interface:
    -4 [NO_DEVICE]' przy normalnym hot-unplug urzadzenia USB), reaguje na
    powazniejsze markery.
    """
    out = []
    markers = [
        ("qemu-system-x86_64: error", "ERROR", "qemu_error"),
        ("VFIO_MAP_DMA failed", "ERROR", "vm_vfio_dma_failed"),
        ("libvirtError", "WARNING", "vm_libvirt_error"),
        ("Guest moved used index", "WARNING", "vm_virtio_queue_issue"),
        ("Unexpected error in qemuMonitor", "ERROR", "vm_qemu_monitor_error"),
    ]
    for name, line in vm_lines:
        for marker, severity, rule_id in markers:
            if marker in line:
                out.append({
                    "severity": severity,
                    "category": "vm",
                    "source": name,
                    "rule_id": rule_id,
                    "title": f"VM {name}: wykryto marker '{marker}' w logu qemu",
                    "detail": f"Linia logu: {_log_timestamp(line)}",
                })
                break
    return out


VM_HEALTH_RULES_WITH_HISTORY = [rule_vm_unexpected_state]


def rule_parity_errors(parity: dict[str, Any]) -> list[dict]:
    """Parity Check errors > 0 -> CRITICAL, zablokuj operacje destrukcyjne."""
    out = []
    errors = parity.get("errors")
    try:
        errors_n = int(errors) if errors not in (None, "") else 0
    except (TypeError, ValueError):
        errors_n = 0
    if errors_n > 0:
        out.append({
            "severity": "CRITICAL",
            "category": "parity",
            "source": "array",
            "rule_id": "parity_errors",
            "title": f"Parity Check errors: {errors_n}",
            "detail": (
                "Wykryto błędy kontroli parzystości. NIE uruchamiaj ręcznie korekcji "
                "parzystości ani rebuildu dopóki przyczyna nie zostanie zdiagnozowana - "
                "sprawdź stan dysków (warning/critical) i logi."
            ),
        })
    return out


def rule_array_not_started(array_state: str | None) -> list[dict]:
    """Array nie jest w stanie STARTED -> ERROR (poza oczekiwanym STOPPED przy konserwacji)."""
    out = []
    if array_state and array_state.upper() not in ("STARTED",):
        out.append({
            "severity": "ERROR",
            "category": "array",
            "source": "array",
            "rule_id": "array_not_started",
            "title": f"Array w stanie {array_state} (oczekiwano STARTED)",
            "detail": "Sprawdź WebGUI unRAID - macierz nie jest aktywnie uruchomiona.",
        })
    return out


def rule_kernel_panic(log_line: str) -> list[dict]:
    """Call Trace / kernel panic / BUG: / Oops: -> CRITICAL.

    Zaplanowane pod przyszły kolektor syslogu (SSH tail) - funkcja gotowa,
    nie jest jeszcze wpięta do żadnego /ingest endpointu w tym MVP.
    """
    out = []
    markers = ["Call Trace", "kernel panic", "BUG:", "Oops:"]
    for m in markers:
        if m in log_line:
            out.append({
                "severity": "CRITICAL",
                "category": "kernel",
                "source": "syslog",
                "rule_id": "kernel_panic_marker",
                "title": f"Wykryto marker krytyczny kernela: '{m}'",
                "detail": f"Linia logu: {_log_timestamp(log_line)}",
            })
            break
    return out


def rule_webgui_login(log_line: str) -> list[dict]:
    """Logowanie do WebGUI unRAID (zrodlo: 'webgui:' w syslogu) -> widoczne
    info w panelu, zamiast szumu z laczen SSH kolektora. Oba warianty (udane
    i nieudane) wysylaja alert Telegram (patrz telegram.py - jawna lista
    rule_id, nie standardowy filtr po severity).

    Dokladne stringi logowane przez /usr/local/emhttp/plugins/dynamix/
    include/.login.php: "Successful login user X from Y" i "Unsuccessful
    login user X from Y. [opcjonalny tekst o blokadzie]" - NIE "Failed
    login", latwo zgadnac zle bez sprawdzenia realnego zrodla PHP.
    """
    out = []
    if "webgui:" not in log_line:
        return out
    if "Successful login" in log_line:
        detail = log_line.split("webgui:", 1)[1].strip()
        out.append({
            "severity": "INFO",
            "category": "webgui_access",
            "source": "syslog",
            "rule_id": "webgui_login_success",
            "title": f"Logowanie do WebGUI: {detail}",
            "detail": f"Linia logu: {_log_timestamp(log_line)}",
        })
    elif "Unsuccessful login" in log_line:
        detail = log_line.split("webgui:", 1)[1].strip()
        out.append({
            "severity": "WARNING",
            "category": "webgui_access",
            "source": "syslog",
            "rule_id": "webgui_login_failed",
            "title": f"Nieudane logowanie do WebGUI: {detail}",
            "detail": f"Linia logu: {_log_timestamp(log_line)}",
        })
    return out


def rule_disk_space_low(share: dict[str, Any], threshold_pct: float = 90.0) -> list[dict]:
    """Przestrzen dyskowa (share/array/cache) ponizej progu -> WARNING."""
    out = []
    used_pct = share.get("used_pct")
    if used_pct is not None and used_pct >= threshold_pct:
        out.append({
            "severity": "WARNING",
            "category": "disk_space",
            "source": share.get("name"),
            "rule_id": "disk_space_low",
            "title": f"{share.get('name')}: {used_pct:.1f}% zajętości (próg {threshold_pct}%)",
            "detail": f"Wolne miejsce: {share.get('free_gb', '?')} GB.",
        })
    return out


# Wszystkie reguly operujace na pojedynczym dysku (z historia poprzedniego odczytu)
DISK_RULES = [rule_disk_critical, rule_disk_warning, rule_disk_errors_increasing]
