"""USC - alerty Telegram.

Wysyla wiadomosc przez Bot API dla incydentow WARNING i wyzej. Token/chat_id
przekazywane jako argumenty (pobrane z panelu/bazy, nie ze zmiennych env) -
brak konfiguracji = cichy no-op (nie wywala backendu), zeby system dzialal
nawet bez skonfigurowanych alertow.
"""
import json
import urllib.request
import urllib.error

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "ERROR": "🟠",
    "WARNING": "🟡",
    "INFO": "🔵",
}

# Tylko te poziomy faktycznie wysylaja powiadomienie (INFO jest zbyt szumne)
_NOTIFY_SEVERITIES = {"WARNING", "ERROR", "CRITICAL"}

# Wyjatki: te rule_id ZAWSZE powiadamiaja Telegram, niezaleznie od severity -
# logowania do WebGUI (udane i nieudane) sa realnym sygnalem bezpieczenstwa
# wartym zobaczenia na biezaco, mimo ze udane logowanie samo w sobie jest
# INFO (zeby nie zawyzac licznika "Nowe incydenty" na dashboardzie).
_ALWAYS_NOTIFY_RULE_IDS = {"webgui_login_success", "webgui_login_failed"}


def send_incident_alert(incident: dict, bot_token: str | None, chat_id: str | None) -> bool:
    """incident = {"severity", "category", "source", "title", "detail"}. Zwraca True gdy wyslano.

    UWAGA: bez parse_mode (plain text) - z Markdown/MarkdownV2 Telegram API
    zwraca "can't parse entities" dla nieescapowanych znakow specjalnych
    (_, *, [, `) w dynamicznej tresci (np. nazwy kontenerow, linie syslogu),
    co powodowalo CICHE gubienie alertow. Niezawodnosc > ladne formatowanie.
    """
    severity = incident.get("severity", "INFO")
    rule_id = incident.get("rule_id", "")
    if severity not in _NOTIFY_SEVERITIES and rule_id not in _ALWAYS_NOTIFY_RULE_IDS:
        return False
    if not bot_token or not chat_id:
        return False

    emoji = _SEVERITY_EMOJI.get(severity, "")
    text = (
        f"{emoji} {severity} - unRaid Security Center\n\n"
        f"{incident.get('title', '')}\n\n"
        f"Kategoria: {incident.get('category', '-')}\n"
        f"Źródło: {incident.get('source', '-')}\n"
        f"{incident.get('detail', '')}"
    )
    body = json.dumps({
        "chat_id": chat_id,
        "text": text[:4000],
    }).encode()
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
            if not resp.get("ok"):
                print(f"[usc-telegram] WYSYLKA NIEUDANA: {resp}", flush=True)
            return bool(resp.get("ok"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"[usc-telegram] WYJATEK przy wysylce: {e!r}", flush=True)
        return False
