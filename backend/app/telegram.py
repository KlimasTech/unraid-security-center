"""USC - alerty Telegram.

Wysyla wiadomosc przez Bot API dla incydentow WARNING i wyzej. Token/chat_id
z zmiennych srodowiskowych - brak konfiguracji = cichy no-op (nie wywala
backendu), zeby MVP dzialal nawet bez skonfigurowanych alertow.
"""
import os
import json
import urllib.request
import urllib.error

TELEGRAM_BOT_TOKEN = os.environ.get("USC_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("USC_TELEGRAM_CHAT_ID", "")

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "ERROR": "🟠",
    "WARNING": "🟡",
    "INFO": "🔵",
}

# Tylko te poziomy faktycznie wysylaja powiadomienie (INFO jest zbyt szumne)
_NOTIFY_SEVERITIES = {"WARNING", "ERROR", "CRITICAL"}


def send_incident_alert(incident: dict) -> bool:
    """incident = {"severity", "category", "source", "title", "detail"}. Zwraca True gdy wyslano.

    UWAGA: bez parse_mode (plain text) - z Markdown/MarkdownV2 Telegram API
    zwraca "can't parse entities" dla nieescapowanych znakow specjalnych
    (_, *, [, `) w dynamicznej tresci (np. nazwy kontenerow, linie syslogu),
    co powodowalo CICHE gubienie alertow. Niezawodnosc > ladne formatowanie.
    """
    severity = incident.get("severity", "INFO")
    if severity not in _NOTIFY_SEVERITIES:
        return False
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    emoji = _SEVERITY_EMOJI.get(severity, "")
    text = (
        f"{emoji} {severity} - unRaid Security Center\n\n"
        f"{incident.get('title', '')}\n"
        f"Kategoria: {incident.get('category', '-')}  *  Zrodlo: {incident.get('source', '-')}\n\n"
        f"{incident.get('detail', '')}"
    )
    body = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text[:4000],
    }).encode()
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
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
