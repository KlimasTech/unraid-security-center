"""USC - Faza 3: AI-doradca (BEZ uprawnien wykonawczych).

AI analizuje incydent/trendy i zwraca ustrukturyzowana diagnoze:
hipotezy uszeregowane po prawdopodobienstwie, bezpieczne komendy
diagnostyczne do RECZNEGO wykonania przez czlowieka (whitelista
read-only wymuszana po stronie USC - cokolwiek innego AI wymysli,
NIE trafia do odpowiedzi) oraz ostrzezenia 'czego nie robic'.

Zasada architektury: DORADZENIE, NIGDY WYKONANIE. Ten modul nie ma
zadnych kompetencji na unRAID - on tylko generuje tekst. Sekrety sa
redagowane z kontekstu PRZED wyslaniem do providera, a sam provider
jest uzywany tylko na zyczenie operatora (przyciski w panelu).

Provider: dowolny endpoint OpenAI-compatible, konfigurowany w panelu
('API Agenta AI': base URL + klucz + model). Brak konfiguracji =
doradca wylaczony, zwraca czytelny blad konfiguracji.
"""
from __future__ import annotations
import json
import re
import urllib.request
import urllib.error

# --- Redakcja sekretow z kontekstu -------------------------------------------
# Wzorce kluczy mainstreamowych + ogolne 'key=...' - intencja jest zredagowanie
# ROZPOZNAWALNYCH sekretow. To defence-in-depth, nie gwarancja - dlatego
# ostateczna decyzja, do jakiego providera puscic dane, nalezy do operatora.
_SECRET_PATTERNS = [
    (re.compile(r"bot\d{6,}:[A-Za-z0-9_-]{5,}"), "<TG-BOT-TOKEN>"),
    (re.compile(r"\b(sk|rk)-[A-Za-z0-9][A-Za-z0-9_-]{15,}"), "<API-KEY>"),
    (re.compile(r"(?i)(api[_-]?key|token|password|passwd|secret)['\"]?\s*[:=]\s*\S+"), "<SECRET>"),
    (re.compile(r"\b[0-9a-f]{32,}\b"), "<HASH>"),
]


def redact_secrets(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# --- Whitelista BEZPIECZNYCH komend (read-only) -------------------------------
# Doradca MOZE zaproponowac komendy diagnostyczne, ALE operator wykonuje je
# SAM, recznie. USC i tak filtruje: do odpowiedzi trafiaja wylacznie komendy
# zaczynajace sie od dozwolonego narzedzia, bez pipe'ow/przekierowan/substitucji.
# /dev/... jako ARGUMENT jest dozwolone TYLKO dla czytnikow parametrow
# urzadzen (smartctl/lsblk/hdparm/nvme smart-log).
_SAFE_PREFIXES_READ_ONLY = (
    "smartctl", "docker logs", "docker inspect", "docker stats", "docker ps",
    "lsblk", "df -h", "df -", "free -m", "free ", "iostat", "dstat",
    "hdparm", "nvme smart-log", "virsh domstate", "virsh dumpxml",
    "udevadm info", "dmesg", "journalctl",
)
_DEV_ALLOWED_PREFIXES = ("smartctl", "lsblk", "hdparm", "nvme smart-log", "udevadm info")
# destrukcyjne NARZEDZIA sprawdzamy po granicy slowa - substring "rm "
# pasowalby do "hdpa|rm| -I" (falszywy odrzut legalnej komendy hdparm)
_FORBIDDEN_TOOLS_RE = re.compile(
    r"\b(rm|dd|shred|mkfs(\.\w+)?|wipefs|fdisk|sfdisk|parted|blockdev|debugfs)\b"
)
_FORBIDDEN_FRAGMENTS = (
    "> ", ">> ", "|", ";", "&&", "$(", "`",
)


def is_safe_diagnostic_command(cmd: str) -> bool:
    """Zwraca True TYLKO dla komend read-only zgodnych z whitelista."""
    cmd = cmd.strip()
    if not cmd or len(cmd) > 250 or "\n" in cmd:
        return False
    prefix_ok = any(cmd == p or cmd.startswith(p + " ") for p in _SAFE_PREFIXES_READ_ONLY)
    if not prefix_ok:
        return False
    # smartctl TYLKO do odczytu: -t (self-test) i -o (offline test) STARTUJA
    # test na dysku (zmiana stanu, obciazenie) - odrzucane jak kazde pisanie.
    if cmd.startswith("smartctl") and (" -t " in cmd or " -o " in cmd or cmd.endswith(" -t") or cmd.endswith(" -o")):
        return False
    if "/dev/" in cmd and not cmd.startswith(_DEV_ALLOWED_PREFIXES):
        return False
    if _FORBIDDEN_TOOLS_RE.search(cmd):
        return False
    if any(f in cmd for f in _FORBIDDEN_FRAGMENTS):
        return False
    return True


class AIAdvisorError(Exception):
    """Blad doradcy (brak konfiguracji, problem z providerem, zly format)."""


# --- Prompty -------------------------------------------------------------------
_SYSTEM_PROMPT_INCIDENT = """Jestes doradca diagnostycznym dla serwera unRAID (NAS).
Dostajesz opis incydentu wykrytego przez system monitorujacy USC oraz kontekst
(historia SMART dysku, powiazane incydenty, wycinki logow). Pomoz operatorowi
zrozumiec, co sie stalo i co bezpiecznie sprawdzic.

ODPOWIADAJ WYLACZNIE po polsku, w formacie JSON (bez markdown fences):
{
 "summary": "2-4 zdania: co sie prawdopodobnie stalo",
 "hypotheses": [{"title": "...", "likelihood": "wysoka|srednia|niska",
   "evidence": "na czym opierasz te hipoteze (KONKRETNE dane z kontekstu)",
   "check": "co zweryfikowac, ze ja potwierdzic"}],
 "safe_commands": ["komendy read-only do MANUALNEGO wykonania przez operatora"],
 "do_not": ["czego NIE robic przy tym incydencie"]
}

ZASADY:
- hipotezy od najbardziej prawdopodobnej, maksymalnie 4
- safe_commands TYLKO read-only diagnostyczne (np. smartctl -a /dev/sdX,
  docker logs, lsblk, dmesg); NIGDY komendy zmieniajace stan (zapisy,
  formatowania, restarty macierzy, parity rebuild)
- do_not: zawsze co najmniej jeden wpis
- przy braku danych w kontekscie powiedz to wprost w summary, nie zmyslaj"""

_SYSTEM_PROMPT_REPORT = """Jestes doradca diagnostycznym dla serwera unRAID (NAS).
Dostajesz liste incydentow z ostatnich 7 dni oraz trendy SMART/RAM z monitoringu
USC. Stworz czytelny RAPORT STANU dla operatora.

ODPOWIADAJ WYLACZNIE po polsku, w formacie JSON (bez markdown fences):
{
 "summary": "3-6 zdan ogolna ocena stanu serwera",
 "highlights": ["najwazniejsze zdarzenia tygodnia"],
 "watch": ["co warto obserwowac w przyszlym tygodniu"],
 "stats_comment": "komentarz o trendach SMART/RAM"
}
Regula: opieraj sie TYLKO na dostarczonych danych, nie zmyslaj."""


def _require_settings(ai_settings: dict) -> tuple[str, str, str]:
    # Akceptujemy OBA styl kluczy: baza zwraca ai_base_url/ai_api_key/ai_model
    # (get_ai_settings z app.db), a dokumentacja modulu mowila base_url/
    # api_key/model - literowki kluczy nie moga wylaczac doradcy.
    base_url = (ai_settings.get("ai_base_url") or ai_settings.get("base_url") or "").strip()
    api_key = (ai_settings.get("ai_api_key") or ai_settings.get("api_key") or "").strip()
    model = (
        ai_settings.get("ai_model") or ai_settings.get("model") or ""
    ).strip() or "gpt-4o-mini"
    if not base_url or not api_key:
        raise AIAdvisorError(
            "Doradca AI nie jest skonfigurowany - uzupelnij 'API Agenta AI' w Ustawieniach."
        )
    return base_url, api_key, model


def _chat_completion(
    base_url: str, api_key: str, model: str, system_prompt: str,
    user_content: str, timeout: int = 60,
) -> dict:
    """Wywoluje OpenAI-compatible /chat/completions i zwraca sparsowany JSON.

    Normalizacja base URL: operator moze wkleic zarowno bazowe
    'https://.../v1', jak i pelny endpoint 'https://.../v1/chat/completions'
    (czesty przypadek - OpenRouter podaje w dokumentacji pelny URL).
    Koncowka '/chat/completions' jest zdejmowana i doklejana RAZ.
    """
    url = base_url.rstrip("/")
    if url.endswith("/chat/completions"):
        url = url[: -len("/chat/completions")]
    url += "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            detail = e.read()[:300]
        except Exception:  # noqa: BLE001
            detail = b""
        raise AIAdvisorError(f"Provider zwrocil HTTP {e.code}: {detail!r}") from e
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise AIAdvisorError(f"Blad polaczenia z providerem: {e!r}") from e
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise AIAdvisorError(f"Nieoczekiwany format odpowiedzi providera: {e!r}") from e
    # Model mial odpowiadac czystym JSON, ale bywa, ze oplota go w fence.
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1] if "\n" in content else content
        content = content.rsplit("```", 1)[0]
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise AIAdvisorError(
            f"Model nie zwrocil poprawnego JSON ({e}); poczatek odpowiedzi: {content[:200]}"
        ) from e


def _ensure_fields(result: dict, defaults: dict) -> None:
    for key, value in defaults.items():
        if key not in result or not isinstance(result[key], type(value)):
            result[key] = value


def advise_incident(ai_settings: dict, incident: dict, context: dict) -> dict:
    """Diagnoza incydentu. context (smart_history/related/syslog_lines) MUSI
    byc juz zredagowany (redact_secrets) przez wywolawce."""
    base_url, api_key, model = _require_settings(ai_settings)
    payload = {"incydent": incident, "kontekst": context}
    result = _chat_completion(
        base_url, api_key, model, _SYSTEM_PROMPT_INCIDENT,
        json.dumps(payload, ensure_ascii=False, default=str),
    )
    # WALIDACJA: komendy przez whiteliste - nic poza read-only nie trafia
    # do operatora, nawet gdyby model zaproponowal cos destrukcyjnego.
    cmds = result.get("safe_commands") or []
    if not isinstance(cmds, list):
        cmds = []
    kept = [c for c in cmds if isinstance(c, str) and is_safe_diagnostic_command(c)]
    result["safe_commands"] = kept
    result["safe_commands_filtered_count"] = len(cmds) - len(kept)
    _ensure_fields(result, {"summary": "-", "hypotheses": [], "do_not": []})
    return result


def advise_weekly_report(ai_settings: dict, incidents: list, trends: dict) -> dict:
    """Raport stanu (7 dni)."""
    base_url, api_key, model = _require_settings(ai_settings)
    payload = {"incydenty_7dni": incidents, "trendy": trends}
    result = _chat_completion(
        base_url, api_key, model, _SYSTEM_PROMPT_REPORT,
        json.dumps(payload, ensure_ascii=False, default=str),
        timeout=90,
    )
    _ensure_fields(
        result, {"summary": "-", "highlights": [], "watch": [], "stats_comment": "-"}
    )
    return result
