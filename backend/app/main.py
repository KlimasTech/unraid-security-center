"""USC - backend FastAPI.

Przyjmuje znormalizowane dane z kolektora, odpala Warstwe 1 (reguly
deterministyczne), zapisuje incydenty, udostepnia REST API, dashboard HTML
(desktop+mobile) i panel ustawien. Dostep do panelu/API chroniony HTTP Basic
Auth (admin); endpointy /ingest/* (kolektor->backend) chronione osobnym,
wspoldzielonym tokenem wewnetrznym (bo port backendu jest wystawiony na
hosta przez docker-compose).
"""
from __future__ import annotations
import os
import json
import secrets
import datetime
from typing import Any

from fastapi import FastAPI, Depends, Header, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db import (
    init_db, get_db, Incident, DiskHistory, SmartAttrHistory,
    DockerHealthHistory, VmHealthHistory, get_all_settings, set_setting,
    seed_settings_from_env,
)
from app import rules
from app import telegram
from app import unraid_pair

app = FastAPI(title="unRaid Security Center (USC)", version="0.2.0")

ADMIN_USER = os.environ.get("USC_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("USC_ADMIN_PASSWORD", "")
INTERNAL_TOKEN = os.environ.get("USC_INTERNAL_TOKEN", "")

_security = HTTPBasic()


def verify_admin(credentials: HTTPBasicCredentials = Depends(_security)) -> str:
    ok_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    ok_pass = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidlowy login lub haslo",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def verify_internal(x_usc_token: str | None = Header(default=None)) -> None:
    if not INTERNAL_TOKEN or not x_usc_token or not secrets.compare_digest(x_usc_token, INTERNAL_TOKEN):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nieprawidlowy token wewnetrzny")


@app.on_event("startup")
def on_startup():
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise RuntimeError("USC_ADMIN_USER / USC_ADMIN_PASSWORD musza byc ustawione w .env")
    if not INTERNAL_TOKEN:
        raise RuntimeError("USC_INTERNAL_TOKEN musi byc ustawiony w .env (wspoldzielony z kolektorem)")
    init_db()
    db = next(get_db())
    try:
        seed_settings_from_env(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok", "service": "USC backend", "time": datetime.datetime.utcnow().isoformat()}


def _save_incident(db: Session, inc: dict[str, Any], raw: dict | None = None):
    row = Incident(
        severity=inc["severity"],
        category=inc["category"],
        source=inc.get("source"),
        rule_id=inc["rule_id"],
        title=inc["title"],
        detail=inc.get("detail", ""),
        raw=json.dumps(raw or {}, ensure_ascii=False, default=str),
        status="NEW",
    )
    db.add(row)
    db.commit()
    settings = get_all_settings(db)
    notified = telegram.send_incident_alert(
        inc, settings.get("telegram_bot_token"), settings.get("telegram_chat_id")
    )
    if notified:
        row.notified = True
        db.commit()
    return row


@app.post("/ingest/disks")
def ingest_disks(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """Kolektor wysyla liste dyskow ze stanem z GraphQL unRAID.

    payload = {"disks": [{"device": "sda", "status": "DISK_OK", "warning": false,
                           "critical": false, "num_errors": 0, "temperature": 34}]}
    """
    found = []
    for disk in payload.get("disks", []):
        device = disk.get("device") or disk.get("name")
        prev_row = (
            db.query(DiskHistory)
            .filter(DiskHistory.device == device)
            .order_by(desc(DiskHistory.recorded_at))
            .first()
        )
        prev = None
        if prev_row:
            prev = {
                "status": prev_row.status, "warning": prev_row.warning,
                "critical": prev_row.critical, "num_errors": prev_row.num_errors,
            }
        db.add(DiskHistory(
            device=device, status=disk.get("status"), warning=disk.get("warning"),
            critical=disk.get("critical"), num_errors=disk.get("num_errors"),
            temperature=disk.get("temperature"),
        ))
        for rule_fn in rules.DISK_RULES:
            for inc in rule_fn(disk, prev):
                _save_incident(db, inc, raw=disk)
                found.append(inc)
    db.commit()
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/docker")
def ingest_docker(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"containers": [{"name": ..., "state": "EXITED", "status": "...", "auto_start": bool}]}"""
    found = []
    for c in payload.get("containers", []):
        for inc in rules.rule_docker_not_running(c):
            _save_incident(db, inc, raw=c)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/array")
def ingest_array(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"array_state": "STARTED", "parity_errors": N}"""
    found = []
    for inc in rules.rule_array_not_started(payload.get("array_state")):
        _save_incident(db, inc, raw=payload)
        found.append(inc)
    for inc in rules.rule_parity_errors({"errors": payload.get("parity_errors")}):
        _save_incident(db, inc, raw=payload)
        found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/shares")
def ingest_shares(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"shares": [{"name": "array", "used_pct": 92.3, "free_gb": 120}]}"""
    found = []
    for share in payload.get("shares", []):
        for inc in rules.rule_disk_space_low(share):
            _save_incident(db, inc, raw=share)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/syslog")
def ingest_syslog(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"lines": ["...", "..."]}"""
    found = []
    for line in payload.get("lines", []):
        for inc in rules.rule_kernel_panic(line):
            _save_incident(db, inc, raw={"line": line})
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/smart")
def ingest_smart(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"disks": [{"device","model","attr_5","attr_187","attr_188",
    "attr_197","attr_198","attr_199","nvme_media_errors","nvme_critical_warning",
    "temperature"}]} - z Fazy 2, kolektor zdobywa dane przez SSH+smartctl."""
    found = []
    for smart in payload.get("disks", []):
        device = smart.get("device")
        prev_row = (
            db.query(SmartAttrHistory)
            .filter(SmartAttrHistory.device == device)
            .order_by(desc(SmartAttrHistory.recorded_at))
            .first()
        )
        prev = None
        if prev_row:
            prev = {
                "attr_5": prev_row.attr_5, "attr_187": prev_row.attr_187,
                "attr_188": prev_row.attr_188, "attr_197": prev_row.attr_197,
                "attr_198": prev_row.attr_198, "attr_199": prev_row.attr_199,
            }
        db.add(SmartAttrHistory(
            device=device, model=smart.get("model"),
            attr_5=smart.get("attr_5"), attr_187=smart.get("attr_187"),
            attr_188=smart.get("attr_188"), attr_197=smart.get("attr_197"),
            attr_198=smart.get("attr_198"), attr_199=smart.get("attr_199"),
            nvme_media_errors=smart.get("nvme_media_errors"),
            nvme_critical_warning=smart.get("nvme_critical_warning"),
            temperature=smart.get("temperature"),
        ))
        for rule_fn in rules.SMART_RULES_SINGLE:
            for inc in rule_fn(smart):
                _save_incident(db, inc, raw=smart)
                found.append(inc)
        for rule_fn in rules.SMART_RULES_WITH_HISTORY:
            for inc in rule_fn(smart, prev):
                _save_incident(db, inc, raw=smart)
                found.append(inc)
    db.commit()
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/docker_health")
def ingest_docker_health(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"containers": [{"name","restart_count","oom_killed",
    "health_status","state","exit_code","started_at"}]} - z plugina USC,
    docker inspect przez ograniczony klucz SSH (dyspozytor)."""
    found = []
    for health in payload.get("containers", []):
        name = health.get("name")
        prev_row = (
            db.query(DockerHealthHistory)
            .filter(DockerHealthHistory.name == name)
            .order_by(desc(DockerHealthHistory.recorded_at))
            .first()
        )
        prev = {"restart_count": prev_row.restart_count} if prev_row else None
        db.add(DockerHealthHistory(
            name=name, restart_count=health.get("restart_count"),
            oom_killed=health.get("oom_killed"), health_status=health.get("health_status"),
            state=health.get("state"),
        ))
        for rule_fn in rules.DOCKER_HEALTH_RULES_SINGLE:
            for inc in rule_fn(health):
                _save_incident(db, inc, raw=health)
                found.append(inc)
        for rule_fn in rules.DOCKER_HEALTH_RULES_WITH_HISTORY:
            for inc in rule_fn(health, prev):
                _save_incident(db, inc, raw=health)
                found.append(inc)
    db.commit()
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/vm_health")
def ingest_vm_health(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"vms": [{"name","state"}]} - z plugina USC (virsh domstate)."""
    found = []
    for vm in payload.get("vms", []):
        name = vm.get("name")
        prev_row = (
            db.query(VmHealthHistory)
            .filter(VmHealthHistory.name == name)
            .order_by(desc(VmHealthHistory.recorded_at))
            .first()
        )
        prev = {"state": prev_row.state} if prev_row else None
        db.add(VmHealthHistory(name=name, state=vm.get("state")))
        for rule_fn in rules.VM_HEALTH_RULES_WITH_HISTORY:
            for inc in rule_fn(vm, prev):
                _save_incident(db, inc, raw=vm)
                found.append(inc)
    db.commit()
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/vm_log")
def ingest_vm_log(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"lines": [["vm_name", "linia logu"], ...]} - z plugina USC
    (tail logow qemu per VM)."""
    pairs = [(item[0], item[1]) for item in payload.get("lines", []) if len(item) == 2]
    found = rules.rule_vm_log_errors(pairs)
    for inc in found:
        _save_incident(db, inc, raw={"vm": inc["source"]})
    return {"incidents_found": len(found), "incidents": found}


@app.get("/internal/settings")
def internal_settings(db: Session = Depends(get_db), _=Depends(verify_internal)):
    """Kolektor pobiera stad host/klucz unRAID (ustawiane w panelu, nie w
    env kolektora) - odpytywane okresowo, zeby zmiana w panelu dzialala bez
    przebudowy kontenera kolektora."""
    settings = get_all_settings(db)
    return {
        "unraid_host": settings.get("unraid_host"),
        "unraid_api_key": settings.get("unraid_api_key"),
    }


@app.get("/incidents")
def list_incidents(
    limit: int = 100, status: str | None = None, severity: str | None = None,
    db: Session = Depends(get_db), _=Depends(verify_admin),
):
    q = db.query(Incident).order_by(desc(Incident.created_at))
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    rows = q.limit(limit).all()
    return [
        {
            "id": r.id, "created_at": r.created_at.isoformat(), "severity": r.severity,
            "category": r.category, "source": r.source, "rule_id": r.rule_id,
            "title": r.title, "detail": r.detail, "status": r.status,
        }
        for r in rows
    ]


@app.post("/incidents/{incident_id}/ack")
def acknowledge_incident(incident_id: int, db: Session = Depends(get_db), _=Depends(verify_admin)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return {"error": "not found"}
    row.status = "ACKNOWLEDGED"
    db.commit()
    return {"id": row.id, "status": row.status}


@app.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int, db: Session = Depends(get_db), _=Depends(verify_admin)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return {"error": "not found"}
    row.status = "RESOLVED"
    db.commit()
    return {"id": row.id, "status": row.status}


_SEVERITY_COLOR = {
    "CRITICAL": "#B00020", "ERROR": "#E65100", "WARNING": "#F9A825", "INFO": "#1565C0",
}

_PAGE_STYLE = """
  * { box-sizing: border-box; min-width: 0; }
  body { background:#0d0d0f; color:#eee; font-family: -apple-system, Segoe UI, sans-serif; margin:0; padding:24px; }
  h1 { font-size:20px; margin-bottom:4px; }
  .sub { color:#777; font-size:13px; margin-bottom:20px; }
  a { color:#4a9eff; text-decoration:none; }
  .nav { margin-bottom:20px; font-size:13px; }
  .nav a { margin-right:16px; }
"""


@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db), _=Depends(verify_admin)):
    rows = db.query(Incident).order_by(desc(Incident.created_at)).limit(200).all()
    new_count = db.query(Incident).filter(Incident.status == "NEW").count()
    crit_count = db.query(Incident).filter(
        Incident.status == "NEW", Incident.severity == "CRITICAL"
    ).count()
    rows_html = ""
    cards_html = ""
    for r in rows:
        color = _SEVERITY_COLOR.get(r.severity, "#555")
        ts = r.created_at.strftime('%Y-%m-%d %H:%M:%S')
        rows_html += f"""
        <tr style="border-bottom:1px solid #333;">
          <td style="padding:6px 10px; white-space:nowrap; color:#888; font-size:12px;">{ts}</td>
          <td style="padding:6px 10px;"><span style="background:{color}; color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600;">{r.severity}</span></td>
          <td style="padding:6px 10px; color:#aaa;">{r.category}</td>
          <td style="padding:6px 10px; color:#aaa;">{r.source or '-'}</td>
          <td style="padding:6px 10px;">{r.title}</td>
          <td style="padding:6px 10px; color:#777; font-size:12px;">{r.status}</td>
        </tr>"""
        cards_html += f"""
        <div class="card">
          <div class="card-top">
            <span class="badge" style="background:{color};">{r.severity}</span>
            <span class="card-status">{r.status}</span>
          </div>
          <div class="card-title">{r.title}</div>
          <div class="card-meta">{r.category} &middot; {r.source or '-'}</div>
          <div class="card-time">{ts}</div>
        </div>"""
    empty_msg = '<tr><td colspan="6" style="padding:20px; text-align:center; color:#666;">Brak incydentów — wszystko OK</td></tr>'
    empty_msg_mobile = '<div style="padding:20px; text-align:center; color:#666;">Brak incydentów — wszystko OK</div>'
    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>unRaid Security Center</title>
<meta http-equiv="refresh" content="30">
<style>
{_PAGE_STYLE}
  .stats {{ display:flex; flex-wrap:wrap; gap:16px; margin-bottom:24px; }}
  .stat {{ background:#1a1a1d; border-radius:8px; padding:16px 24px; flex:1 1 140px; }}
  .stat .num {{ font-size:28px; font-weight:700; }}
  .stat .label {{ color:#888; font-size:12px; text-transform:uppercase; }}
  table {{ width:100%; border-collapse:collapse; background:#1a1a1d; border-radius:8px; overflow:hidden; table-layout:fixed; }}
  th {{ text-align:left; padding:8px 10px; background:#222; color:#999; font-size:12px; text-transform:uppercase; }}
  td {{ word-break:break-word; }}
  .mobile-cards {{ display:none; }}
  @media (max-width: 720px) {{
    body {{ padding:12px; }}
    .desktop-table {{ display:none; }}
    .mobile-cards {{ display:block; }}
    .stat {{ padding:12px 16px; flex:1 1 100px; }}
    .stat .num {{ font-size:22px; }}
    .card {{ background:#1a1a1d; border-radius:8px; padding:12px 14px; margin-bottom:10px; }}
    .card-top {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }}
    .badge {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }}
    .card-status {{ color:#777; font-size:12px; }}
    .card-title {{ font-size:14px; margin-bottom:4px; word-break:break-word; }}
    .card-meta {{ color:#aaa; font-size:12px; margin-bottom:2px; }}
    .card-time {{ color:#666; font-size:11px; }}
  }}
</style></head>
<body>
  <h1>🛡️ unRaid Security Center (USC)</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a></div>
  <div class="sub">Odświeża się co 30s</div>
  <div class="stats">
    <div class="stat"><div class="num" style="color:#B00020;">{crit_count}</div><div class="label">Krytyczne (nowe)</div></div>
    <div class="stat"><div class="num">{new_count}</div><div class="label">Nowe incydenty</div></div>
    <div class="stat"><div class="num">{len(rows)}</div><div class="label">Ostatnie 200</div></div>
  </div>
  <div class="desktop-table">
    <table>
      <tr><th>Czas</th><th>Poziom</th><th>Kategoria</th><th>Źródło</th><th>Opis</th><th>Status</th></tr>
      {rows_html if rows_html else empty_msg}
    </table>
  </div>
  <div class="mobile-cards">
    {cards_html if cards_html else empty_msg_mobile}
  </div>
</body></html>"""
    return html


def _mask(value: str | None, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return "•" * len(value)
    return value[:keep] + "•" * max(len(value) - keep, 4)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(db: Session = Depends(get_db), _=Depends(verify_admin), saved: int = 0):
    s = get_all_settings(db)
    banner = '<div class="banner">Zapisano ustawienia.</div>' if saved else ""
    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>USC - Ustawienia</title>
<style>
{_PAGE_STYLE}
  .banner {{ background:#1b3a1b; color:#9fdc9f; padding:10px 14px; border-radius:6px; margin-bottom:16px; font-size:13px; }}
  form {{ background:#1a1a1d; border-radius:8px; padding:20px; max-width:560px; }}
  label {{ display:block; font-size:12px; color:#999; text-transform:uppercase; margin:16px 0 6px; }}
  label:first-of-type {{ margin-top:0; }}
  input {{ width:100%; padding:10px 12px; border-radius:6px; border:1px solid #333; background:#111; color:#eee; font-size:14px; }}
  .hint {{ color:#666; font-size:12px; margin-top:4px; }}
  button {{ margin-top:20px; padding:10px 20px; border-radius:6px; border:none; background:#2a6ef0; color:#fff; font-size:14px; cursor:pointer; }}
</style></head>
<body>
  <h1>🛡️ unRaid Security Center (USC)</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a></div>
  {banner}
  <form method="POST" action="/settings">
    <label>Host unRAID (IP)</label>
    <input name="unraid_host" value="{s.get('unraid_host') or ''}" placeholder="192.168.1.10" required>

    <label>Klucz API unRAID (rola VIEWER)</label>
    <input name="unraid_api_key" type="password" placeholder="{_mask(s.get('unraid_api_key')) or 'wklej nowy klucz'}">
    <div class="hint">Zostaw puste, żeby nie zmieniać obecnego klucza.</div>

    <label>Token bota Telegram</label>
    <input name="telegram_bot_token" type="password" placeholder="{_mask(s.get('telegram_bot_token')) or 'np. z @BotFather'}">
    <div class="hint">Zostaw puste, żeby nie zmieniać. Pamiętaj: musisz najpierw sam napisać do bota.</div>

    <label>Chat ID Telegram (odbiorca alertów)</label>
    <input name="telegram_chat_id" value="{s.get('telegram_chat_id') or ''}" placeholder="123456789">

    <button type="submit">Zapisz</button>
  </form>
</body></html>"""
    return html


@app.post("/settings")
def settings_save(
    unraid_host: str = Form(...),
    unraid_api_key: str = Form(""),
    telegram_bot_token: str = Form(""),
    telegram_chat_id: str = Form(""),
    db: Session = Depends(get_db), _=Depends(verify_admin),
):
    set_setting(db, "unraid_host", unraid_host.strip())
    if unraid_api_key.strip():
        set_setting(db, "unraid_api_key", unraid_api_key.strip())
    if telegram_bot_token.strip():
        set_setting(db, "telegram_bot_token", telegram_bot_token.strip())
    set_setting(db, "telegram_chat_id", telegram_chat_id.strip())
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.get("/wizard", response_class=HTMLResponse)
def wizard_page(db: Session = Depends(get_db), _=Depends(verify_admin)):
    s = get_all_settings(db)
    connected = bool(s.get("unraid_host") and s.get("unraid_api_key"))

    if connected:
        body = f"""
  <div class="banner ok">Połączono z unRAID — IP: {s.get('unraid_host')}</div>
  <p style="color:#999; font-size:13px; max-width:480px;">
    Klucze SSH i klucz API są aktywne, kolektor zbiera dane. Rozłączenie
    usuwa tylko wpisy z panelu (host/klucz API) — klucze SSH w
    <code>authorized_keys</code> na unRAID zostają, więc możesz się
    połączyć ponownie bez ponownego wpisywania hasła roota.
  </p>
  <form method="POST" action="/wizard/disconnect" onsubmit="return confirm('Rozłączyć USC od unRAID {s.get('unraid_host')}?');">
    <button type="submit" class="danger">Rozłącz</button>
  </form>"""
    else:
        body = """
  <p style="color:#999; font-size:13px; max-width:480px;">
    Wklej IP unRAID i hasło roota. Hasło jest użyte TYLKO jednorazowo, przez to
    jedno połączenie SSH - nigdzie nie jest zapisywane. USC sam wygeneruje
    i zainstaluje klucze SSH oraz klucz API (wymaga wcześniej zainstalowanego
    pluginu "unRaid Security Center Plugin" na unRAID).
  </p>
  <form method="POST" action="/wizard/connect" onsubmit="this.querySelector('button').disabled=true; this.querySelector('button').textContent='Łączę...';">
    <label>IP serwera unRAID</label>
    <input name="unraid_host" placeholder="192.168.1.10" required>

    <label>Hasło roota unRAID</label>
    <input name="unraid_password" type="password" required autocomplete="off">
    <div class="hint">Używane tylko teraz, nigdy nie jest zapisywane.</div>

    <button type="submit">Połącz</button>
  </form>"""

    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>USC - Połącz z unRAID</title>
<style>
{_PAGE_STYLE}
  form {{ background:#1a1a1d; border-radius:8px; padding:20px; max-width:480px; }}
  label {{ display:block; font-size:12px; color:#999; text-transform:uppercase; margin:16px 0 6px; }}
  label:first-of-type {{ margin-top:0; }}
  input {{ width:100%; padding:10px 12px; border-radius:6px; border:1px solid #333; background:#111; color:#eee; font-size:14px; }}
  .hint {{ color:#666; font-size:12px; margin-top:4px; }}
  button {{ margin-top:0; padding:10px 20px; border-radius:6px; border:none; background:#2a6ef0; color:#fff; font-size:14px; cursor:pointer; }}
  button:disabled {{ background:#444; cursor:wait; }}
  button.danger {{ background:#B00020; }}
  .banner {{ padding:12px 16px; border-radius:6px; margin-bottom:16px; font-size:14px; max-width:480px; }}
  .banner.ok {{ background:#1b3a1b; color:#9fdc9f; }}
</style></head>
<body>
  <h1>🛡️ unRaid Security Center (USC)</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a></div>
  {body}
</body></html>"""
    return html


@app.post("/wizard/connect", response_class=HTMLResponse)
def wizard_connect(
    unraid_host: str = Form(...),
    unraid_password: str = Form(...),
    db: Session = Depends(get_db), _=Depends(verify_admin),
):
    host = unraid_host.strip()
    try:
        result = unraid_pair.run_pairing(host, unraid_password)
    except unraid_pair.PairingError as e:
        result = {"success": False, "steps": [{"name": "Połączenie", "ok": False, "detail": str(e)}],
                   "unraid_host": host, "unraid_api_key": None}
    finally:
        unraid_password = None  # noqa: F841 - jawne wyczyszczenie referencji do hasla

    if result["success"]:
        set_setting(db, "unraid_host", result["unraid_host"])
        if result["unraid_api_key"]:
            set_setting(db, "unraid_api_key", result["unraid_api_key"])

    steps_html = ""
    for step in result["steps"]:
        icon = "✅" if step["ok"] else "❌"
        steps_html += f"""<div class="wiz-step"><span class="wiz-icon">{icon}</span>
          <div><div class="wiz-name">{step['name']}</div><div class="wiz-detail">{step['detail']}</div></div>
        </div>"""

    banner = (
        '<div class="banner ok">Połączono! Ustawienia zapisane - host i klucz API są już aktywne.</div>'
        if result["success"] else
        '<div class="banner err">Parowanie nie powiodło się - zobacz szczegóły poniżej.</div>'
    )

    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>USC - Wynik parowania</title>
<style>
{_PAGE_STYLE}
  .banner {{ padding:12px 16px; border-radius:6px; margin-bottom:16px; font-size:14px; }}
  .banner.ok {{ background:#1b3a1b; color:#9fdc9f; }}
  .banner.err {{ background:#3a1b1b; color:#e09b9b; }}
  .wiz-step {{ display:flex; gap:12px; align-items:flex-start; background:#1a1a1d; border-radius:8px; padding:12px 14px; margin-bottom:8px; max-width:560px; }}
  .wiz-icon {{ font-size:18px; }}
  .wiz-name {{ font-size:14px; font-weight:600; }}
  .wiz-detail {{ font-size:12px; color:#999; margin-top:2px; }}
</style></head>
<body>
  <h1>🛡️ unRaid Security Center (USC)</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a></div>
  {banner}
  {steps_html}
  <p style="margin-top:20px;"><a href="/settings">← Wróć do ustawień</a></p>
</body></html>"""
    return html


@app.post("/wizard/disconnect")
def wizard_disconnect(db: Session = Depends(get_db), _=Depends(verify_admin)):
    set_setting(db, "unraid_host", "")
    set_setting(db, "unraid_api_key", "")
    return RedirectResponse(url="/wizard", status_code=303)
