"""USC - backend FastAPI.

Faza 1 MVP: przyjmuje znormalizowane dane z kolektora, odpala Warstwę 1
(reguly deterministyczne), zapisuje incydenty, udostepnia REST API i
minimalny dashboard HTML (bez pelnego React - to przyjdzie w kolejnej iteracji).
"""
from __future__ import annotations
import json
import datetime
from typing import Any

from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db import init_db, get_db, Incident, DiskHistory, SmartAttrHistory, DockerHealthHistory, VmHealthHistory
from app import rules
from app import telegram

app = FastAPI(title="unRaid Security Center (USC)", version="0.1.0")


@app.on_event("startup")
def on_startup():
    init_db()


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
    notified = telegram.send_incident_alert(inc)
    if notified:
        row.notified = True
        db.commit()
    return row


@app.post("/ingest/disks")
def ingest_disks(payload: dict[str, Any], db: Session = Depends(get_db)):
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
def ingest_docker(payload: dict[str, Any], db: Session = Depends(get_db)):
    """payload = {"containers": [{"name": ..., "state": "EXITED", "status": "...", "auto_start": bool}]}"""
    found = []
    for c in payload.get("containers", []):
        for inc in rules.rule_docker_not_running(c):
            _save_incident(db, inc, raw=c)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/array")
def ingest_array(payload: dict[str, Any], db: Session = Depends(get_db)):
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
def ingest_shares(payload: dict[str, Any], db: Session = Depends(get_db)):
    """payload = {"shares": [{"name": "array", "used_pct": 92.3, "free_gb": 120}]}"""
    found = []
    for share in payload.get("shares", []):
        for inc in rules.rule_disk_space_low(share):
            _save_incident(db, inc, raw=share)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/syslog")
def ingest_syslog(payload: dict[str, Any], db: Session = Depends(get_db)):
    """payload = {"lines": ["...", "..."]}"""
    found = []
    for line in payload.get("lines", []):
        for inc in rules.rule_kernel_panic(line):
            _save_incident(db, inc, raw={"line": line})
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/smart")
def ingest_smart(payload: dict[str, Any], db: Session = Depends(get_db)):
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
def ingest_docker_health(payload: dict[str, Any], db: Session = Depends(get_db)):
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
def ingest_vm_health(payload: dict[str, Any], db: Session = Depends(get_db)):
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
def ingest_vm_log(payload: dict[str, Any], db: Session = Depends(get_db)):
    """payload = {"lines": [["vm_name", "linia logu"], ...]} - z plugina USC
    (tail logow qemu per VM)."""
    pairs = [(item[0], item[1]) for item in payload.get("lines", []) if len(item) == 2]
    found = rules.rule_vm_log_errors(pairs)
    for inc in found:
        _save_incident(db, inc, raw={"vm": inc["source"]})
    return {"incidents_found": len(found), "incidents": found}


@app.get("/incidents")
def list_incidents(
    limit: int = 100, status: str | None = None, severity: str | None = None,
    db: Session = Depends(get_db),
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
def acknowledge_incident(incident_id: int, db: Session = Depends(get_db)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return {"error": "not found"}
    row.status = "ACKNOWLEDGED"
    db.commit()
    return {"id": row.id, "status": row.status}


@app.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int, db: Session = Depends(get_db)):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return {"error": "not found"}
    row.status = "RESOLVED"
    db.commit()
    return {"id": row.id, "status": row.status}


_SEVERITY_COLOR = {
    "CRITICAL": "#B00020", "ERROR": "#E65100", "WARNING": "#F9A825", "INFO": "#1565C0",
}


@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
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
        # Karta mobilna - te same dane, uklad pionowy (zero scrolla w bok)
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
  * {{ box-sizing: border-box; min-width: 0; }}
  body {{ background:#0d0d0f; color:#eee; font-family: -apple-system, Segoe UI, sans-serif; margin:0; padding:24px; }}
  h1 {{ font-size:20px; margin-bottom:4px; }}
  .sub {{ color:#777; font-size:13px; margin-bottom:20px; }}
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
  <div class="sub">Octopus unRAID — Faza 1 MVP — odświeża się co 30s</div>
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
