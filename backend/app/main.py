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
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db import (
    init_db, get_db, Incident, DiskHistory, SmartAttrHistory,
    DockerHealthHistory, VmHealthHistory, LogUsageHistory, DockerLogUsageHistory,
    SyslogLine, MemoryUsageHistory, Advisory, get_ai_settings,
    get_all_settings, set_setting, seed_settings_from_env,
)
from app import rules
from app import telegram
from app import unraid_pair
from app import ai_advisor

app = FastAPI(title="unRaid Security Center (USC)", version="0.2.0")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

_LOGO_HEAD = '<link rel="icon" type="image/png" href="/static/favicon.png">'
_LOGO_H1 = '<img src="/static/logo-96.png" alt="USC" style="height:48px;width:48px;border-radius:50%;vertical-align:-14px;margin-right:10px;"> unRaid Security Center (USC)'

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
    """payload = {"lines": ["...", "..."]}

    Linie sa PRZECHOWYWANE w syslog_lines (z pochodna flaga is_sata_reset)
    - to material dla korelacji Fazy 2 (np. rosnacy SMART 199 + seria resetow
    SATA = wada toru transmisyjnego). Prune do 48h przy kazdym ingescie.
    """
    lines = payload.get("lines", [])
    found = []
    sata_seen = 0
    first_reset_line = None
    for line in lines:
        is_reset = rules.is_sata_reset_line(line)
        if is_reset and first_reset_line is None:
            first_reset_line = line
        db.add(SyslogLine(line=line, is_sata_reset=is_reset))
        for inc in rules.rule_kernel_panic(line):
            _save_incident(db, inc, raw={"line": line})
            found.append(inc)
        for inc in rules.rule_webgui_login(line):
            _save_incident(db, inc, raw={"line": line})
            found.append(inc)
        if is_reset:
            sata_seen += 1
    # Incydent sata_reset: deduplikacja 10-minutowa - seria resetow przy
    # jednym zdarzeniu kernela to kilka linii, nie chcemy N IDENTYCZNYCH
    # incydentow INFO, wystarczy jeden na okno (korelacja liczy linie
    # z syslog_lines, nie incydenty).
    if sata_seen:
        ten_min_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        recent = db.query(Incident).filter(
            Incident.rule_id == "sata_reset", Incident.created_at >= ten_min_ago
        ).first()
        if not recent:
            inc = rules.rule_sata_reset(first_reset_line)
            for i in inc:
                _save_incident(db, i, raw={"sata_reset_lines": sata_seen})
                found.append(i)
    # Prune: trzymamy tylko 48h linii (korelacja patrzy 24h wstecz +
    # zapas); bez tego tabela roslaby w nieskonczonosc.
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=48)
    db.query(SyslogLine).filter(SyslogLine.received_at < cutoff).delete()
    db.commit()
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/memory")
def ingest_memory(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"total_mb": 32042, "available_mb": 8123, "used_pct": 75}
    - zajetosc RAM hosta unRAID (free -m przez dyspozytor USC)."""
    used_pct = payload.get("used_pct")
    available_mb = payload.get("available_mb")
    db.add(MemoryUsageHistory(
        total_mb=payload.get("total_mb"),
        available_mb=available_mb,
        used_pct=used_pct,
    ))
    db.commit()
    found = []
    if used_pct is not None:
        for inc in rules.rule_mem_available_low(used_pct, available_mb):
            _save_incident(db, inc, raw=payload)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/log_usage")
def ingest_log_usage(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"used_pct": 16, "used_bytes": 20140032, "total_bytes": 134217728}
    - zajetosc /var/log (tmpfs, zwykle 128MB na unRAID)."""
    used_pct = payload.get("used_pct")
    db.add(LogUsageHistory(
        used_pct=used_pct,
        used_bytes=payload.get("used_bytes"),
        total_bytes=payload.get("total_bytes"),
    ))
    db.commit()
    found = []
    if used_pct is not None:
        for inc in rules.rule_log_usage_high(used_pct):
            _save_incident(db, inc, raw=payload)
            found.append(inc)
    return {"incidents_found": len(found), "incidents": found}


@app.post("/ingest/docker_log_usage")
def ingest_docker_log_usage(payload: dict[str, Any], db: Session = Depends(get_db), _=Depends(verify_internal)):
    """payload = {"used_pct": 8, "used_bytes": ..., "max_bytes": ..., "container_count": 25}
    - zajetosc logow kontenerow Docker wzgledem limitu z polityki rotacji."""
    used_pct = payload.get("used_pct")
    container_count = payload.get("container_count") or 0
    db.add(DockerLogUsageHistory(
        used_pct=used_pct,
        used_bytes=payload.get("used_bytes"),
        max_bytes=payload.get("max_bytes"),
        container_count=container_count,
    ))
    db.commit()
    found = []
    if used_pct is not None:
        for inc in rules.rule_docker_log_usage_high(used_pct, container_count):
            _save_incident(db, inc, raw=payload)
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
        # Faza 2 - korelacja: rosnacy UDMA CRC + reset linku SATA potwierdzone
        # w przechowywanym syslogu (24h). Liczymy po zindexowanej fladze, nie
        # po tekscie linii. Pierwsza kolejnosc: gdy korelacja strzela, zwykla
        # regula 'cable_suspect' NIE zglasza incydentu - jeden spojny alert
        # z dowodem zamiast dwoch alarmow o tym samym sygnale.
        day_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
        sata_resets_24h = (
            db.query(SyslogLine)
            .filter(SyslogLine.is_sata_reset.is_(True), SyslogLine.received_at >= day_ago)
            .count()
        )
        correlated = rules.rule_smart_199_link_correlated(smart, prev, sata_resets_24h)
        for inc in correlated:
            _save_incident(db, inc, raw={**smart, "sata_resets_24h": sata_resets_24h})
            found.append(inc)
        for rule_fn in rules.SMART_RULES_SINGLE:
            for inc in rule_fn(smart):
                _save_incident(db, inc, raw=smart)
                found.append(inc)
        for rule_fn in rules.SMART_RULES_WITH_HISTORY:
            for inc in rule_fn(smart, prev):
                if correlated and inc.get("rule_id") == "smart_199_cable_suspect":
                    continue  # zastapione przez smart_x199_link_correlated
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
        # Faza 2 - korelacja: OOM kill + znikniecie RAM hosta miedzy dwoma
        # ostatnimi pomiarami = spojny obraz wycieku pamieci kontenera.
        last_two = (
            db.query(MemoryUsageHistory)
            .order_by(desc(MemoryUsageHistory.recorded_at))
            .limit(2)
            .all()
        )
        ram_jump = None
        if len(last_two) == 2 and last_two[0].available_mb is not None and last_two[1].available_mb is not None:
            ram_jump = last_two[1].available_mb - last_two[0].available_mb
        for inc in rules.rule_docker_mem_leak_correlated(health, ram_jump):
            _save_incident(db, inc, raw={**health, "ram_jump_mb": ram_jump})
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
        # Faza 2 - korelacja: pauza + markery bledow w logu qemu tej VM
        # (niedawne incydenty vm_log, 15 min) = pauza z potwierdzona przyczyna.
        vm_log_rule_ids = ("qemu_error", "vm_vfio_dma_failed", "vm_libvirt_error", "vm_qemu_monitor_error")
        fifteen_min_ago = datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        evidence_rows = db.query(Incident).filter(
            Incident.source == name,
            Incident.rule_id.in_(vm_log_rule_ids),
            Incident.created_at >= fifteen_min_ago,
        ).all()
        qemu_evidence = [f"{r.rule_id} @ {r.created_at.strftime('%H:%M')}" for r in evidence_rows]
        correlated = rules.rule_vm_paused_io_correlated(vm, qemu_evidence)
        for inc in correlated:
            _save_incident(db, inc, raw={**vm, "qemu_evidence": qemu_evidence})
            found.append(inc)
        for rule_fn in rules.VM_HEALTH_RULES_WITH_HISTORY:
            for inc in rule_fn(vm, prev):
                if correlated and inc.get("rule_id") == "vm_paused_io_error":
                    continue  # zastapione przez vm_paused_io_correlated
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


def _build_incident_context(db: Session, incident_row) -> dict:
    """Buduje (deterministycznie, z budzetem) kontekst dla AI-doradcy:
    historia SMART zrodlowego dysku, powiazane incydenty (to zrodlo),
    oraz relevante linie syslogu z 24h. WSZYSTKO przechodzi przez
    redact_secrets przed wyjsciem z tej funkcji."""
    source = incident_row.source or ""
    context: dict[str, Any] = {"smart_history": [], "related": [], "syslog_lines": []}

    # historia SMART dysku-zrodla (ostatnie 24h, max 20 pomiarow)
    if source.startswith("/dev/") or source.startswith("sd"):
        day_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
        rows = (
            db.query(SmartAttrHistory)
            .filter(SmartAttrHistory.device == source, SmartAttrHistory.recorded_at >= day_ago)
            .order_by(desc(SmartAttrHistory.recorded_at))
            .limit(20)
            .all()
        )
        context["smart_history"] = [
            {
                "recorded_at": r.recorded_at.isoformat(), "attr_197": r.attr_197,
                "attr_198": r.attr_198, "attr_199": r.attr_199, "temperature": r.temperature,
            }
            for r in rows
        ]

    # powiazane incydenty (to samo zrodlo, nie ten sam, ostatnie 5)
    related = (
        db.query(Incident)
        .filter(Incident.source == source, Incident.id != incident_row.id)
        .order_by(desc(Incident.created_at))
        .limit(5)
        .all()
    )
    context["related"] = [
        {"created_at": r.created_at.isoformat(), "severity": r.severity,
         "rule_id": r.rule_id, "title": r.title, "detail": r.detail}
        for r in related
    ]

    # linie syslogu z 24h pasujace do zrodla lubSlow kluczowych incydentu
    day_ago = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    keywords = [w for w in (source, incident_row.category) if w]
    sys_rows = (
        db.query(SyslogLine)
        .filter(SyslogLine.received_at >= day_ago)
        .order_by(desc(SyslogLine.received_at))
        .limit(500)
        .all()
    )
    picked = []
    for r in sys_rows:
        if any(k and k in (r.line or "") for k in keywords):
            picked.append(r.line)
        if len(picked) >= 30:
            break
    context["syslog_lines"] = picked

    # redakcja sekretow CALOSCI kontekstu + incydentu (defence-in-depth)
    context = json.loads(ai_advisor.redact_secrets(json.dumps(context, default=str)))
    return context


@app.post("/incidents/{incident_id}/advise")
def advise_incident_endpoint(
    incident_id: int, regenerate: int = 0,
    db: Session = Depends(get_db), _=Depends(verify_admin),
):
    """Diagnoza AI incydentu (Faza 3). Reczny trigger z panelu, cache
    w advisories (regenerate=1 wymusza ponowne generowanie)."""
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return {"error": "not found"}
    if not regenerate:
        cached = (
            db.query(Advisory)
            .filter(Advisory.incident_id == incident_id, Advisory.kind == "incident")
            .order_by(desc(Advisory.created_at))
            .first()
        )
        # Cache(unia) tylko SUKCESOW: zapisany blad nie blokuje kolejnej
        # proby - operator mogl w miedzyczasie poprawic konfiguracje
        # doradcy (jakie to typowe: pierwszy klik bez klucza API).
        if cached and cached.result_json:
            return {"incident_id": incident_id, "cached": True,
                    "result": json.loads(cached.result_json)}

    incident = {
        "severity": row.severity, "category": row.category, "source": row.source,
        "rule_id": row.rule_id, "title": row.title, "detail": row.detail,
        "created_at": row.created_at.isoformat(),
    }
    context = _build_incident_context(db, row)
    advisory_row = Advisory(incident_id=incident_id, kind="incident")
    try:
        result = ai_advisor.advise_incident(get_ai_settings(db), incident, context)
        advisory_row.result_json = json.dumps(result, ensure_ascii=False)
        error = None
    except ai_advisor.AIAdvisorError as e:
        result, error = None, str(e)
        advisory_row.error = error
    db.add(advisory_row)
    db.commit()
    if error:
        return {"incident_id": incident_id, "error": error}
    return {"incident_id": incident_id, "cached": False, "result": result}


@app.post("/report/weekly")
def weekly_report_endpoint(send_telegram: int = 0, db: Session = Depends(get_db), _=Depends(verify_admin)):
    """Raport stanu AI za ostatnie 7 dni (incydenty + trendy). Opcjonalnie
    wysylka na Telegram (send_telegram=1)."""
    week_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    incidents = (
        db.query(Incident)
        .filter(Incident.created_at >= week_ago)
        .order_by(desc(Incident.created_at))
        .limit(150)
        .all()
    )
    incidents_payload = [
        {"created_at": r.created_at.isoformat(), "severity": r.severity,
         "category": r.category, "source": r.source, "rule_id": r.rule_id,
         "title": r.title, "status": r.status}
        for r in incidents
    ]
    # trendy: SMART per dysk (min/max/ostatnia z 7 dni) + RAM (min/max/ostatnia)
    smart_trends = {}
    for dev_row in db.query(SmartAttrHistory.device).distinct().all():
        device = dev_row[0]
        hist = (
            db.query(SmartAttrHistory)
            .filter(SmartAttrHistory.device == device, SmartAttrHistory.recorded_at >= week_ago)
            .order_by(SmartAttrHistory.recorded_at)
            .all()
        )
        if not hist:
            continue
        def _mm(field):
            vals = [getattr(h, field) for h in hist if getattr(h, field) is not None]
            if not vals:
                return None
            return {"min": min(vals), "max": max(vals), "last": vals[-1]}
        smart_trends[device] = {"attr_199": _mm("attr_199"), "attr_197": _mm("attr_197"),
                                "temperature": _mm("temperature")}
    mem_hist = db.query(MemoryUsageHistory).filter(
        MemoryUsageHistory.recorded_at >= week_ago
    ).order_by(MemoryUsageHistory.recorded_at).all()
    mem_vals = [m.used_pct for m in mem_hist if m.used_pct is not None]
    ram_trend = ({"min": min(mem_vals), "max": max(mem_vals), "last": mem_vals[-1]}
                 if mem_vals else None)

    advisory_row = Advisory(kind="weekly_report")
    try:
        result = ai_advisor.advise_weekly_report(
            get_ai_settings(db), incidents_payload,
            {"smart": smart_trends, "ram": ram_trend},
        )
        advisory_row.result_json = json.dumps(result, ensure_ascii=False)
        error = None
    except ai_advisor.AIAdvisorError as e:
        result, error = None, str(e)
        advisory_row.error = error
    db.add(advisory_row)
    db.commit()
    if error:
        return {"error": error}

    if send_telegram:
        settings = get_all_settings(db)
        text = (
            "🤖 USC - raport tygodnia (AI)\n\n"
            f"{result.get('summary', '')}\n\n"
            "Najważniejsze:\n- " + "\n- ".join(result.get("highlights") or ["-"]) + "\n\n"
            "Obserwować:\n- " + "\n- ".join(result.get("watch") or ["-"])
        )
        telegram.send_plain_message(
            text, settings.get("telegram_bot_token"), settings.get("telegram_chat_id")
        )
    return {"cached": False, "result": result}


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


@app.get("/advise/{incident_id}", response_class=HTMLResponse)
def advise_page(incident_id: int, db: Session = Depends(get_db), _=Depends(verify_admin)):
    """Strona diagnozy AI dla incydentu. Klikniecie linku na dashboardzie =
    od razu proba generowania (przy cache pokazuje zapisany wynik natychmiast);
    przycisk 'Generuj ponownie' wymusza nowe (regenerate=1)."""
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        return HTMLResponse("<h3>Nie ma takiego incydentu.</h3>", status_code=404)

    resp = advise_incident_endpoint(incident_id, regenerate=0, db=db)
    _ = verify_admin  # dependency juz spelnila rolę przy wejsciu

    error = resp.get("error")
    result = resp.get("result") or {}
    cached = resp.get("cached", False)

    hyp_html = ""
    for h in (result.get("hypotheses") or []):
        hyp_html += f"""
        <div class="hyp">
          <div class="hyp-title">{h.get('title', '?')} <span class="lik lik-{(h.get('likelihood') or 'srednia').lower()}">{h.get('likelihood', '')}</span></div>
          <div class="hyp-row"><b>Dowód:</b> {h.get('evidence', '-')}</div>
          <div class="hyp-row"><b>Weryfikacja:</b> {h.get('check', '-')}</div>
        </div>"""

    cmds = result.get("safe_commands") or []
    cmds_html = "".join(f"<div class='cmd'>&#36; {c}</div>" for c in cmds)
    if result.get("safe_commands_filtered_count"):
        cmds_html += f"<div class='hint'>(Filtr bezpieczeństwa odrzucił {result['safe_commands_filtered_count']} propozycji spoza whitelisty read-only)</div>"

    do_not = result.get("do_not") or []
    donot_html = "".join(f"<div class='donot'>&#9888; {d}</div>" for d in do_not)

    ts = row.created_at.strftime('%Y-%m-%d %H:%M:%S')
    color = _SEVERITY_COLOR.get(row.severity, "#555")
    err_banner = f'<div class="banner err">{error}</div>' if error else ""
    body_html = f"""
    {err_banner}
    <div class="inc">
      <span class="badge" style="background:{color};">{row.severity}</span>
      <b>{row.title}</b>
      <div class="hint">{ts} &middot; {row.category} &middot; {row.source or '-'} &middot; regula: {row.rule_id}</div>
      <div class="hint">{row.detail}</div>
    </div>
    <h2 class="sect">🤖 Diagnoza AI {'(z cache)' if cached else ''}</h2>
    <div class="adv-box">
      <p>{result.get('summary', '-')}</p>
    </div>
    <h2 class="sect">Hipotezy (od najbardziej prawdopodobnej)</h2>
    {hyp_html or '<div class="hint">brak hipotez w odpowiedzi modelu</div>'}
    <h2 class="sect">Bezpieczne komendy do ręcznego wykonania</h2>
    {cmds_html or '<div class="hint">brak propozycji</div>'}
    <h2 class="sect">Czego NIE robić</h2>
    {donot_html or '<div class="hint">brak ostrzeżeń</div>'}
    <form method="POST" action="/advise/{incident_id}/regenerate" style="margin-top:24px;">
      <button type="submit">Generuj ponownie (omija cache)</button>
    </form>"""

    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
{_LOGO_HEAD}
<title>USC - Diagnoza AI</title>
<style>
{_PAGE_STYLE}
  .nav a {{ margin-right:16px; }}
  h2.sect {{ margin:24px 0 8px; font-size:15px; }}
  .banner {{ padding:12px 16px; border-radius:6px; margin-bottom:16px; font-size:14px; max-width:760px; }}
  .banner.err {{ background:#3a1b1b; color:#e09b9b; }}
  .inc {{ background:#1a1a1d; border-radius:8px; padding:14px 16px; margin-bottom:8px; max-width:760px; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; margin-right:8px; }}
  .adv-box {{ background:#1a1a1d; border-radius:8px; padding:14px 16px; max-width:760px; }}
  .hyp {{ background:#1a1a1d; border-radius:8px; padding:12px 14px; margin-bottom:8px; max-width:760px; }}
  .hyp-title {{ font-weight:600; margin-bottom:6px; }}
  .hyp-row {{ font-size:13px; color:#bbb; margin-bottom:3px; }}
  .lik {{ font-size:11px; padding:1px 7px; border-radius:4px; margin-left:8px; }}
  .lik-wysoka {{ background:#B00020; color:#fff; }}
  .lik-srednia {{ background:#F9A825; color:#111; }}
  .lik-niska {{ background:#2a6ef0; color:#fff; }}
  .cmd {{ font-family:monospace; background:#111; border:1px solid #333; border-radius:4px; padding:6px 10px; margin-bottom:4px; max-width:760px; overflow-x:auto; }}
  .donot {{ font-size:13px; color:#e0a88a; margin-bottom:4px; max-width:760px; }}
  .hint {{ color:#666; font-size:12px; margin-top:4px; }}
  form {{ background:none; padding:0; max-width:none; }}
</style></head>
<body>
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
  {body_html}
</body></html>"""
    return html


@app.post("/advise/{incident_id}/regenerate")
def advise_regenerate(incident_id: int, db: Session = Depends(get_db), _=Depends(verify_admin)):
    advise_incident_endpoint(incident_id, regenerate=1, db=db)
    return RedirectResponse(url=f"/advise/{incident_id}", status_code=303)


@app.get("/report/weekly/view", response_class=HTMLResponse)
def weekly_report_page(db: Session = Depends(get_db), _=Depends(verify_admin)):
    """Raport tygodnia AI - wygenerowany na zyczenie (przycisk), z opcja
    wyslania kopii na Telegram."""
    resp = weekly_report_endpoint(send_telegram=0, db=db)
    result = resp.get("result") or {}
    error = resp.get("error")

    hl_html = "".join(f"<li>{h}</li>" for h in (result.get("highlights") or []))
    watch_html = "".join(f"<li>{w}</li>" for w in (result.get("watch") or []))
    err_banner = f'<div class="banner err">{error}</div>' if error else ""
    body = f"""
    {err_banner}
    <div class="adv-box"><p>{result.get('summary', '-')}</p></div>
    <h2 class="sect">Najważniejsze zdarzenia</h2>
    <ul>{hl_html or '<div class="hint">brak</div>'}</ul>
    <h2 class="sect">Obserwować w przyszłym tygodniu</h2>
    <ul>{watch_html or '<div class="hint">brak</div>'}</ul>
    <h2 class="sect">Trendy</h2>
    <div class="adv-box"><p>{result.get('stats_comment', '-')}</p></div>
    <form method="POST" action="/report/weekly/send-tg" style="margin-top:24px;">
      <button type="submit">Wyślij kopię na Telegram</button>
    </form>"""

    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
{_LOGO_HEAD}
<title>USC - Raport tygodnia</title>
<style>
{_PAGE_STYLE}
  .nav a {{ margin-right:16px; }}
  h2.sect {{ margin:24px 0 8px; font-size:15px; }}
  .banner {{ padding:12px 16px; border-radius:6px; margin-bottom:16px; font-size:14px; max-width:760px; }}
  .banner.err {{ background:#3a1b1b; color:#e09b9b; }}
  .adv-box {{ background:#1a1a1d; border-radius:8px; padding:14px 16px; max-width:760px; }}
  ul {{ color:#bbb; font-size:14px; max-width:760px; }}
  form {{ background:none; padding:0; max-width:none; }}
</style></head>
<body>
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
  {body}
</body></html>"""
    return html


@app.post("/report/weekly/send-tg")
def weekly_report_send_tg(db: Session = Depends(get_db), _=Depends(verify_admin)):
    weekly_report_endpoint(send_telegram=1, db=db)
    return RedirectResponse(url="/report/weekly/view", status_code=303)


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
  .ai-link { font-size:12px; margin-left:8px; white-space:nowrap; }
"""


@app.get("/", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db), _=Depends(verify_admin)):
    rows = db.query(Incident).order_by(desc(Incident.created_at)).limit(200).all()
    new_count = db.query(Incident).filter(
        Incident.status == "NEW", Incident.severity != "INFO"
    ).count()
    crit_count = db.query(Incident).filter(
        Incident.status == "NEW", Incident.severity == "CRITICAL"
    ).count()
    latest_log_usage = db.query(LogUsageHistory).order_by(desc(LogUsageHistory.recorded_at)).first()
    log_usage_pct = latest_log_usage.used_pct if latest_log_usage else None
    log_usage_color = "#B00020" if (log_usage_pct or 0) >= 95 else ("#F9A825" if (log_usage_pct or 0) >= 80 else "#eee")
    latest_docker_log_usage = db.query(DockerLogUsageHistory).order_by(desc(DockerLogUsageHistory.recorded_at)).first()
    docker_log_usage_pct = latest_docker_log_usage.used_pct if latest_docker_log_usage else None
    docker_log_usage_color = "#B00020" if (docker_log_usage_pct or 0) >= 95 else ("#F9A825" if (docker_log_usage_pct or 0) >= 80 else "#eee")
    latest_mem = db.query(MemoryUsageHistory).order_by(desc(MemoryUsageHistory.recorded_at)).first()
    mem_used_pct = latest_mem.used_pct if latest_mem else None
    mem_color = "#B00020" if (mem_used_pct or 0) >= 95 else ("#F9A825" if (mem_used_pct or 0) >= 90 else "#eee")

    # --- Faza 2: trendy SMART (7 dni) - sparkline SVG per dysk ---
    def _sparkline(values: list[int | None], width: int = 220, height: int = 36) -> str:
        """Minimalistyczny sparkline SVG (rysowany serwerowo, zero JS/CDN).
        None (brak odczytu) przerywa linie; ostatnia wartosc przy gornym skali zakresu -> pomaranczowy."""
        pts = [v for v in values if v is not None]
        if len(pts) < 2:
            return '<span style="color:#555;font-size:12px;">za mało danych</span>'
        lo, hi = min(pts), max(pts)
        span = (hi - lo) or 1
        n = len(values)
        d_parts = []
        prev_v = None
        for i, v in enumerate(values):
            x = 2 + i * (width - 4) / max(n - 1, 1)
            if v is None:
                prev_v = None
                continue
            y = height - 4 - (v - lo) * (height - 8) / span
            d_parts.append(("M" if prev_v is None else "L") + f"{x:.0f} {y:.0f}")
            prev_v = v
        color = "#888"
        if pts[-1] is not None and pts[-1] > 0 and lo >= 0 and lo + (hi - lo) * 0.8 <= pts[-1]:
            color = "#F9A825"
        d_attr = "".join(d_parts)
        return (
            '<svg width="' + str(width) + '" height="' + str(height) + '" style="vertical-align:middle;">'
            '<path d="' + d_attr + '" fill="none" stroke="' + color + '" stroke-width="1.5"/></svg>'
            '<span style="color:#999;font-size:11px;margin-left:6px;">' + str(pts[-1]) + '&nbsp;(min ' + str(lo) + ', max ' + str(hi) + ')</span>'
        )

    week_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    smart_devices = [
        r[0] for r in db.query(SmartAttrHistory.device).distinct().all()
    ]
    trends_html = ""
    for device in sorted(d or "" for d in smart_devices):
        hist = (
            db.query(SmartAttrHistory)
            .filter(SmartAttrHistory.device == device, SmartAttrHistory.recorded_at >= week_ago)
            .order_by(SmartAttrHistory.recorded_at)
            .all()
        )
        if not hist:
            continue
        temps = [h.temperature for h in hist]
        a197 = [h.attr_197 for h in hist]
        a199 = [h.attr_199 for h in hist]
        trend_color = "#B00020" if (a197 and any(v and v > 0 for v in a197)) else "#eee"
        trends_html += f"""
        <div class="trend-row">
          <div class="trend-dev">{device}</div>
          <div class="trend-cell"><div class="trend-label">Temperatura</div>{_sparkline(temps)}</div>
          <div class="trend-cell"><div class="trend-label">SMART 197 (pending)</div>{_sparkline(a197)}</div>
          <div class="trend-cell"><div class="trend-label">SMART 199 (UDMA CRC)</div>{_sparkline(a199)}</div>
          <div class="trend-flag" style="color:{trend_color};">{'&#9888; 197 > 0' if (a197 and any(v and v > 0 for v in a197)) else ''}</div>
        </div>"""
    # --- Faza 2: trend RAM hosta (24h) w tej samej sekcji ---
    day_ago_mem = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    mem_hist = (
        db.query(MemoryUsageHistory)
        .filter(MemoryUsageHistory.recorded_at >= day_ago_mem)
        .order_by(MemoryUsageHistory.recorded_at)
        .all()
    )
    if mem_hist:
        trends_html += f"""
        <div class="trend-row">
          <div class="trend-dev">RAM hosta</div>
          <div class="trend-cell"><div class="trend-label">Zajętość RAM (24h)</div>{_sparkline([m.used_pct for m in mem_hist])}</div>
          <div class="trend-flag" style="color:{mem_color};">{'&#9888; > 90%' if (mem_used_pct or 0) > 90 else ''}</div>
        </div>"""
    if not trends_html:
        trends_html = '<div style="color:#666;font-size:13px;">Brak danych SMART (kolektor jeszcze nie zebrał historii)</div>'
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
          <td style="padding:6px 10px;">{r.title} <a class="ai-link" href="/advise/{r.id}">🤖 Diagnoza AI</a></td>
          <td style="padding:6px 10px; color:#777; font-size:12px;">{r.status}</td>
        </tr>"""
        cards_html += f"""
        <div class="card">
          <div class="card-top">
            <span class="badge" style="background:{color};">{r.severity}</span>
            <span class="card-status">{r.status}</span>
          </div>
          <div class="card-title">{r.title}</div>
          <div class="card-meta">{r.category} &middot; {r.source or '-'} &middot; <a class="ai-link" href="/advise/{r.id}">🤖 Diagnoza AI</a></div>
          <div class="card-time">{ts}</div>
        </div>"""
    empty_msg = '<tr><td colspan="6" style="padding:20px; text-align:center; color:#666;">Brak incydentów — wszystko OK</td></tr>'
    empty_msg_mobile = '<div style="padding:20px; text-align:center; color:#666;">Brak incydentów — wszystko OK</div>'
    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
{_LOGO_HEAD}
<title>unRaid Security Center</title>
<meta http-equiv="refresh" content="30">
<style>
{_PAGE_STYLE}
  .stats {{ display:flex; flex-wrap:wrap; gap:16px; margin-bottom:24px; }}
  .stat {{ background:#1a1a1d; border-radius:8px; padding:16px 24px; flex:1 1 140px; }}
  .stat .num {{ font-size:28px; font-weight:700; }}
  .stat .label {{ color:#888; font-size:12px; text-transform:uppercase; }}
  .trends {{ background:#1a1a1d; border-radius:8px; padding:14px 16px; margin-bottom:24px; }}
  .trend-row {{ display:flex; align-items:center; gap:18px; padding:8px 0; border-bottom:1px solid #26262a; flex-wrap:wrap; }}
  .trend-row:last-child {{ border-bottom:none; }}
  .trend-dev {{ font-weight:600; min-width:90px; }}
  .trend-cell {{ flex:0 1 auto; }}
  .trend-label {{ color:#888; font-size:11px; text-transform:uppercase; margin-bottom:2px; }}
  .trend-flag {{ font-size:12px; font-weight:600; margin-left:auto; }}
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
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
  <div class="sub">Odświeża się co 30s</div>
  <div class="stats">
    <div class="stat"><div class="num" style="color:#B00020;">{crit_count}</div><div class="label">Krytyczne (nowe)</div></div>
    <div class="stat"><div class="num">{new_count}</div><div class="label">Nowe incydenty</div></div>
    <div class="stat"><div class="num">{len(rows)}</div><div class="label">Ostatnie 200</div></div>
    <div class="stat"><div class="num" style="color:{log_usage_color};">{log_usage_pct if log_usage_pct is not None else '?'}%</div><div class="label">Zajętość /var/log</div></div>
    <div class="stat"><div class="num" style="color:{docker_log_usage_color};">{docker_log_usage_pct if docker_log_usage_pct is not None else '?'}%</div><div class="label">Zajętość logów Docker</div></div>
    <div class="stat"><div class="num" style="color:{mem_color};">{mem_used_pct if mem_used_pct is not None else '?'}%</div><div class="label">RAM hosta unRAID</div></div>
  </div>
  <h2 style="font-size:15px;margin:8px 0 10px;">Trendy SMART (7 dni)</h2>
  <div class="trends">
    {trends_html}
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
{_LOGO_HEAD}
<title>USC - Ustawienia</title>
<style>
{_PAGE_STYLE}
  .banner {{ background:#1b3a1b; color:#9fdc9f; padding:10px 14px; border-radius:6px; margin-bottom:16px; font-size:13px; }}
  form {{ background:#1a1a1d; border-radius:8px; padding:20px; max-width:560px; }}
  label {{ display:block; font-size:12px; color:#999; text-transform:uppercase; margin:16px 0 6px; }}
  label:first-of-type {{ margin-top:0; }}
  input {{ width:100%; padding:10px 12px; border-radius:6px; border:1px solid #333; background:#111; color:#eee; font-size:14px; }}
  .hint {{ color:#666; font-size:12px; margin-top:4px; }}
  h2.sect {{ margin:24px 0 8px; font-size:15px; }}
  button {{ margin-top:20px; padding:10px 20px; border-radius:6px; border:none; background:#2a6ef0; color:#fff; font-size:14px; cursor:pointer; }}
</style></head>
<body>
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
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

    <h2 class="sect">API Agenta AI</h2>
    <div class="hint" style="margin:0 0 6px;">Dowolny endpoint kompatybilny z OpenAI (/chat/completions). Puste = doradca wyłączony. Dane incydentów (z redakcją sekretów) wychodzą do tego providera tylko po kliknięciu „Diagnoza AI".</div>
    <label>Base URL</label>
    <input name="ai_base_url" value="{s.get('ai_base_url') or ''}" placeholder="https://api.openai.com/v1">

    <label>Klucz API</label>
    <input name="ai_api_key" type="password" placeholder="{_mask(s.get('ai_api_key')) or 'sk-...'}">
    <div class="hint">Zostaw puste, żeby nie zmieniać obecnego klucza.</div>

    <label>Model</label>
    <input name="ai_model" value="{s.get('ai_model') or ''}" placeholder="gpt-4o-mini">

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
    ai_base_url: str = Form(""),
    ai_api_key: str = Form(""),
    ai_model: str = Form(""),
    db: Session = Depends(get_db), _=Depends(verify_admin),
):
    set_setting(db, "unraid_host", unraid_host.strip())
    if unraid_api_key.strip():
        set_setting(db, "unraid_api_key", unraid_api_key.strip())
    if telegram_bot_token.strip():
        set_setting(db, "telegram_bot_token", telegram_bot_token.strip())
    set_setting(db, "telegram_chat_id", telegram_chat_id.strip())
    set_setting(db, "ai_base_url", ai_base_url.strip())
    if ai_api_key.strip():
        set_setting(db, "ai_api_key", ai_api_key.strip())
    set_setting(db, "ai_model", ai_model.strip())
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
    usuwa wszystko: wpisy z <code>authorized_keys</code> na unRAID, klucz
    API i lokalne pliki kluczy — bez śmieci. Ponowne połączenie wymaga
    znowu wpisania hasła roota.
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
{_LOGO_HEAD}
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
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
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
{_LOGO_HEAD}
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
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
  {banner}
  {steps_html}
  <p style="margin-top:20px;"><a href="/settings">← Wróć do ustawień</a></p>
</body></html>"""
    return html


@app.post("/wizard/disconnect")
def wizard_disconnect(db: Session = Depends(get_db), _=Depends(verify_admin)):
    s = get_all_settings(db)
    host = s.get("unraid_host") or ""
    result = unraid_pair.unpair(host) if host else {"steps": []}
    set_setting(db, "unraid_host", "")
    set_setting(db, "unraid_api_key", "")

    steps_html = ""
    for step in result["steps"]:
        icon = "✅" if step["ok"] else "❌"
        steps_html += f"""<div class="wiz-step"><span class="wiz-icon">{icon}</span>
          <div><div class="wiz-name">{step['name']}</div><div class="wiz-detail">{step['detail']}</div></div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="pl"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
{_LOGO_HEAD}
<title>USC - Rozłączono</title>
<style>
{_PAGE_STYLE}
  .banner {{ padding:12px 16px; border-radius:6px; margin-bottom:16px; font-size:14px; }}
  .banner.ok {{ background:#1b3a1b; color:#9fdc9f; }}
  .wiz-step {{ display:flex; gap:12px; align-items:flex-start; background:#1a1a1d; border-radius:8px; padding:12px 14px; margin-bottom:8px; max-width:560px; }}
  .wiz-icon {{ font-size:18px; }}
  .wiz-name {{ font-size:14px; font-weight:600; }}
  .wiz-detail {{ font-size:12px; color:#999; margin-top:2px; }}
</style></head>
<body>
  <h1>{_LOGO_H1}</h1>
  <div class="nav"><a href="/">Dashboard</a><a href="/settings">Ustawienia</a><a href="/wizard">Połącz z unRAID</a><a href="/report/weekly/view">Raport tygodnia</a></div>
  <div class="banner ok">Rozłączono od {host or 'unRAID'}. Posprzątano wpisy w authorized_keys, klucz API i lokalne pliki kluczy.</div>
  {steps_html}
  <p style="margin-top:20px;"><a href="/wizard">← Wróć do parowania</a></p>
</body></html>"""
    return html
