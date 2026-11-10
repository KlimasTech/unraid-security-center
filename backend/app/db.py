"""USC - warstwa bazy danych (SQLAlchemy + PostgreSQL)."""
import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get(
    "USC_DATABASE_URL",
    "postgresql://usc:usc@usc-postgres:5432/usc",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Incident(Base):
    """Jeden wykryty incydent/zdarzenie po przejściu przez silnik reguł."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    severity = Column(String(16), index=True)  # INFO, WARNING, ERROR, CRITICAL
    category = Column(String(64), index=True)  # smart, parity, docker, vm, disk_space, kernel...
    source = Column(String(128))  # np. nazwa dysku, nazwa kontenera
    rule_id = Column(String(64))  # identyfikator reguły ktora wykryla
    title = Column(String(256))
    detail = Column(Text)
    raw = Column(Text)  # surowe dane z kolektora (JSON jako tekst)
    status = Column(String(16), default="NEW")  # NEW, ACKNOWLEDGED, RESOLVED
    notified = Column(Boolean, default=False)


class DiskHistory(Base):
    """Historia stanu dysków per urządzenie - do analizy trendu numErrors.

    UWAGA: GraphQL API unRAID 7.3 NIE eksportuje surowych atrybutów SMART
    (5/187/188/197/198/199) - tylko gotowe flagi `warning`/`critical`
    (wyliczone przez samego unRAID) oraz licznik `numErrors`. Granularna
    analiza atrybutów SMART per-attribute wymagałaby osobnego kolektora
    SSH + smartctl (Faza 2, nie w tym MVP).
    """

    __tablename__ = "disk_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    device = Column(String(64), index=True)
    status = Column(String(32), nullable=True)
    warning = Column(Boolean, nullable=True)
    critical = Column(Boolean, nullable=True)
    num_errors = Column(Integer, nullable=True)
    temperature = Column(Integer, nullable=True)


class SmartAttrHistory(Base):
    """Historia granularnych atrybutow SMART per dysk (Faza 2).

    Pobierane przez SSH + smartctl (GraphQL unRAID tego nie udostepnia).
    attr_5/187/188/197/198/199 dla ATA; nvme_media_errors/nvme_critical_warning
    dla NVMe (inny schemat, brak klasycznych numerowanych atrybutow).
    """

    __tablename__ = "smart_attr_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    device = Column(String(64), index=True)
    model = Column(String(128), nullable=True)
    attr_5 = Column(Integer, nullable=True)
    attr_187 = Column(Integer, nullable=True)
    attr_188 = Column(Integer, nullable=True)
    attr_197 = Column(Integer, nullable=True)
    attr_198 = Column(Integer, nullable=True)
    attr_199 = Column(Integer, nullable=True)
    nvme_media_errors = Column(Integer, nullable=True)
    nvme_critical_warning = Column(Integer, nullable=True)
    temperature = Column(Integer, nullable=True)


class DockerHealthHistory(Base):
    """Historia zdrowia kontenerow (restart_count/oom_killed/health_status).

    Pobierane przez SSH + docker inspect (plugin USC) - GraphQL unRAID
    udostepnia tylko state/status/autoStart, nie RestartCount/OOMKilled/Health.
    """

    __tablename__ = "docker_health_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    name = Column(String(128), index=True)
    restart_count = Column(Integer, nullable=True)
    oom_killed = Column(Boolean, nullable=True)
    health_status = Column(String(32), nullable=True)
    state = Column(String(32), nullable=True)


class VmHealthHistory(Base):
    """Historia stanu maszyn wirtualnych (libvirt/QEMU) - do wykrywania
    nieoczekiwanych przejsc stanu (running -> paused/crashed)."""

    __tablename__ = "vm_health_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    name = Column(String(128), index=True)
    state = Column(String(32), nullable=True)


class LogUsageHistory(Base):
    """Zajetosc /var/log na unRAID (tmpfs, zwykle 128MB) - zapelnienie
    zatrzymuje logowanie i moze destabilizowac uslugi."""

    __tablename__ = "log_usage_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    used_pct = Column(Integer, nullable=True)
    used_bytes = Column(Integer, nullable=True)
    total_bytes = Column(Integer, nullable=True)


class DockerLogUsageHistory(Base):
    """Zajetosc logow kontenerow Docker (*-json.log) wzgledem teoretycznego
    limitu z polityki rotacji docker.cfg (DOCKER_LOG_SIZE x DOCKER_LOG_FILES
    x liczba kontenerow) - unRAID nie udostepnia gotowej wartosci."""

    __tablename__ = "docker_log_usage_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    used_pct = Column(Integer, nullable=True)
    used_bytes = Column(Integer, nullable=True)
    max_bytes = Column(Integer, nullable=True)
    container_count = Column(Integer, nullable=True)


class SyslogLine(Base):
    """Surowe linie syslogu unRAID (tail na zywo + syslog-previous).

    Przechowywane TYLKO na potrzeby korelacji wielomodulowej (Faza 2) -
    np. licznik resetow linku SATA jako poswiadczenie dla rosnacego
    SMART 199 (UDMA CRC). Nie sa zadnym incydentem samym w sobie;
    interaktywna przegladarka logow celowo NIE jest budowana na tych
    danych (prune do 48h, brak indeksow full-text - to nie ELK).
    """

    __tablename__ = "syslog_lines"

    id = Column(Integer, primary_key=True, index=True)
    received_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    line = Column(Text)
    # Pochodna: linia wyglada na reset linku SATA (kernel ata). Liczona
    # przy zapisie (rules.is_sata_reset_line), zeby korelacja SMART 199
    # mogla policzyc resetow prostym COUNT po zaindeksowanej fladze,
    # zamiast regexa po Text w SQL przy KAZdym ingescie SMART.
    is_sata_reset = Column(Boolean, default=False, index=True)


class MemoryUsageHistory(Base):
    """Zajetosc RAM hosta unRAID (MemTotal/MemAvailable z free -m) -
    poswiadczenie dla korelacji OOM kontenera (skok zuzycia RAM hosta
    w momencie zabicia kontenera = rzeczywisty brak pamieci, prawdopodobny
    wyciek pamieci w kontenerze), zamiast trzech oderwanych alertow."""

    __tablename__ = "memory_usage_history"

    id = Column(Integer, primary_key=True, index=True)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    total_mb = Column(Integer, nullable=True)
    available_mb = Column(Integer, nullable=True)
    used_pct = Column(Integer, nullable=True)


class Advisory(Base):
    """Diagnoza AI-doradcy (Faza 3) powiazana z incydentem.

    Cache: po jednym kliknieciu 'Diagnoza AI' koszt nie jest ponawiany
    dla tego samego incydentu (odswiezenie wymaga jawnego 'regenerate').
    Raport tygodniowy: incident_id = NULL, kind = 'weekly_report'.
    Doradca NIGDY nic nie wykonuje - to tylko wygenerowany tekst."""

    __tablename__ = "advisories"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    incident_id = Column(Integer, nullable=True, index=True)
    kind = Column(String(32), default="incident")  # incident | weekly_report
    result_json = Column(Text)  # pelna odpowiedz doradcy (JSON jako tekst)
    error = Column(Text, nullable=True)  # niepowodzenie (konfiguracja/provider)


class Setting(Base):
    """Ustawienia konfigurowalne z panelu (nie z .env) - np. host unRAID,
    klucz API, token/chat Telegram. Prostzy key-value store."""

    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=True)


# Klucze ustawien zarzadzanych przez panel (nie przez zmienne env kontenerow)
SETTING_KEYS = [
    "unraid_host",
    "unraid_api_key",
    "telegram_bot_token",
    "telegram_chat_id",
    "ai_base_url",
    "ai_api_key",
    "ai_model",
]


def get_ai_settings(db) -> dict[str, str | None]:
    """Ustawienia 'API Agenta AI' (Faza 3) - osobno od glownych, bo uzywane
    tylko przez modul ai_advisor i ustawiane w panelu w dedykowanej sekcji."""
    keys = ["ai_base_url", "ai_api_key", "ai_model"]
    rows = db.query(Setting).filter(Setting.key.in_(keys)).all()
    values = {r.key: r.value for r in rows}
    return {k: values.get(k) for k in keys}


def get_setting(db, key: str, default: str | None = None) -> str | None:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else default


def get_all_settings(db) -> dict[str, str | None]:
    rows = db.query(Setting).filter(Setting.key.in_(SETTING_KEYS)).all()
    values = {r.key: r.value for r in rows}
    return {k: values.get(k) for k in SETTING_KEYS}


def set_setting(db, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def seed_settings_from_env(db) -> None:
    """Jednorazowe seedowanie ustawien z env (migracja z poprzedniej wersji
    opartej na .env) - TYLKO jesli w bazie jeszcze nic nie ma dla danego
    klucza. Nigdy nie nadpisuje juz ustawionej wartosci z panelu."""
    env_map = {
        "unraid_host": "USC_SEED_UNRAID_HOST",
        "unraid_api_key": "USC_SEED_UNRAID_API_KEY",
        "telegram_bot_token": "USC_SEED_TELEGRAM_BOT_TOKEN",
        "telegram_chat_id": "USC_SEED_TELEGRAM_CHAT_ID",
    }
    for key, env_name in env_map.items():
        existing = db.query(Setting).filter(Setting.key == key).first()
        if existing is None:
            env_val = os.environ.get(env_name)
            if env_val:
                db.add(Setting(key=key, value=env_val))
    db.commit()


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
