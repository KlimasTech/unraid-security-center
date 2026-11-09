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


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
