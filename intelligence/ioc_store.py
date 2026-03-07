"""
intelligence/ioc_store.py — Juwan CTI v3.0
SQLAlchemy models: ioc_events + campaigns (PostgreSQL via Docker)
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    create_engine, Column, String, Float, Integer,
    DateTime, JSON, ForeignKey, Text, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from config import settings
from logger import get_logger

logger = get_logger(__name__)

Base = declarative_base()


# ─────────────────────────────────────────────────────────────────────
# ORM Models
# ─────────────────────────────────────────────────────────────────────

class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    victim_count = Column(Integer, default=0)
    channels = Column(JSON, default=list)     # ["email", "url", ...]
    ttps = Column(JSON, default=list)         # ["T1566.001", ...]
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IOCEvent(Base):
    __tablename__ = "ioc_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    artifact_id = Column(String(36), nullable=False, index=True)
    channel = Column(String(32), nullable=False)        # email|url|chat|voice|image|ensemble
    threat_level = Column(String(16), nullable=False)   # HIGH|MEDIUM|LOW
    confidence = Column(Float, nullable=False)
    prediction = Column(String(32), nullable=False)
    indicators = Column(JSON, default=list)
    indicator_weights = Column(JSON, default=dict)
    raw_input = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id"), nullable=True, index=True)

    __table_args__ = (
        Index("ix_ioc_channel_ts", "channel", "timestamp"),
        Index("ix_ioc_threat_ts", "threat_level", "timestamp"),
    )


# ─────────────────────────────────────────────────────────────────────
# Engine & Session
# ─────────────────────────────────────────────────────────────────────

_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings.DATABASE_SYNC_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
        logger.info("PostgreSQL engine initialised")
    return _engine


def get_session() -> Session:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionLocal()


def init_db():
    """Create all tables (run once on startup or via Alembic migrations)."""
    try:
        Base.metadata.create_all(bind=get_engine())
        logger.info("IOC store tables ready")
    except Exception as e:
        logger.warning(f"init_db warning: {e}")


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────

def log_ioc_event(
    artifact_id: str,
    channel: str,
    threat_level: str,
    confidence: float,
    prediction: str,
    indicators: list,
    indicator_weights: dict,
    raw_input: Optional[str] = None,
    campaign_id: Optional[str] = None,
) -> Optional[str]:
    """
    Write a single IOC event record to PostgreSQL.
    Returns the new event ID or None if the write fails.
    Never raises — DB failure must never break detection responses.
    """
    try:
        with get_session() as session:
            event = IOCEvent(
                artifact_id=artifact_id,
                channel=channel,
                threat_level=threat_level,
                confidence=confidence,
                prediction=prediction,
                indicators=indicators,
                indicator_weights=indicator_weights,
                raw_input=(raw_input or "")[:2000],  # cap stored raw input
                campaign_id=campaign_id,
            )
            session.add(event)
            session.commit()
            logger.debug(f"IOC event logged: {event.id} [{channel}] {threat_level}")
            return event.id
    except Exception as e:
        logger.warning(f"IOC write failed (non-fatal): {e}")
        return None


def get_recent_ioc_events(hours: int = 24) -> list:
    """Fetch IOC events from the last N hours for campaign clustering."""
    try:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        with get_session() as session:
            events = (
                session.query(IOCEvent)
                .filter(IOCEvent.timestamp >= cutoff)
                .order_by(IOCEvent.timestamp.desc())
                .all()
            )
            return events
    except Exception as e:
        logger.warning(f"get_recent_ioc_events failed: {e}")
        return []


def update_event_campaign(event_id: str, campaign_id: str) -> bool:
    """Assign a campaign_id FK to an existing IOC event."""
    try:
        with get_session() as session:
            event = session.query(IOCEvent).filter_by(id=event_id).first()
            if event:
                event.campaign_id = campaign_id
                session.commit()
                return True
        return False
    except Exception as e:
        logger.warning(f"update_event_campaign failed: {e}")
        return False
