"""Threat indicator database model (Phase 7, section 7.21)."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base

VALID_INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "username")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    indicator: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Confidence that this indicator is genuinely malicious (1-100).
    confidence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=50,
    )

    threat_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="manual",
    )

    tags: Mapped[list | None] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )