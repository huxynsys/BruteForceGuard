from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AttackSession(Base):
    __tablename__ = "attack_sessions"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    session_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    source_ips: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
    )

    usernames: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
    )

    services: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
    )

    detection_types: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
        default=list,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        index=True,
    )

    # Phase 7 intelligence enrichment
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="informational",
    )

    risk_factors: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    behavioral_profile: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )