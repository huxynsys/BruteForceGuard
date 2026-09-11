from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    alert_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    source_ip: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
        index=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    service: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=50,
    )

    evidence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
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

    threat_intelligence: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    source_reputation: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    mitre_context: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="open",
        index=True,
    )

    # Optional: Link to attack session
    session_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )