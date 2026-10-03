from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
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

    # Last lifecycle transition snapshot (the full audit trail lives in
    # ``AlertStatusHistory``).  NULL until the alert is first triaged.
    status_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    status_updated_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    #: Optional analyst-supplied reason for the last transition (recorded for
    #: closure decisions such as resolved / false positive).
    status_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Optional: Link to attack session
    session_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )


class AlertStatusHistory(Base):
    """One row per lifecycle transition (the alert's audit trail).

    Records *who* moved *which* alert *from* one status *to* another, *when*,
    and *why* (optional ``reason``).  Rows are never updated or deleted with
    the alert's current status - they are append-only evidence.
    """

    __tablename__ = "alert_status_history"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    alert_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    from_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    to_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    changed_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    changed_by_role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )