"""Storage layer for threat indicators (Phase 7, section 7.6)."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intelligence.schemas import ThreatIndicatorCreate
from app.models.threat_indicator import ThreatIndicator


def _naive_or_aware(value: datetime | None, fallback: datetime) -> datetime:
    if value is None:
        return fallback
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class ThreatIndicatorRepository:

    def __init__(self, db: Session):
        self.db = db

    def create(self, data: ThreatIndicatorCreate) -> ThreatIndicator:
        indicator = ThreatIndicator(
            indicator=data.indicator.strip().lower(),
            indicator_type=data.indicator_type,
            confidence=data.confidence,
            threat_type=data.threat_type,
            source=data.source,
            tags=list(data.tags),
            active=data.active,
        )
        self.db.add(indicator)
        self.db.commit()
        self.db.refresh(indicator)
        return indicator

    def get(self, indicator_id: int) -> ThreatIndicator | None:
        return self.db.get(ThreatIndicator, indicator_id)

    def list_indicators(
        self,
        *,
        indicator_type: Optional[str] = None,
        active_only: bool = False,
        limit: int = 100,
    ) -> list[ThreatIndicator]:
        statement = select(ThreatIndicator).order_by(
            ThreatIndicator.created_at.desc(),
        ).limit(limit)

        if indicator_type:
            statement = statement.where(
                ThreatIndicator.indicator_type == indicator_type,
            )
        if active_only:
            statement = statement.where(ThreatIndicator.active.is_(True))

        return list(self.db.scalars(statement))

    def find_active(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIndicator | None:
        """Find an active indicator matching exactly (case-insensitive)."""
        statement = select(ThreatIndicator).where(
            ThreatIndicator.indicator == indicator.strip().lower(),
            ThreatIndicator.indicator_type == indicator_type,
            ThreatIndicator.active.is_(True),
        )
        return self.db.scalar(statement)

    def delete(self, indicator_id: int) -> bool:
        indicator = self.db.get(ThreatIndicator, indicator_id)
        if not indicator:
            return False
        self.db.delete(indicator)
        self.db.commit()
        return True

    def record_observation(self, indicator_id: int) -> None:
        """Update last_seen when an indicator is observed in the wild."""
        indicator = self.db.get(ThreatIndicator, indicator_id)
        if not indicator:
            return
        now = datetime.now(timezone.utc)
        indicator.last_seen = _naive_or_aware(indicator.last_seen, now)
        self.db.commit()