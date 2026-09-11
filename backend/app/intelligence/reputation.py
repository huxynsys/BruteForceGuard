"""Internal behavioral reputation (Phase 7, sections 7.8-7.9).

Builds a deterministic behavioural profile for a source IP from the
existing authentication events, alerts and attack sessions, and maps it
to an internal reputation score 0-100 with an explicit level.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intelligence.config import reputation_level_for_score
from app.intelligence.schemas import ReputationResult
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class ReputationService:

    def __init__(self, db: Session):
        self.db = db

    def _events_for(self, source_ip: str) -> list[AuthEvent]:
        statement = select(AuthEvent).where(
            AuthEvent.source_ip == source_ip,
        )
        return list(self.db.scalars(statement))

    def _alerts_for(self, source_ip: str) -> list[Alert]:
        statement = select(Alert).where(
            Alert.source_ip == source_ip,
        )
        return list(self.db.scalars(statement))

    def _sessions_for(self, source_ip: str) -> list[AttackSession]:
        sessions = list(
            self.db.scalars(
                select(AttackSession).where(AttackSession.status == "active"),
            )
        )
        return [s for s in sessions if source_ip in (s.source_ips or [])]

    def build_profile(self, source_ip: str) -> dict:
        """Behavioural profile of a source IP (section 7.9)."""
        events = self._events_for(source_ip)
        alerts = self._alerts_for(source_ip)
        sessions = self._sessions_for(source_ip)

        failures = [e for e in events if e.result == "failure"]
        successes = [e for e in events if e.result == "success"]
        total = len(events)

        failure_rate = (len(failures) / total) if total else None

        usernames = {e.username for e in events if e.username}
        services = {e.service for e in events if e.service}

        timestamps = [_aware(e.timestamp) for e in events if e.timestamp]
        timestamps = [t for t in timestamps if t is not None]

        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        return {
            "source_ip": source_ip,
            "failure_rate": failure_rate,
            "failure_count": len(failures),
            "success_count": len(successes),
            "unique_usernames": len(usernames),
            "unique_services": len(services),
            "attack_sessions": len(sessions),
            "alert_count": len(alerts),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

    def reputation_score(self, profile: dict) -> int:
        """Deterministic internal-reputation score (0-100)."""
        score = 0

        score += min(20, profile["alert_count"] * 4)
        score += min(20, profile["attack_sessions"] * 5)
        score += min(10, profile["unique_usernames"] * 2)
        score += min(10, profile["unique_services"] * 3)

        failure_rate = profile.get("failure_rate")
        if failure_rate is not None:
            score += round(min(20, failure_rate * 20))

        last_seen = profile.get("last_seen")
        if last_seen is not None:
            recency = datetime.now(timezone.utc) - last_seen
            if recency <= timedelta(hours=1):
                score += 10
            elif recency <= timedelta(hours=24):
                score += 5

        return max(0, min(100, score))

    def get_reputation(self, source_ip: str) -> ReputationResult:
        profile = self.build_profile(source_ip)
        score = self.reputation_score(profile)

        return ReputationResult(
            source_ip=source_ip,
            internal_reputation_score=score,
            internal_reputation_level=reputation_level_for_score(score),
            failure_rate=profile["failure_rate"],
            unique_usernames=profile["unique_usernames"],
            unique_services=profile["unique_services"],
            attack_sessions=profile["attack_sessions"],
            alert_count=profile["alert_count"],
            first_seen=profile["first_seen"],
            last_seen=profile["last_seen"],
        )