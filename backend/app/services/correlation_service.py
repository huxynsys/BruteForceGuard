from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent


class CorrelationService:

    def __init__(self, db: Session):
        self.db = db

    def get_related_events(
        self,
        event: AuthEvent,
        window_seconds: int = 600,
    ):
        """Get all events within a time window."""
        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
        )

        return list(self.db.scalars(statement))

    def get_events_by_source_ip(
        self,
        source_ip: str,
        timestamp: datetime,
        window_seconds: int = 600,
    ):
        """Get all events from a specific source IP."""
        start_time = timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.source_ip == source_ip,
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= timestamp,
        )

        return list(self.db.scalars(statement))

    def get_events_by_username(
        self,
        username: str,
        timestamp: datetime,
        window_seconds: int = 600,
    ):
        """Get all events targeting a specific username."""
        start_time = timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.username == username,
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= timestamp,
        )

        return list(self.db.scalars(statement))

    def correlate_attack_patterns(
        self,
        events: list[AuthEvent],
    ):
        """Analyze a set of events for attack patterns."""
        if not events:
            return {}

        sources = {str(e.source_ip) for e in events}
        usernames = {e.username for e in events if e.username}
        services = {e.service for e in events if e.service}

        failures = sum(1 for e in events if e.result == "failure")
        successes = sum(1 for e in events if e.result == "success")

        return {
            "total_events": len(events),
            "distinct_source_ips": len(sources),
            "distinct_usernames": len(usernames),
            "distinct_services": len(services),
            "failure_count": failures,
            "success_count": successes,
            "source_ips": sorted(sources),
            "usernames": sorted(usernames)[:20],
            "services": sorted(services),
        }

    def find_related_alerts(
        self,
        event: AuthEvent,
        window_seconds: int = 600,
    ):
        """Find existing alerts related to an event."""
        from app.models.alert import Alert

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(Alert).where(
            Alert.created_at >= start_time,
            Alert.created_at <= event.timestamp,
            Alert.status == "open",
        )

        return list(self.db.scalars(statement))