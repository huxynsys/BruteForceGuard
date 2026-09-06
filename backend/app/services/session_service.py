from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent


class SessionService:

    def __init__(self, db: Session):
        self.db = db

    def find_active_session(
        self,
        session_type: str,
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
        timeout_seconds: int = 600,
    ):
        """Find an active session matching the criteria."""
        cutoff_time = datetime.now().astimezone() - timedelta(seconds=timeout_seconds)

        statement = select(AttackSession).where(
            AttackSession.session_type == session_type,
            AttackSession.status == "active",
            AttackSession.last_seen_at >= cutoff_time,
        )

        if source_ip:
            statement = statement.where(
                AttackSession.source_ips.contains([source_ip])
            )

        if username:
            statement = statement.where(
                AttackSession.usernames.contains([username])
            )

        if service:
            statement = statement.where(
                AttackSession.services.contains([service])
            )

        return self.db.scalar(statement)

    def create_session(
        self,
        session_type: str,
        severity: str,
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
    ):
        """Create a new attack session."""
        session = AttackSession(
            started_at=datetime.now().astimezone(),
            last_seen_at=datetime.now().astimezone(),
            session_type=session_type,
            severity=severity,
            event_count=1,
            source_ips=[source_ip] if source_ip else [],
            usernames=[username] if username else [],
            services=[service] if service else [],
            detection_types=[session_type],
            status="active",
        )

        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        return session

    def update_session(
        self,
        session: AttackSession,
        event: AuthEvent,
    ):
        """Update an existing session with new event data."""
        session.last_seen_at = datetime.now().astimezone()
        session.event_count += 1

        # Add source IP if not already present
        source_ip = str(event.source_ip)
        if source_ip and source_ip not in (session.source_ips or []):
            if session.source_ips is None:
                session.source_ips = []
            session.source_ips.append(source_ip)

        # Add username if not already present
        if event.username and event.username not in (session.usernames or []):
            if session.usernames is None:
                session.usernames = []
            session.usernames.append(event.username)

        # Add service if not already present
        if event.service and event.service not in (session.services or []):
            if session.services is None:
                session.services = []
            session.services.append(event.service)

        self.db.commit()

        return session

    def close_session(self, session: AttackSession):
        """Close an attack session."""
        session.status = "closed"
        self.db.commit()
        return session

    def close_inactive_sessions(self, timeout_seconds: int = 600):
        """Close sessions that have been inactive for too long."""
        cutoff_time = datetime.now().astimezone() - timedelta(seconds=timeout_seconds)

        statement = select(AttackSession).where(
            AttackSession.status == "active",
            AttackSession.last_seen_at < cutoff_time,
        )

        sessions = list(self.db.scalars(statement))

        for session in sessions:
            session.status = "closed"

        self.db.commit()

        return len(sessions)

    def get_session_stats(self, session: AttackSession):
        """Get statistics for a session."""
        return {
            "id": session.id,
            "started_at": session.started_at.isoformat(),
            "last_seen_at": session.last_seen_at.isoformat(),
            "duration_seconds": (
                session.last_seen_at - session.started_at
            ).total_seconds(),
            "event_count": session.event_count,
            "source_ips": session.source_ips or [],
            "usernames": session.usernames or [],
            "services": session.services or [],
            "detection_types": session.detection_types or [],
            "status": session.status,
        }