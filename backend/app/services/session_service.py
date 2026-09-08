from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack_session import AttackSession


class SessionService:

    def __init__(self, db: Session):
        self.db = db

    def find_active_session(
        self,
        session_type: str,
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
        event_timestamp: datetime | None = None,
        timeout_seconds: int = 600,
    ):
        """
        Find an active attack session that matches the current attack
        and is still within the configured timeout window.
        """

        timestamp = event_timestamp or datetime.now().astimezone()

        statement = select(AttackSession).where(
            AttackSession.session_type == session_type,
            AttackSession.status == "active",
        )

        sessions = list(self.db.scalars(statement))

        for session in sessions:

            # Check timeout using the event timeline.
            if session.last_seen_at:
                elapsed = (
                    timestamp - session.last_seen_at
                ).total_seconds()

                if elapsed > timeout_seconds:
                    session.status = "closed"
                    continue

            # Match source IP when provided.
            if source_ip is not None:
                if not session.source_ips or source_ip not in session.source_ips:
                    continue

            # Match username when provided.
            if username is not None:
                if not session.usernames or username not in session.usernames:
                    continue

            # Match service when provided.
            if service is not None:
                if not session.services or service not in session.services:
                    continue

            self.db.commit()
            return session

        self.db.commit()
        return None

    def create_session(
        self,
        session_type: str,
        severity: str,
        event_timestamp: datetime,
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
        detection_type: str | None = None,
    ):
        """
        Create a new attack session using the authentication event timestamp.
        """

        session = AttackSession(
            started_at=event_timestamp,
            last_seen_at=event_timestamp,
            session_type=session_type,
            severity=severity,
            event_count=1,
            source_ips=[source_ip] if source_ip else [],
            usernames=[username] if username else [],
            services=[service] if service else [],
            detection_types=[detection_type] if detection_type else [],
            status="active",
        )

        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)

        return session

    def update_session(
        self,
        session: AttackSession,
        event_timestamp: datetime,
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
        detection_type: str | None = None,
        severity: str | None = None,
    ):
        """
        Update an existing attack session with new evidence.
        """

        session.last_seen_at = max(
            session.last_seen_at,
            event_timestamp,
        )

        session.event_count += 1

        if source_ip:
            if not session.source_ips:
                session.source_ips = []

            if source_ip not in session.source_ips:
                session.source_ips.append(source_ip)

        if username:
            if not session.usernames:
                session.usernames = []

            if username not in session.usernames:
                session.usernames.append(username)

        if service:
            if not session.services:
                session.services = []

            if service not in session.services:
                session.services.append(service)

        if detection_type:
            if not session.detection_types:
                session.detection_types = []

            if detection_type not in session.detection_types:
                session.detection_types.append(detection_type)

        if severity:
            severity_rank = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
            }

            current_rank = severity_rank.get(
                session.severity,
                0,
            )

            new_rank = severity_rank.get(
                severity,
                0,
            )

            if new_rank > current_rank:
                session.severity = severity

        self.db.commit()
        self.db.refresh(session)

        return session

    def close_session(
        self,
        session: AttackSession,
    ):
        """
        Manually close an attack session.
        """

        session.status = "closed"

        self.db.commit()
        self.db.refresh(session)

        return session

    def close_inactive_sessions(
        self,
        timeout_seconds: int = 600,
    ):
        """
        Close active sessions that have been inactive for too long.
        """

        now = datetime.now().astimezone()

        statement = select(AttackSession).where(
            AttackSession.status == "active"
        )

        sessions = list(self.db.scalars(statement))

        closed_count = 0

        for session in sessions:

            if not session.last_seen_at:
                continue

            elapsed = (
                now - session.last_seen_at
            ).total_seconds()

            if elapsed > timeout_seconds:
                session.status = "closed"
                closed_count += 1

        self.db.commit()

        return closed_count

    def get_session_stats(self):
        """
        Return basic attack-session statistics.
        """

        statement = select(AttackSession).where(
            AttackSession.status == "active"
        )

        sessions = list(self.db.scalars(statement))

        unique_ips = set()
        unique_users = set()

        total_events = 0

        for session in sessions:

            total_events += session.event_count

            if session.source_ips:
                unique_ips.update(session.source_ips)

            if session.usernames:
                unique_users.update(session.usernames)

        return {
            "active_sessions": len(sessions),
            "total_events": total_events,
            "unique_source_ips": len(unique_ips),
            "unique_usernames": len(unique_users),
        }