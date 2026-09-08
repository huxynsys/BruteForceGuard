from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attack_session import AttackSession


def _to_naive_utc(value: datetime) -> datetime:
    """
    Normalize a datetime to naive UTC so comparisons never mix
    offset-aware and offset-naive values.

    PostgreSQL TIMESTAMPTZ returns offset-aware datetimes while SQLite
    returns naive ones; normalizing both sides keeps the service correct
    on either backend.
    """
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    return value


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

        timestamp = _to_naive_utc(
            event_timestamp or datetime.now(timezone.utc)
        )

        statement = select(AttackSession).where(
            AttackSession.session_type == session_type,
            AttackSession.status == "active",
        )

        sessions = list(self.db.scalars(statement))

        for session in sessions:

            # Check timeout using the event timeline.
            if session.last_seen_at:
                elapsed = (
                    timestamp - _to_naive_utc(session.last_seen_at)
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

    def find_session_by_correlation(
        self,
        key_fields: tuple[str, ...],
        source_ip: str | None = None,
        username: str | None = None,
        service: str | None = None,
        event_timestamp: datetime | None = None,
        timeout_seconds: int = 600,
    ):
        """
        Find an active session whose correlation key matches an alert.

        ``key_fields`` decides which dimensions MUST already exist on the
        session for the alert to belong to it (Section 5.10):

        * single-account / failed-success / low-and-slow -> ip + user + service
        * password-spray / credential-stuffing           -> ip + service
        * distributed                                     -> user + service

        Sessions that have been inactive beyond ``timeout_seconds`` on the
        event timeline are closed as a side effect and are not returned.
        """
        timestamp = _to_naive_utc(
            event_timestamp or datetime.now(timezone.utc)
        )

        statement = (
            select(AttackSession)
            .where(AttackSession.status == "active")
            .order_by(AttackSession.last_seen_at.desc())
        )

        sessions = list(self.db.scalars(statement))

        for session in sessions:

            # Timeout is checked on the event timeline, not wall-clock.
            if session.last_seen_at:
                elapsed = (
                    timestamp - _to_naive_utc(session.last_seen_at)
                ).total_seconds()

                if elapsed > timeout_seconds:
                    session.status = "closed"
                    continue

            matched = True

            for field in key_fields:
                if field == "source_ip":
                    if (
                        not source_ip
                        or not session.source_ips
                        or source_ip not in session.source_ips
                    ):
                        matched = False
                        break

                elif field == "username":
                    if (
                        not username
                        or not session.usernames
                        or username not in session.usernames
                    ):
                        matched = False
                        break

                elif field == "service":
                    if (
                        not service
                        or not session.services
                        or service not in session.services
                    ):
                        matched = False
                        break

            if matched:
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
        additional_source_ips: list[str] | None = None,
        additional_usernames: list[str] | None = None,
    ):
        """
        Create a new attack session using the authentication event timestamp.

        ``additional_source_ips`` / ``additional_usernames`` let the
        integration layer seed the session with the full scope of the
        detection (e.g. ALL source IPs of a distributed attack, or ALL
        affected accounts of a spray) instead of only the triggering
        event's single values.
        """

        source_ips = [source_ip] if source_ip else []

        for ip in additional_source_ips or []:
            if ip not in source_ips:
                source_ips.append(ip)

        usernames = [username] if username else []

        for user in additional_usernames or []:
            if user not in usernames:
                usernames.append(user)

        session = AttackSession(
            started_at=event_timestamp,
            last_seen_at=event_timestamp,
            session_type=session_type,
            severity=severity,
            event_count=1,
            source_ips=source_ips,
            usernames=usernames,
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
        additional_source_ips: list[str] | None = None,
        additional_usernames: list[str] | None = None,
    ):
        """
        Update an existing attack session with new evidence.

        ``additional_source_ips`` / ``additional_usernames`` let the
        integration layer merge the FULL scope of a detection (from the
        alert's evidence) into the session's maintained lists.
        """

        session.last_seen_at = max(
            _to_naive_utc(session.last_seen_at),
            _to_naive_utc(event_timestamp),
        )

        session.event_count += 1

        # NOTE: the JSONB list columns are plain (no MutableList tracking),
        # so every list mutation MUST be applied through reassignment —
        # in-place appends on a loaded list are silently not persisted.

        if source_ip:
            ips = list(session.source_ips or [])

            if source_ip not in ips:
                ips.append(source_ip)

            session.source_ips = ips

        if username:
            users = list(session.usernames or [])

            if username not in users:
                users.append(username)

            session.usernames = users

        if service:
            services = list(session.services or [])

            if service not in services:
                services.append(service)

            session.services = services

        if detection_type:
            types = list(session.detection_types or [])

            if detection_type not in types:
                types.append(detection_type)

            session.detection_types = types

        for ip in additional_source_ips or []:
            ips = list(session.source_ips or [])

            if ip and ip not in ips:
                ips.append(ip)
                session.source_ips = ips

        for user in additional_usernames or []:
            users = list(session.usernames or [])

            if user and user not in users:
                users.append(user)
                session.usernames = users

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

        now = _to_naive_utc(datetime.now(timezone.utc))

        statement = select(AttackSession).where(
            AttackSession.status == "active"
        )

        sessions = list(self.db.scalars(statement))

        closed_count = 0

        for session in sessions:

            if not session.last_seen_at:
                continue

            elapsed = (
                now - _to_naive_utc(session.last_seen_at)
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