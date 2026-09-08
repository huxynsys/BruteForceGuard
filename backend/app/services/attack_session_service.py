import logging

from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.services.session_service import SessionService

logger = logging.getLogger(__name__)

#: Per-attack-type session correlation keys (Phase 5, Section 5.10).
#: A new alert belongs to an active session only when every field in its
#: key already exists on that session.  This lets one real-world attack
#: (e.g. 10 failures + a success) accumulate multiple detection signals
#: in a single attack session, while keeping genuinely distinct attacks
#: (e.g. a password spray and a distributed attack on another account)
#: in separate sessions.
CORRELATION_KEYS = {
    "single_account": ("source_ip", "username", "service"),
    "password_spray": ("source_ip", "service"),
    "distributed": ("username", "service"),
    "failed_success": ("source_ip", "username", "service"),
    "credential_stuffing": ("source_ip", "service"),
    "low_and_slow": ("source_ip", "username", "service"),
}


class AttackSessionIntegrationService:

    def __init__(self, db: Session):
        self.db = db
        self.session_service = SessionService(db)

    def process_alert(
        self,
        event: AuthEvent,
        alert: Alert,
        detection_type: str,
    ):
        """
        Connect a detection alert to an attack session.

        Flow: alert -> map to correlation key -> find active session
        -> update when found, otherwise create.
        """

        session_type = detection_type

        key_fields = CORRELATION_KEYS.get(
            detection_type,
            ("source_ip", "username", "service"),
        )

        source_ip = (
            str(event.source_ip)
            if event.source_ip
            else None
        )

        username = event.username

        service = event.service

        # Seed/merge the session with the FULL scope of the detection from
        # the alert's evidence — e.g. ALL affected accounts of a spray or
        # ALL source IPs of a distributed attack — instead of only the
        # triggering event's single values (Sections 5.19 / 5.21).
        evidence = alert.evidence or {}

        additional_source_ips = [
            str(ip) for ip in (evidence.get("source_ips") or [])
        ]

        additional_usernames = [
            str(user) for user in (evidence.get("usernames") or [])
        ]

        session = self.session_service.find_session_by_correlation(
            key_fields=key_fields,
            source_ip=source_ip,
            username=username,
            service=service,
            event_timestamp=event.timestamp,
            timeout_seconds=600,
        )

        if session:

            logger.info(
                "Attack session %s updated: type=%s detection=%s",
                session.id,
                session_type,
                detection_type,
            )

            return self.session_service.update_session(
                session=session,
                event_timestamp=event.timestamp,
                source_ip=source_ip,
                username=username,
                service=service,
                detection_type=detection_type,
                severity=alert.severity,
                additional_source_ips=additional_source_ips,
                additional_usernames=additional_usernames,
            )

        logger.info(
            "Attack session created: type=%s detection=%s",
            session_type,
            detection_type,
        )

        return self.session_service.create_session(
            session_type=session_type,
            severity=alert.severity,
            event_timestamp=event.timestamp,
            source_ip=source_ip,
            username=username,
            service=service,
            detection_type=detection_type,
            additional_source_ips=additional_source_ips,
            additional_usernames=additional_usernames,
        )