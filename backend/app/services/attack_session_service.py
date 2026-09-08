from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.services.session_service import SessionService


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
        """

        session_type = detection_type

        source_ip = (
            str(event.source_ip)
            if event.source_ip
            else None
        )

        username = event.username

        service = event.service

        session = self.session_service.find_active_session(
            session_type=session_type,
            source_ip=source_ip,
            username=username,
            service=service,
            event_timestamp=event.timestamp,
            timeout_seconds=600,
        )

        if session:

            return self.session_service.update_session(
                session=session,
                event_timestamp=event.timestamp,
                source_ip=source_ip,
                username=username,
                service=service,
                detection_type=detection_type,
                severity=alert.severity,
            )

        return self.session_service.create_session(
            session_type=session_type,
            severity=alert.severity,
            event_timestamp=event.timestamp,
            source_ip=source_ip,
            username=username,
            service=service,
            detection_type=detection_type,
        )