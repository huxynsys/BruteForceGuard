from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.schemas.auth_event import AuthEventCreate


def create_auth_event(
    db: Session,
    event_data: AuthEventCreate,
) -> AuthEvent:

    event = AuthEvent(
        timestamp=event_data.timestamp,
        source=event_data.source,
        source_ip=str(event_data.source_ip),
        destination_ip=(
            str(event_data.destination_ip)
            if event_data.destination_ip
            else None
        ),
        username=event_data.username,
        result=event_data.result.value,
        service=event_data.service,
        port=event_data.port,
        hostname=event_data.hostname,
        user_agent=event_data.user_agent,
        event_id=event_data.event_id,
        raw_event=event_data.raw_event,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event