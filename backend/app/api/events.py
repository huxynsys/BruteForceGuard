import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.auth_event import (
    AuthEventCreate,
    AuthEventResponse,
    EventGroupPage,
)
from app.services.event_service import EventService

from app.services.detection_service import DetectionService
from app.services.detection_engine import DetectionEngine
from app.services.attack_session_service import (
    AttackSessionIntegrationService,
)
from app.intelligence.service import IntelligenceService  # Phase 7

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
)


@router.post("/", response_model=AuthEventResponse)
def create_event(
    event_data: AuthEventCreate,
    db: Session = Depends(get_db),
):
    """Create an authentication event and run detection."""

    # 1. Initialize event service
    event_service = EventService(db)

    # 2. Create the authentication event
    new_event = event_service.create_event(event_data)

    logger.info(
        "Authentication event accepted: id=%s result=%s service=%s username=%s source_ip=%s",
        new_event.id,
        new_event.result,
        new_event.service,
        new_event.username,
        new_event.source_ip,
    )

    # 3. Initialize detection service
    detection_service = DetectionService(db)

    session_integration_service = AttackSessionIntegrationService(db)

    # Phase 7: security-intelligence enrichment (best-effort, never fatal)
    intelligence_service = IntelligenceService(db)

    # 4. Run the configured independent rules. Detector failures remain
    # isolated inside the engine and never prevent event ingestion.
    detection_results = DetectionEngine(detection_service).run(new_event)
    for result in detection_results:
        try:
            logger.info(
                "Detection triggered: rule_id=%s type=%s event_id=%s",
                result.rule_id,
                result.detection_type,
                new_event.id,
            )

            # Phase 7: enrich alert with risk / intel / MITRE context.
            intelligence_service.enrich_alert(alert=result.alert, event=new_event)

            session = session_integration_service.process_alert(
                event=new_event,
                alert=result.alert,
                detection_type=result.session_detection_type,
            )

            # Phase 7: aggregate intelligence onto the attack session.
            if session is not None:
                intelligence_service.enrich_session(session)
        except Exception:
            logger.exception(
                "Detection result processing failed: rule_id=%s event_id=%s",
                result.rule_id,
                new_event.id,
            )

    # 6. Return the created authentication event
    return new_event


@router.get("/", response_model=list[AuthEventResponse])
def list_events(
    db: Session = Depends(get_db),
    limit: int = 100,
    skip: int = 0,
):
    """List recent authentication events."""

    event_service = EventService(db)

    return event_service.get_events(
        limit=limit,
        skip=skip,
    )


@router.get("/groups", response_model=EventGroupPage)
def list_event_groups(
    db: Session = Depends(get_db),
    search: str | None = None,
    result: str | None = None,
    sort: str = "recent",
    skip: int = 0,
    limit: int = 20,
    events_limit: int = 20,
):
    """Group events by their strongest correlation identifier.

    ``AuthEvent`` has no session linkage (sessions are only reachable via
    ``Alert.session_id``), so groups are keyed by ``source_ip`` — NOT NULL and
    indexed on every event.  Attack context per group (``alert_types``,
    ``session_ids``) is derived from alerts sharing the group's source IP.
    Grouping, filtering, sorting and pagination all happen server-side so the
    browser never receives an unbounded raw event list.

    Registered before ``/{event_id}`` so the int path parameter cannot
    shadow this literal route.
    """
    if result is not None and result not in ("success", "failure"):
        raise HTTPException(
            status_code=422,
            detail="result must be 'success' or 'failure'",
        )
    if sort not in ("recent", "events", "ip"):
        raise HTTPException(
            status_code=422,
            detail="sort must be one of 'recent', 'events', 'ip'",
        )

    event_service = EventService(db)

    items, total = event_service.get_event_groups(
        search=search,
        result=result,
        sort=sort,
        skip=skip,
        limit=limit,
        events_limit=events_limit,
    )

    return {"items": items, "total": total}


@router.get("/{event_id}", response_model=AuthEventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
):
    """Get a specific authentication event by ID."""

    event_service = EventService(db)

    event = event_service.get_event(event_id)

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Event not found",
        )

    return event