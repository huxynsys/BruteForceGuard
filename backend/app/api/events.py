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
from app.core.detection_config import (
    CREDENTIAL_STUFFING_WINDOW_SECONDS,
    FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
    FAILED_THEN_SUCCESS_WINDOW_SECONDS,
    LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
    LOW_AND_SLOW_MINIMUM_FAILURES,
    LOW_AND_SLOW_WINDOW_SECONDS,
    get_service_thresholds,
)
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

    # 4. Get service-specific detection thresholds
    thresholds = get_service_thresholds(new_event.service)

    # 5. Run all detectors
    detectors = [
        (
            "single_account",
            detection_service.detect_single_account_bruteforce,
            {
                "threshold": thresholds["failure_threshold"],
                "window_seconds": thresholds["window_seconds"],
            },
        ),
        (
            "password_spray",
            detection_service.detect_password_spraying,
            {
                "minimum_users": thresholds["password_spray_users"],
                "minimum_failures": thresholds["failure_threshold"] * 2,
                "window_seconds": thresholds["window_seconds"],
            },
        ),
        (
            "distributed",
            detection_service.detect_distributed_bruteforce,
            {
                "minimum_source_ips": thresholds["distributed_ips"],
                "minimum_failures": thresholds["failure_threshold"] * 2,
                "window_seconds": thresholds["window_seconds"],
            },
        ),
        (
            "failed_success",
            detection_service.detect_failed_then_success,
            {
                "minimum_failures": FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
                "window_seconds": FAILED_THEN_SUCCESS_WINDOW_SECONDS,
            },
        ),
        (
            "credential_stuffing",
            detection_service.detect_credential_stuffing,
            {
                "minimum_users": thresholds["credential_stuffing_users"],
                "minimum_failures": thresholds["credential_stuffing_failures"],
                "window_seconds": CREDENTIAL_STUFFING_WINDOW_SECONDS,
            },
        ),
        (
            "low_and_slow",
            detection_service.detect_low_and_slow,
            {
                "minimum_failures": LOW_AND_SLOW_MINIMUM_FAILURES,
                "window_seconds": LOW_AND_SLOW_WINDOW_SECONDS,
                "minimum_active_intervals": LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
            },
        ),
    ]

    for name, detector, kwargs in detectors:
        try:
            alert = detector(new_event, **kwargs)

            if alert:
                logger.info(
                    "Detection triggered: type=%s event_id=%s",
                    name,
                    new_event.id,
                )

                # Phase 7: enrich alert with risk / intel / MITRE context.
                intelligence_service.enrich_alert(
                    alert=alert,
                    event=new_event,
                )

                session = session_integration_service.process_alert(
                    event=new_event,
                    alert=alert,
                    detection_type=name,
                )

                # Phase 7: aggregate intelligence onto the attack session.
                if session is not None:
                    intelligence_service.enrich_session(session)

        except Exception as e:
            # Detection errors must not prevent event ingestion.
            logger.warning(
                "Detector %s failed for event %s: %s",
                name,
                new_event.id,
                e,
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