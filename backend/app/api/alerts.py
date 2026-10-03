"""Alert API - the detailed, filterable alert work queue.

The alerts page is the single authoritative detailed view of detections, so:

* ``GET  /api/v1/alerts/``       list with server-side filters + pagination
                                 (defaults unchanged: newest 100 alerts)
* ``GET  /api/v1/alerts/stats``  matching total + facet counts, used for
                                 pagination and the filter options
* ``GET  /api/v1/alerts/{id}``   one alert for the investigation page
* ``GET  /api/v1/alerts/{id}/history``  audit trail of lifecycle transitions
* ``PATCH /api/v1/alerts/{id}``  persist an analyst triage transition

Every response also carries ``detection_rule`` (the threshold/window/requirement
behind the alert type, from the engine configuration) and ``explanation`` (the
structured, generated "why this alert exists" context - see
``app.services.alert_explanation``) so the alert-details panel can explain a
detection without duplicating thresholds in the browser.

Triage writes (``PATCH``) require a bearer token bound to an ``analyst`` or
``admin`` role via ``ALERT_TRIAGE_API_TOKENS`` plus an ``X-User-Id`` identity
header; the state machine in ``app.services.alert_lifecycle`` then decides
whether the requested transition is legal for that role.  Read endpoints stay
public - only state *changes* are gated.

Note: ``/stats`` is declared before ``/{alert_id}`` so the static path is not
captured by the dynamic one.
"""

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.detection_config import get_detection_rule
from app.db.database import get_db
from app.models.alert import Alert
from app.models.audit_log import AuditAction, AuditResult
from app.schemas.alert import (
    AlertDetectionRule,
    AlertResponse,
    AlertSeverity,
    AlertStats,
    AlertStatus,
    AlertStatusTransition,
    AlertStatusUpdate,
)
from app.services.alert_explanation import build_alert_explanation
from app.services.alert_lifecycle import (
    InvalidTransitionError,
    TransitionPermissionError,
)
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService, client_ip


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)

SEARCH_DESCRIPTION = "Case-insensitive substring match on source IP or username"


@dataclass(frozen=True)
class TriageActor:
    """Authenticated identity performing a lifecycle transition."""

    user: str
    role: str


def require_alert_triage_auth(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    request: Request = None,
    db: Session = Depends(get_db),
) -> TriageActor:
    """Authenticate a triage write and resolve its role.

    Follows the ``require_ip_management_auth`` pattern: a bearer token from
    ``ALERT_TRIAGE_API_TOKENS`` authenticates the request while the
    ``X-User-Id`` header names the actor recorded in the audit trail.  The
    role is bound to the *token* server-side - any client-supplied role
    header is ignored, so holding an analyst token can never grant admin
    transitions.

    Every rejection (unconfigured, missing/unknown token, missing identity)
    is recorded as an ``auth.failed`` audit entry before the exception is
    raised; the presented token itself is never stored.
    """

    audit = AuditService(db)
    source_ip = client_ip(request)
    path = request.url.path if request is not None else None

    def _deny(note: str, status_code: int, detail: str, **headers) -> HTTPException:
        audit.record_auth_failure(
            actor=x_user_id.strip() if x_user_id and x_user_id.strip() else None,
            target_id=path,
            source_ip=source_ip,
            note=note,
            detail={"path": path, "status": status_code},
        )
        return HTTPException(status_code=status_code, detail=detail, headers=headers or None)

    token_roles = settings.alert_triage_token_roles
    if not token_roles:
        # Fail-closed configuration state, not an authentication attempt:
        # deliberately not audited (it would repeat on every request).
        raise HTTPException(
            status_code=503,
            detail="Alert triage API is not configured",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise _deny(
            "Triage write rejected: bearer token missing",
            401,
            "Authentication required",
            **{"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    role = token_roles.get(token)
    if role is None:
        raise _deny(
            "Triage write rejected: unknown token",
            403,
            "Forbidden",
        )

    if not x_user_id or not x_user_id.strip():
        raise _deny(
            "Triage write rejected: identity header missing",
            401,
            "User identity required",
        )

    return TriageActor(user=x_user_id.strip(), role=role)


def _with_detection_rule(alert: Alert) -> AlertResponse:
    """``AlertResponse`` plus the detection rule and generated explanation.

    The rule context (threshold, window, human-readable requirement) is derived
    from the engine configuration in ``app.core.detection_config`` - the same
    values ingestion runs with - so the investigation panel can explain why a
    rule triggered without the browser duplicating detection thresholds.  The
    ``explanation`` combines that rule context with the alert's recorded
    evidence into structured fields plus a generated human-readable sentence.
    Both are computed per response (no extra query, no new endpoint); the rule
    is ``None`` for alert types the engine no longer knows, while the
    explanation still falls back to the recorded evidence alone.
    """

    response = AlertResponse.model_validate(alert)

    rule = get_detection_rule(alert.alert_type, alert.service)
    if rule is not None:
        response.detection_rule = AlertDetectionRule(**rule)

    response.explanation = build_alert_explanation(alert, rule)

    return response


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    db: Session = Depends(get_db),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    severity: AlertSeverity | None = Query(
        default=None,
        description="Only alerts with this severity",
    ),
    status: AlertStatus | None = Query(
        default=None,
        description="Only alerts in this triage status",
    ),
    alert_type: str | None = Query(
        default=None,
        max_length=100,
        description="Only alerts of this detection type",
    ),
    search: str | None = Query(
        default=None,
        max_length=255,
        description=SEARCH_DESCRIPTION,
    ),
):
    """List alerts newest first, optionally filtered and paginated."""

    return [
        _with_detection_rule(alert)
        for alert in AlertService(db).list_alerts(
            skip=skip,
            limit=limit,
            severity=severity.value if severity else None,
            status=status.value if status else None,
            alert_type=alert_type,
            search=search,
        )
    ]


@router.get("/stats", response_model=AlertStats)
def get_alert_stats(
    db: Session = Depends(get_db),
    severity: AlertSeverity | None = Query(default=None),
    status: AlertStatus | None = Query(default=None),
    alert_type: str | None = Query(default=None, max_length=100),
    search: str | None = Query(default=None, max_length=255),
):
    """Total and facet counts for the current filter set (drives paging)."""

    return AlertService(db).stats(
        severity=severity.value if severity else None,
        status=status.value if status else None,
        alert_type=alert_type,
        search=search,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """Get a single alert by ID (used by the alert investigation page)."""
    alert = AlertService(db).get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _with_detection_rule(alert)


@router.get("/{alert_id}/history", response_model=list[AlertStatusTransition])
def get_alert_status_history(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """Audit trail of every lifecycle transition of one alert (newest first)."""

    service = AlertService(db)
    if not service.get_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")

    return service.list_status_history(alert_id)


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: TriageActor = Depends(require_alert_triage_auth),
):
    """Persist an analyst triage transition for an alert.

    The transition must be legal for the current status (``409`` otherwise)
    and permitted for the authenticated role (``403`` when an analyst tries
    to reopen a closed alert).  Accepted changes record the actor, role,
    timestamp and optional reason in the ``alert_status_history`` audit trail
    plus a ``security_audit_logs`` entry; rejected transitions are audited
    separately as ``denied`` / ``failure`` outcomes so the security log shows
    attempted privilege escalations too.
    """

    service = AlertService(db)
    source_ip = client_ip(request)

    alert = service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        updated = service.update_status(
            alert,
            target_status=update.status.value,
            actor=actor.user,
            role=actor.role,
            reason=update.reason,
            source_ip=source_ip,
        )
    except InvalidTransitionError as exc:
        AuditService(db).record(
            action=AuditAction.ALERT_STATUS_CHANGE,
            result=AuditResult.FAILURE,
            actor=actor.user,
            actor_role=actor.role,
            target_type="alert",
            target_id=alert_id,
            source_ip=source_ip,
            detail={
                "from_status": alert.status,
                "to_status": update.status.value,
                "reason": update.reason,
            },
            note=str(exc),
        )
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except TransitionPermissionError as exc:
        AuditService(db).record(
            action=AuditAction.ALERT_STATUS_CHANGE,
            result=AuditResult.DENIED,
            actor=actor.user,
            actor_role=actor.role,
            target_type="alert",
            target_id=alert_id,
            source_ip=source_ip,
            detail={
                "from_status": alert.status,
                "to_status": update.status.value,
                "reason": update.reason,
            },
            note=str(exc),
        )
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return _with_detection_rule(updated)
