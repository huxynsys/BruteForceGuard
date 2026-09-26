"""Alert API - the detailed, filterable alert work queue.

The alerts page is the single authoritative detailed view of detections, so:

* ``GET  /api/v1/alerts/``       list with server-side filters + pagination
                                 (defaults unchanged: newest 100 alerts)
* ``GET  /api/v1/alerts/stats``  matching total + facet counts, used for
                                 pagination and the filter options
* ``GET  /api/v1/alerts/{id}``   one alert for the investigation page
* ``PATCH /api/v1/alerts/{id}``  persist an analyst triage transition

Every response also carries ``detection_rule`` (the threshold/window/requirement
behind the alert type, from the engine configuration) so the alert-details
panel can explain a detection without duplicating thresholds in the browser.

Note: ``/stats`` is declared before ``/{alert_id}`` so the static path is not
captured by the dynamic one.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.detection_config import get_detection_rule
from app.db.database import get_db
from app.models.alert import Alert
from app.schemas.alert import (
    AlertDetectionRule,
    AlertResponse,
    AlertSeverity,
    AlertStats,
    AlertStatus,
    AlertStatusUpdate,
)
from app.services.alert_service import AlertService


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)

SEARCH_DESCRIPTION = "Case-insensitive substring match on source IP or username"


def _with_detection_rule(alert: Alert) -> AlertResponse:
    """``AlertResponse`` plus the detection rule that produced the alert.

    The rule context (threshold, window, human-readable requirement) is derived
    from the engine configuration in ``app.core.detection_config`` - the same
    values ingestion runs with - so the investigation panel can explain why a
    rule triggered without the browser duplicating detection thresholds.  It is
    computed per response (no extra query, no new endpoint) and is ``None`` for
    alert types the engine no longer knows.
    """

    response = AlertResponse.model_validate(alert)

    rule = get_detection_rule(alert.alert_type, alert.service)
    if rule is not None:
        response.detection_rule = AlertDetectionRule(**rule)

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


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    """Persist an analyst triage transition for an alert."""

    service = AlertService(db)

    alert = service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return _with_detection_rule(service.update_status(alert, update.status.value))
