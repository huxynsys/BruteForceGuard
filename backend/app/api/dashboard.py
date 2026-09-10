import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["dashboard"],
)

# alert_type -> short UI-facing detection key
DETECTION_KEYS = {
    "single_account_bruteforce": "single_account",
    "password_spraying": "password_spray",
    "distributed_bruteforce": "distributed",
    "failed_then_success": "failed_success",
    "credential_stuffing": "credential_stuffing",
    "low_and_slow": "low_and_slow",
}

SEVERITY_KEYS = ["critical", "high", "medium", "low"]


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """
    Aggregated dashboard summary: totals, severity and detection
    distributions. One clean data source for the dashboard KPIs.
    """
    events = list(db.scalars(select(AuthEvent)))
    alerts = list(db.scalars(select(Alert)))
    active_sessions = list(
        db.scalars(
            select(AttackSession).where(AttackSession.status == "active")
        )
    )

    unique_ips = {str(e.source_ip) for e in events if e.source_ip}
    unique_users = {e.username for e in events if e.username}

    severity_counts = Counter(
        a.severity.lower() for a in alerts if a.severity
    )

    detection_counts = Counter(
        DETECTION_KEYS.get(a.alert_type, a.alert_type) for a in alerts
    )

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "active_sessions": len(active_sessions),
        "unique_source_ips": len(unique_ips),
        "unique_usernames": len(unique_users),
        "severity": {
            key: severity_counts.get(key, 0) for key in SEVERITY_KEYS
        },
        "detections": {
            key: detection_counts.get(key, 0)
            for key in DETECTION_KEYS.values()
        },
    }


@router.get("/analytics")
def get_dashboard_analytics(db: Session = Depends(get_db)):
    """
    Analytics data: authentication activity over the last 24 hours
    (hourly buckets), plus top attacking IPs, targeted usernames and
    services, computed from authentication events.
    """
    now = _naive_utc(datetime.now(timezone.utc))
    window_start = now - timedelta(hours=24)

    events = list(
        db.scalars(
            select(AuthEvent).where(AuthEvent.timestamp >= window_start)
        )
    )

    # Hourly activity buckets (failures vs successes).
    buckets: dict[str, dict[str, int]] = {}
    for i in range(23, -1, -1):
        hour_start = (now - timedelta(hours=i)).replace(
            minute=0, second=0, microsecond=0
        )
        buckets[hour_start.strftime("%Y-%m-%dT%H:00")] = {
            "failure": 0,
            "success": 0,
        }

    for event in events:
        if event.timestamp is None:
            continue
        key = _naive_utc(event.timestamp).replace(
            minute=0, second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:00")
        if key in buckets and event.result in ("failure", "success"):
            buckets[key][event.result] += 1

    activity = [
        {"time": key, "failure": value["failure"], "success": value["success"]}
        for key, value in buckets.items()
    ]

    # Top entities from the 24h window.
    ip_counter = Counter(
        str(e.source_ip) for e in events
        if e.source_ip and e.result == "failure"
    )
    user_counter = Counter(
        e.username for e in events
        if e.username and e.result == "failure"
    )
    service_counter = Counter(
        e.service for e in events if e.service and e.result == "failure"
    )

    return {
        "activity": activity,
        "top_ips": [
            {"value": ip, "count": count}
            for ip, count in ip_counter.most_common(10)
        ],
        "top_users": [
            {"value": user, "count": count}
            for user, count in user_counter.most_common(10)
        ],
        "top_services": [
            {"value": service, "count": count}
            for service, count in service_counter.most_common(10)
        ],
    }
