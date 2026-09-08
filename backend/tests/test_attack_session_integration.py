from datetime import datetime, timedelta, timezone

from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.services.attack_session_service import (
    AttackSessionIntegrationService,
)


def _make_event(db, timestamp):
    event = AuthEvent(
        timestamp=timestamp,
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def _make_alert(db, severity="high", confidence=70):
    alert = Alert(
        alert_type="single_account_bruteforce",
        severity=severity,
        confidence=confidence,
        title="Brute Force",
        description="Test detection",
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        status="open",
        evidence={
            "failure_count": 5,
        },
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


def test_alert_creates_attack_session(db):
    event = _make_event(db, datetime.now(timezone.utc))
    alert = _make_alert(db)

    service = AttackSessionIntegrationService(db)

    session = service.process_alert(
        event=event,
        alert=alert,
        detection_type="single_account",
    )

    assert session is not None
    assert session.status == "active"
    assert session.event_count == 1
    assert "10.0.0.1" in session.source_ips
    assert "admin" in session.usernames
    assert "ssh" in session.services
    assert session.started_at == session.last_seen_at


def test_related_alert_updates_existing_session(db):
    timestamp = datetime.now(timezone.utc)

    event1 = _make_event(db, timestamp)
    alert1 = _make_alert(db)

    service = AttackSessionIntegrationService(db)

    session1 = service.process_alert(
        event1,
        alert1,
        "single_account",
    )
    first_last_seen = session1.last_seen_at

    event2 = _make_event(
        db,
        timestamp + timedelta(seconds=60),
    )
    alert2 = _make_alert(db, confidence=80)

    session2 = service.process_alert(
        event2,
        alert2,
        "single_account",
    )

    assert session1.id == session2.id
    assert session2.event_count == 2
    assert session2.last_seen_at > first_last_seen


def test_detection_type_is_recorded_on_session(db):
    """A session records the detection signals that produced it."""
    timestamp = datetime.now(timezone.utc)

    event = _make_event(db, timestamp)
    alert = _make_alert(db)

    session = AttackSessionIntegrationService(db).process_alert(
        event,
        alert,
        "single_account",
    )

    assert session.detection_types == ["single_account"]


def test_distinct_attack_types_get_distinct_sessions(db):
    """
    Different attack types are not merged into one session:
    the correlation key is (session_type, source_ip, username, service).
    """
    timestamp = datetime.now(timezone.utc)

    event = _make_event(db, timestamp)
    alert = _make_alert(db)
    service = AttackSessionIntegrationService(db)

    single_account_session = service.process_alert(
        event,
        alert,
        "single_account",
    )

    failed_success_session = service.process_alert(
        event,
        alert,
        "failed_success",
    )

    assert single_account_session.id != failed_success_session.id
    assert single_account_session.session_type == "single_account"
    assert failed_success_session.session_type == "failed_success"


def test_severity_escalates_but_never_downgrades(db):
    """A session keeps the highest severity it has observed."""
    timestamp = datetime.now(timezone.utc)
    service = AttackSessionIntegrationService(db)

    # Start as low.
    session = service.process_alert(
        _make_event(db, timestamp),
        _make_alert(db, severity="low"),
        "single_account",
    )
    assert session.severity == "low"

    # Escalate to critical.
    session = service.process_alert(
        _make_event(db, timestamp + timedelta(seconds=60)),
        _make_alert(db, severity="critical"),
        "single_account",
    )
    assert session.severity == "critical"

    # A later medium alert must NOT downgrade it.
    session = service.process_alert(
        _make_event(db, timestamp + timedelta(seconds=120)),
        _make_alert(db, severity="medium"),
        "single_account",
    )
    assert session.severity == "critical"


def test_evidence_is_kept_unique_per_session(db):
    """Duplicated evidence is stored once, not multiple times."""
    timestamp = datetime.now(timezone.utc)
    service = AttackSessionIntegrationService(db)

    session = service.process_alert(
        _make_event(db, timestamp),
        _make_alert(db),
        "single_account",
    )

    session = service.process_alert(
        _make_event(db, timestamp + timedelta(seconds=60)),
        _make_alert(db),
        "single_account",
    )

    assert session.source_ips == ["10.0.0.1"]
    assert session.usernames == ["admin"]
    assert session.services == ["ssh"]
    assert session.detection_types == ["single_account"]