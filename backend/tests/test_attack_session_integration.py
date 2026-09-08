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


def test_multiple_detection_signals_share_one_session(db):
    """
    Section 5.9: one real-world attack can trigger multiple detectors
    (e.g. 10 failures -> single-account alert, then a successful login
    -> failed-success alert).  Because both share the same correlation
    key (ip + user + service) they land in ONE attack session and the
    session accumulates both detection types.
    """
    timestamp = datetime.now(timezone.utc)

    event1 = _make_event(db, timestamp)
    alert1 = _make_alert(db)

    service = AttackSessionIntegrationService(db)

    session1 = service.process_alert(
        event1,
        alert1,
        "single_account",
    )

    event2 = _make_event(db, timestamp + timedelta(seconds=60))
    alert2 = _make_alert(db, severity="critical")

    session2 = service.process_alert(
        event2,
        alert2,
        "failed_success",
    )

    assert session1.id == session2.id
    assert session2.session_type == "single_account"
    assert "single_account" in session2.detection_types
    assert "failed_success" in session2.detection_types


def test_distinct_attacks_get_distinct_sessions(db):
    """
    Section 5.10: attacks with different correlation keys do NOT merge.
    A single-account brute force against `admin` and a distributed
    attack against `administrator` are different attacks, so they get
    different sessions.
    """
    timestamp = datetime.now(timezone.utc)

    service = AttackSessionIntegrationService(db)

    single_account_session = service.process_alert(
        _make_event(db, timestamp),
        _make_alert(db),
        "single_account",
    )

    # Distributed attack against a DIFFERENT account (different key).
    admin_event = AuthEvent(
        timestamp=timestamp + timedelta(seconds=10),
        source="test",
        source_ip="10.0.0.9",
        username="administrator",
        result="failure",
        service="ssh",
        port=22,
    )
    db.add(admin_event)
    db.commit()
    db.refresh(admin_event)

    admin_alert = _make_alert(db)
    admin_alert.alert_type = "distributed_bruteforce"
    admin_alert.username = "administrator"

    distributed_session = service.process_alert(
        admin_event,
        admin_alert,
        "distributed",
    )

    assert single_account_session.id != distributed_session.id
    assert single_account_session.session_type == "single_account"
    assert distributed_session.session_type == "distributed"


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