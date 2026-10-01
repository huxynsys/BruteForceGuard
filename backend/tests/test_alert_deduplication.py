"""Alert deduplication: a repeated detection refreshes, it does not duplicate.

Deduplication keeps one *open* alert per ``alert_type + source_ip + username +
service``.  These tests pin both halves of that contract: while the alert is
open no second row is ever created, and the suppressed duplicate is still
recorded on the alert it belongs to (evidence counters, attack scope,
``first_seen`` / ``last_seen`` and the per-detection occurrence history).
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.auth_event import AuthEvent
from app.services.detection_service import create_alert_if_new


def test_duplicate_alert_is_not_created(db):
    event = AuthEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
    )

    db.add(event)
    db.commit()

    alert_data = {
        "alert_type": "single_account_bruteforce",
        "severity": "high",
        "confidence": 50,
        "title": "Possible Single-Account Brute Force",
        "description": "5 failed authentication attempts.",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "service": "ssh",
        "mitre_technique": "T1110.001",
        "evidence": {
            "failure_count": 5,
        },
    }

    # First call creates the alert...
    first_alert = create_alert_if_new(db, alert_data)

    # Second call for the same open attack is deduplicated...
    second_alert = create_alert_if_new(db, alert_data)

    # ...and only one row exists in the database.
    alerts = list(db.scalars(select(Alert)))

    assert first_alert is not None
    assert second_alert is None
    assert len(alerts) == 1


def test_different_attack_creates_a_different_alert(db):
    event = AuthEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
    )

    db.add(event)
    db.commit()

    single_account_data = {
        "alert_type": "single_account_bruteforce",
        "severity": "high",
        "confidence": 50,
        "title": "Possible Single-Account Brute Force",
        "description": "5 failed authentication attempts.",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "service": "ssh",
        "mitre_technique": "T1110.001",
        "evidence": {},
    }

    failed_success_data = dict(single_account_data)
    failed_success_data.update(
        {
            "alert_type": "failed_then_success",
            "severity": "critical",
            "mitre_technique": "T1110",
        }
    )

    single_account_alert = create_alert_if_new(db, single_account_data)
    failed_success_alert = create_alert_if_new(db, failed_success_data)

    assert single_account_alert is not None
    assert failed_success_alert is not None
    assert single_account_alert.id != failed_success_alert.id


# ---------------------------------------------------------------------------
# A repeated detection refreshes the alert it belongs to
# ---------------------------------------------------------------------------


def _alert_data(**overrides):
    """Detection payload as the single-account detector emits it."""
    data = {
        "alert_type": "single_account_bruteforce",
        "severity": "high",
        "confidence": 50,
        "title": "Possible Single-Account Brute Force",
        "description": "5 failed authentication attempts.",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "service": "ssh",
        "mitre_technique": "T1110.001",
        "evidence": {
            "failure_count": 5,
            "window_seconds": 300,
            "distinct_users": 1,
            "distinct_source_ips": 1,
            "services": ["ssh"],
            "first_seen": "2026-09-08T10:00:00+00:00",
            "last_seen": "2026-09-08T10:04:00+00:00",
        },
    }
    data.update(overrides)
    return data


def test_repeated_detection_refreshes_the_open_alert(db):
    first_alert = create_alert_if_new(db, _alert_data())

    # The same attack keeps running: a later detection covers more failures and
    # a longer stretch of the event timeline.
    repeated = _alert_data(
        evidence={
            "failure_count": 9,
            "window_seconds": 300,
            "distinct_users": 1,
            "distinct_source_ips": 1,
            "services": ["ssh"],
            "first_seen": "2026-09-08T10:03:00+00:00",
            "last_seen": "2026-09-08T10:09:00+00:00",
        },
    )

    assert create_alert_if_new(db, repeated) is None

    alerts = list(db.scalars(select(Alert)))
    assert len(alerts) == 1

    alert = alerts[0]
    evidence = alert.evidence

    assert alert.id == first_alert.id
    assert alert.status == "open"

    # Counters and the attack window grow...
    assert evidence["failure_count"] == 9
    assert evidence["last_seen"] == "2026-09-08T10:09:00+00:00"

    # ...while the true start of the attack is preserved.
    assert evidence["first_seen"] == "2026-09-08T10:00:00+00:00"

    # The suppressed duplicate is still visible as its own raw detection.
    assert evidence["occurrence_count"] == 2
    assert [
        occurrence["failure_count"] for occurrence in evidence["occurrences"]
    ] == [5, 9]


def test_repeated_detection_never_downgrades_severity_or_confidence(db):
    create_alert_if_new(db, _alert_data(severity="high", confidence=50))

    # A weaker repeat must not lower what has already been recorded.
    assert create_alert_if_new(
        db,
        _alert_data(severity="medium", confidence=40),
    ) is None

    alert = db.scalars(select(Alert)).one()
    assert alert.severity == "high"
    assert alert.confidence == 50

    # A stronger repeat escalates the alert.
    assert create_alert_if_new(
        db,
        _alert_data(severity="critical", confidence=90),
    ) is None

    alert = db.scalars(select(Alert)).one()
    assert alert.severity == "critical"
    assert alert.confidence == 90
    assert db.scalar(select(func.count()).select_from(Alert)) == 1


def test_closed_alert_does_not_absorb_a_new_detection(db):
    first_alert = create_alert_if_new(db, _alert_data())

    # An analyst finished the investigation; the state transition must not make
    # the next detection disappear into a closed case.
    first_alert.status = "resolved"
    db.commit()

    second_alert = create_alert_if_new(db, _alert_data())

    assert second_alert is not None
    assert second_alert.id != first_alert.id
    assert second_alert.status == "open"
    # The new alert starts its own occurrence history.
    assert second_alert.evidence["occurrence_count"] == 1
    assert db.scalar(select(func.count()).select_from(Alert)) == 2


def test_merged_evidence_unions_scope_and_never_shrinks(db):
    spray = {
        "alert_type": "password_spraying",
        "severity": "high",
        "confidence": 60,
        "title": "Possible Password Spraying",
        "description": "12 failures against 5 accounts.",
        "source_ip": "10.0.0.5",
        "username": None,
        "service": "ssh",
        "mitre_technique": "T1110.003",
        "evidence": {
            "failure_count": 12,
            "distinct_users": 5,
            "usernames": ["admin", "guest"],
            "window_seconds": 600,
            "first_seen": "2026-09-08T10:00:00+00:00",
            "last_seen": "2026-09-08T10:05:00+00:00",
        },
    }

    create_alert_if_new(db, spray)

    # A later window of the same spray sees fewer failures but one more account.
    create_alert_if_new(
        db,
        {
            **spray,
            "evidence": {
                **spray["evidence"],
                "failure_count": 11,
                "usernames": ["guest", "root"],
                "last_seen": "2026-09-08T10:12:00+00:00",
            },
        },
    )

    alert = db.scalars(select(Alert)).one()

    assert alert.evidence["failure_count"] == 12
    assert alert.evidence["usernames"] == ["admin", "guest", "root"]
    assert alert.evidence["distinct_users"] == 5
    assert alert.evidence["last_seen"] == "2026-09-08T10:12:00+00:00"
    assert alert.evidence["occurrence_count"] == 2


def test_occurrence_history_is_counted_and_bounded(db):
    create_alert_if_new(db, _alert_data())

    for minute in range(1, 15):
        create_alert_if_new(
            db,
            _alert_data(
                evidence={
                    "failure_count": 5 + minute,
                    "first_seen": "2026-09-08T10:00:00+00:00",
                    "last_seen": f"2026-09-08T10:{minute:02d}:00+00:00",
                },
            ),
        )

    alert = db.scalars(select(Alert)).one()
    occurrences = alert.evidence["occurrences"]

    # 1 creation + 14 suppressed duplicates, all counted...
    assert alert.evidence["occurrence_count"] == 15
    # ...but only the newest snapshots are retained.
    assert len(occurrences) == 10
    assert occurrences[-1]["last_seen"] == "2026-09-08T10:14:00+00:00"
    assert alert.evidence["failure_count"] == 19
    assert db.scalar(select(func.count()).select_from(Alert)) == 1


def test_merge_tolerates_detections_without_timestamps(db):
    create_alert_if_new(db, _alert_data(evidence={"failure_count": 5}))

    assert create_alert_if_new(
        db,
        _alert_data(evidence={"failure_count": 6}),
    ) is None

    alert = db.scalars(select(Alert)).one()

    assert alert.evidence["failure_count"] == 6
    assert alert.evidence["occurrence_count"] == 2
    assert [
        occurrence["failure_count"] for occurrence in alert.evidence["occurrences"]
    ] == [5, 6]
    assert "first_seen" not in alert.evidence
    assert "last_seen" not in alert.evidence


def test_deduplication_key_separates_ips_users_services_and_types(db):
    created = [
        create_alert_if_new(db, _alert_data()),
        create_alert_if_new(db, _alert_data(source_ip="10.0.0.2")),
        create_alert_if_new(db, _alert_data(username="root")),
        create_alert_if_new(db, _alert_data(service="rdp")),
        create_alert_if_new(db, _alert_data(alert_type="low_and_slow")),
    ]

    assert all(alert is not None for alert in created)
    assert len({alert.id for alert in created}) == 5
    assert db.scalar(select(func.count()).select_from(Alert)) == 5


# ---------------------------------------------------------------------------
# The same contract through the real ingestion pipeline
# ---------------------------------------------------------------------------


def _post_failure(client, timestamp: datetime) -> None:
    response = client.post(
        "/api/v1/events/",
        json={
            "timestamp": timestamp.isoformat(),
            "source": "linux",
            "source_ip": "203.0.113.7",
            "username": "admin",
            "result": "failure",
            "service": "ssh",
            "port": 22,
        },
    )
    assert response.status_code == 200, response.text


def test_repeated_failures_refresh_one_alert_end_to_end(client, test_engine):
    base = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)

    # 5 failures trip the ssh threshold and raise the alert.
    for index in range(5):
        _post_failure(client, base + timedelta(seconds=index))

    with Session(bind=test_engine) as db:
        assert db.scalar(select(func.count()).select_from(Alert)) == 1

    # Four more failures of the same attack: no new alert, but the open alert
    # keeps absorbing the attempts.
    for index in range(5, 9):
        _post_failure(client, base + timedelta(seconds=index))

    with Session(bind=test_engine) as db:
        alerts = list(db.scalars(select(Alert)))

        assert len(alerts) == 1
        assert alerts[0].status == "open"
        assert alerts[0].evidence["failure_count"] == 9
        assert alerts[0].evidence["occurrence_count"] >= 2
        assert alerts[0].evidence["first_seen"].startswith("2026-09-08T10:00:00")
        assert alerts[0].evidence["last_seen"].startswith("2026-09-08T10:00:08")