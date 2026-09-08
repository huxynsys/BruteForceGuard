from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def test_credential_stuffing_alert_created(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)
    users = [f"user{i:02d}" for i in range(10)]
    last_event = None

    # 20 failures against 10 distinct accounts from the same source IP.
    for i in range(20):
        last_event = event_factory(
            start + timedelta(seconds=i * 5),
            source_ip="10.0.0.3",
            username=users[i % len(users)],
        )

    alert = DetectionService(db).detect_credential_stuffing(
        last_event,
        minimum_users=10,
        minimum_failures=20,
        window_seconds=600,
    )

    assert alert is not None
    assert alert.alert_type == "credential_stuffing"
    assert alert.severity == "high"
    assert alert.confidence >= 50
    assert str(alert.source_ip) == "10.0.0.3"

    evidence = alert.evidence or {}
    assert evidence["failure_count"] == 20
    assert evidence["distinct_users"] == 10
    assert evidence["source_ip"] == "10.0.0.3"
    assert "usernames" in evidence
    assert evidence["services"] == ["ssh"]


def test_no_credential_stuffing_below_threshold(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)
    users = [f"user{i:02d}" for i in range(10)]
    last_event = None

    # Only 10 failures against 10 accounts: below the 20-failure threshold.
    for i in range(10):
        last_event = event_factory(
            start + timedelta(seconds=i * 5),
            source_ip="10.0.0.3",
            username=users[i],
        )

    alert = DetectionService(db).detect_credential_stuffing(
        last_event,
        minimum_users=10,
        minimum_failures=20,
        window_seconds=600,
    )

    assert alert is None