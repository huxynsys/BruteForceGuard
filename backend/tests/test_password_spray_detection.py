from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def test_password_spraying_alert_created(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)
    users = ["alice", "bob", "charlie", "david", "eve"]
    last_event = None

    # 10 failures against 5 distinct accounts from the same source IP.
    for i in range(10):
        last_event = event_factory(
            start + timedelta(seconds=i * 10),
            source_ip="10.0.0.2",
            username=users[i % len(users)],
        )

    alert = DetectionService(db).detect_password_spraying(
        last_event,
        minimum_users=5,
        minimum_failures=10,
        window_seconds=600,
    )

    assert alert is not None
    assert alert.alert_type == "password_spraying"
    assert alert.severity == "high"
    assert alert.confidence >= 50
    assert str(alert.source_ip) == "10.0.0.2"


def test_single_username_no_spray_alert(db, event_factory):
    """Same volume against one account is NOT password spraying."""
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(10):
        last_event = event_factory(
            start + timedelta(seconds=i * 10),
            source_ip="10.0.0.2",
            username="alice",
        )

    alert = DetectionService(db).detect_password_spraying(
        last_event,
        minimum_users=5,
        minimum_failures=10,
        window_seconds=600,
    )

    assert alert is None