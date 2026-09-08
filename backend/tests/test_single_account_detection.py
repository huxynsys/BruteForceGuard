from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def _fire_failures(event_factory, count, *, source_ip, username):
    """Create `count` failures (5 seconds apart) and return the last one."""
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(count):
        last_event = event_factory(
            start + timedelta(seconds=i * 5),
            source_ip=source_ip,
            username=username,
        )

    return last_event


def test_single_account_bruteforce_alert_created(db, event_factory):
    last_event = _fire_failures(
        event_factory,
        5,
        source_ip="10.0.0.1",
        username="admin",
    )

    alert = DetectionService(db).detect_single_account_bruteforce(
        last_event,
        threshold=5,
        window_seconds=300,
    )

    assert alert is not None
    assert alert.alert_type == "single_account_bruteforce"
    assert alert.severity == "high"
    assert alert.confidence >= 50
    assert str(alert.source_ip) == "10.0.0.1"
    assert alert.username == "admin"


def test_below_threshold_no_alert(db, event_factory):
    last_event = _fire_failures(
        event_factory,
        4,
        source_ip="10.0.0.1",
        username="admin",
    )

    alert = DetectionService(db).detect_single_account_bruteforce(
        last_event,
        threshold=5,
        window_seconds=300,
    )

    assert alert is None


def test_success_event_never_triggers_single_account(db, event_factory):
    event = event_factory(
        datetime(2026, 9, 1, 10, 0, 0),
        source_ip="10.0.0.1",
        username="admin",
        result="success",
    )

    alert = DetectionService(db).detect_single_account_bruteforce(
        event,
        threshold=5,
        window_seconds=300,
    )

    assert alert is None