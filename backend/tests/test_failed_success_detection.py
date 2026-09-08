from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def _play_out_attack(event_factory, failures, success=None):
    """Play failures then an optional success; return the last event."""
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(failures):
        last_event = event_factory(
            start + timedelta(seconds=i * 10),
            source_ip="10.0.0.1",
            username="admin",
            result="failure",
        )

    if success is not None:
        last_event = event_factory(
            start + timedelta(seconds=failures * 10 + 10),
            source_ip="10.0.0.1",
            username="admin",
            result=success,
        )

    return last_event


def test_failed_then_success_alert_created(db, event_factory):
    success_event = _play_out_attack(event_factory, failures=3, success="success")

    alert = DetectionService(db).detect_failed_then_success(
        success_event,
        minimum_failures=3,
        window_seconds=300,
    )

    assert alert is not None
    assert alert.alert_type == "failed_then_success"
    assert alert.severity == "critical"
    assert alert.confidence >= 70
    assert alert.username == "admin"


def test_few_failures_no_success_alert(db, event_factory):
    success_event = _play_out_attack(event_factory, failures=2, success="success")

    alert = DetectionService(db).detect_failed_then_success(
        success_event,
        minimum_failures=3,
        window_seconds=300,
    )

    assert alert is None


def test_failure_event_does_not_trigger_failed_then_success(db, event_factory):
    """The detector only fires on the SUCCESS event."""
    last_failure = _play_out_attack(event_factory, failures=4)

    alert = DetectionService(db).detect_failed_then_success(
        last_failure,
        minimum_failures=3,
        window_seconds=300,
    )

    assert alert is None