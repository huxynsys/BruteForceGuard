from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def test_low_and_slow_alert_created(db, event_factory):
    """
    Failures spread across the window (>= 5 active 12-minute intervals
    inside a 1 hour window) must trigger low-and-slow.
    """
    start = datetime(2026, 9, 1, 10, 30, 0)
    last_event = None

    # One failure every 5 minutes: 10:30 -> 11:15 (10 failures).
    for i in range(10):
        last_event = event_factory(
            start + timedelta(minutes=5 * i),
            source_ip="10.0.0.4",
            username="slowuser",
        )

    alert = DetectionService(db).detect_low_and_slow(
        last_event,
        minimum_failures=10,
        window_seconds=3600,
        minimum_active_intervals=5,
    )

    assert alert is not None
    assert alert.alert_type == "low_and_slow"
    assert alert.severity == "medium"
    assert alert.confidence >= 50
    assert alert.username == "slowuser"

    evidence = alert.evidence or {}
    assert evidence["active_intervals"] >= 5


def test_clustered_failures_no_low_and_slow_alert(db, event_factory):
    """
    Ten failures clustered inside a single short interval do NOT satisfy
    the "active intervals" requirement.
    """
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(10):
        last_event = event_factory(
            start + timedelta(seconds=6 * i),
            source_ip="10.0.0.4",
            username="slowuser",
        )

    alert = DetectionService(db).detect_low_and_slow(
        last_event,
        minimum_failures=10,
        window_seconds=3600,
        minimum_active_intervals=5,
    )

    assert alert is None