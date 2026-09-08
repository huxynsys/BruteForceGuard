from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def test_distributed_bruteforce_alert_created(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    last_event = None

    # 12 failures against one account from 3 different source IPs.
    for i in range(12):
        last_event = event_factory(
            start + timedelta(seconds=i * 10),
            source_ip=ips[i % len(ips)],
            username="administrator",
        )

    alert = DetectionService(db).detect_distributed_bruteforce(
        last_event,
        minimum_source_ips=3,
        minimum_failures=10,
        window_seconds=600,
    )

    assert alert is not None
    assert alert.alert_type == "distributed_bruteforce"
    assert alert.severity == "high"
    assert alert.confidence >= 50
    assert alert.username == "administrator"


def test_single_source_no_distributed_alert(db, event_factory):
    """The same volume from a single IP is not a distributed attack."""
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(12):
        last_event = event_factory(
            start + timedelta(seconds=i * 10),
            source_ip="10.0.0.1",
            username="administrator",
        )

    alert = DetectionService(db).detect_distributed_bruteforce(
        last_event,
        minimum_source_ips=3,
        minimum_failures=10,
        window_seconds=600,
    )

    assert alert is None