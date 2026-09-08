from datetime import datetime, timedelta

from app.services.correlation_service import CorrelationService


def test_get_related_events_inside_window(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)

    event_a = event_factory(start, source_ip="10.0.0.5", username="alice")
    event_b = event_factory(
        start + timedelta(seconds=120),
        source_ip="10.0.0.5",
        username="alice",
    )
    # Latest in-window event: the window is [C - 600s, C].
    event_c = event_factory(
        start + timedelta(seconds=300),
        source_ip="10.0.0.6",
        username="bob",
    )

    # Outside the 600 second window (9 minutes after event A).
    event_d = event_factory(
        start + timedelta(seconds=900),
        source_ip="10.0.0.7",
        username="carol",
    )

    related = CorrelationService(db).get_related_events(
        event_c,
        window_seconds=600,
    )

    assert event_a in related
    assert event_b in related
    assert event_c in related
    assert event_d not in related


def test_get_events_by_source_ip_and_username(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)

    event_factory(start, source_ip="10.0.0.5", username="alice")
    event_factory(
        start + timedelta(seconds=10),
        source_ip="10.0.0.5",
        username="bob",
    )
    event_factory(
        start + timedelta(seconds=20),
        source_ip="10.0.0.6",
        username="bob",
    )

    service = CorrelationService(db)

    by_ip = service.get_events_by_source_ip(
        "10.0.0.5",
        start + timedelta(seconds=30),
        window_seconds=600,
    )
    by_user = service.get_events_by_username(
        "bob",
        start + timedelta(seconds=30),
        window_seconds=600,
    )

    assert len(by_ip) == 2
    assert len(by_user) == 2


def test_correlate_attack_patterns(db, event_factory):
    start = datetime(2026, 9, 1, 10, 0, 0)

    event_factory(start, source_ip="10.0.0.5", username="alice")
    event_factory(
        start + timedelta(seconds=10),
        source_ip="10.0.0.5",
        username="bob",
    )
    event_factory(
        start + timedelta(seconds=20),
        source_ip="10.0.0.6",
        username="bob",
    )
    last = event_factory(
        start + timedelta(seconds=30),
        source_ip="10.0.0.6",
        username="bob",
        result="success",
    )

    events = CorrelationService(db).get_related_events(
        last,
        window_seconds=600,
    )
    stats = CorrelationService(db).correlate_attack_patterns(events)

    assert stats["total_events"] == 4
    assert stats["distinct_source_ips"] == 2
    assert stats["distinct_usernames"] == 2
    assert stats["failure_count"] == 3
    assert stats["success_count"] == 1
    assert stats["source_ips"] == ["10.0.0.5", "10.0.0.6"]