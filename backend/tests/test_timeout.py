"""
Attack-session timeout tests (Phase 5, Section 5.26).

The service layer must be able to close sessions that have been inactive
for longer than the configured timeout, whether that is triggered
explicitly (close_inactive_sessions) or as a side effect of correlation
lookup (find_session_by_correlation).
"""

from datetime import datetime, timedelta, timezone

from app.services.session_service import SessionService


def _old_timestamp(minutes_ago, seconds_ago=0):
    return (
        datetime.now(timezone.utc)
        - timedelta(minutes=minutes_ago, seconds=seconds_ago)
    )


def test_close_inactive_sessions_closes_stale_sessions(
    db,
    session_factory,
):
    now = datetime.now(timezone.utc)

    stale = session_factory(
        started_at=now - timedelta(minutes=30),
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
    )
    # Recent session stays active.
    fresh = session_factory(
        started_at=now,
        source_ips=["10.0.0.2"],
        usernames=["bob"],
        services=["ssh"],
    )

    closed_count = SessionService(db).close_inactive_sessions(
        timeout_seconds=600,
    )

    assert closed_count == 1
    assert stale.status == "closed"
    assert fresh.status == "active"


def test_recent_session_is_not_closed(db, session_factory):
    session = session_factory(
        started_at=datetime.now(timezone.utc) - timedelta(seconds=30),
    )

    closed_count = SessionService(db).close_inactive_sessions(
        timeout_seconds=600,
    )

    assert closed_count == 0
    assert session.status == "active"


def test_timeout_side_effect_when_searching(db, session_factory):
    """
    find_session_by_correlation closes stale sessions as a side effect
    and returns None instead of returning the stale session.
    """
    old = _old_timestamp(minutes_ago=30)

    session = session_factory(
        started_at=old,
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
    )

    service = SessionService(db)

    found = service.find_session_by_correlation(
        key_fields=("source_ip", "username", "service"),
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        event_timestamp=datetime.now(timezone.utc),
        timeout_seconds=600,
    )

    assert found is None
    assert session.status == "closed"


def test_in_window_session_is_returned(db, session_factory):
    now = datetime.now(timezone.utc)

    session = session_factory(
        started_at=now - timedelta(seconds=60),
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
    )

    service = SessionService(db)

    found = service.find_session_by_correlation(
        key_fields=("source_ip", "username", "service"),
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        event_timestamp=now,
        timeout_seconds=600,
    )

    assert found is not None
    assert found.id == session.id
    assert session.status == "active"


def test_event_timeline_drives_timeout(db, session_factory):
    """
    Section 5.8: timeout must be evaluated on the EVENT timeline.
    A session last seen at 10:00 is stale for an event at 11:00 even if
    the wall clock says otherwise...
    """
    event_ts = datetime(2026, 9, 1, 11, 0, 0, tzinfo=timezone.utc)

    session = session_factory(
        started_at=datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc),
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
    )

    service = SessionService(db)

    found = service.find_session_by_correlation(
        key_fields=("source_ip", "username", "service"),
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        event_timestamp=event_ts,
        timeout_seconds=600,
    )

    assert found is None
    assert session.status == "closed"

    # ...but is still active for an event at 10:05 (within 600s).
    session.status = "active"
    db.commit()

    found = service.find_session_by_correlation(
        key_fields=("source_ip", "username", "service"),
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        event_timestamp=datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc),
        timeout_seconds=600,
    )

    assert found is not None
    assert found.id == session.id