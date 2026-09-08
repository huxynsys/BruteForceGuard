"""
Confidence-score tests (Phase 5, Section 5.30).

These prove the heuristic confidence ladders encoded in each detector:
more evidence (more failures, more users, more IPs) must produce a
higher confidence score.  They are deliberately NOT calibrated scores —
they are deterministic heuristics.
"""

from datetime import datetime, timedelta

from app.services.detection_service import DetectionService


def _failures(event_factory, count, *, source_ip, username,
              users=None, ips=None, spacing_seconds=5):
    """Insert `count` failures and return the LAST event created."""
    start = datetime(2026, 9, 1, 10, 0, 0)
    last_event = None

    for i in range(count):
        user = (users or [username])[i % len(users or [username])]
        ip = (ips or [source_ip])[i % len(ips or [source_ip])]
        last_event = event_factory(
            start + timedelta(seconds=i * spacing_seconds),
            source_ip=ip,
            username=user,
            service="ssh",
        )

    assert last_event is not None
    return last_event


# ---------------------------------------------------------------------
# Single-account: 5 -> 50, 10 -> 65, 20 -> 80
# ---------------------------------------------------------------------
def test_single_account_confidence_increases_with_failures(
    db, event_factory
):
    for count, expected in [(5, 50), (10, 65), (20, 80)]:
        last = _failures(
            event_factory,
            count,
            source_ip=f"10.1.0.{count}",
            username="admin",
        )
        alert = DetectionService(db).detect_single_account_bruteforce(
            last,
            threshold=5,
            window_seconds=300,
        )
        assert alert is not None
        assert alert.confidence == expected

        # Roll everything back so each case starts clean.
        db.query(last.__class__).delete()
        db.commit()


# ---------------------------------------------------------------------
# Password spray: 50 base, 65 at >=20 failures, 75 at >=10 users
# ---------------------------------------------------------------------
def test_password_spray_base_confidence(db, event_factory):
    users = ["alice", "bob", "charlie", "david", "eve"]
    last = _failures(
        event_factory, 10,
        source_ip="10.2.0.1",
        username="sprayer",
        users=users,
        spacing_seconds=10,
    )
    alert = DetectionService(db).detect_password_spraying(
        last, minimum_users=5, minimum_failures=10, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 50  # < 20 failures, < 10 users


def test_password_spray_confidence_at_20_failures(db, event_factory):
    users = ["alice", "bob", "charlie", "david", "eve"]
    last = _failures(
        event_factory, 20,
        source_ip="10.2.0.2",
        username="sprayer",
        users=users,
        spacing_seconds=10,
    )
    alert = DetectionService(db).detect_password_spraying(
        last, minimum_users=5, minimum_failures=10, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 65  # >= 20 failures, < 10 users


def test_password_spray_confidence_at_10_users(db, event_factory):
    last = _failures(
        event_factory, 10,
        source_ip="10.2.0.3",
        username="sprayer",
        users=[f"u{i}" for i in range(10)],
        spacing_seconds=10,
    )
    alert = DetectionService(db).detect_password_spraying(
        last, minimum_users=5, minimum_failures=10, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 75  # >= 10 users


# ---------------------------------------------------------------------
# Distributed: 50 base, 65 at >=5 IPs, 75 at >=20 events,
# 85 at >=10 IPs and >=30 events
# ---------------------------------------------------------------------
def test_distributed_base_confidence(db, event_factory):
    ips = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
    last = _failures(
        event_factory, 12,
        source_ip=ips[0],
        username="root",
        ips=ips,
        spacing_seconds=5,
    )
    alert = DetectionService(db).detect_distributed_bruteforce(
        last, minimum_source_ips=3, minimum_failures=10, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 50  # < 5 IPs, < 20 events


def test_distributed_confidence_at_5_ips(db, event_factory):
    ips = [f"10.0.2.{i}" for i in range(1, 6)]
    last = _failures(
        event_factory, 15,
        source_ip=ips[0],
        username="root",
        ips=ips,
        spacing_seconds=5,
    )
    alert = DetectionService(db).detect_distributed_bruteforce(
        last, minimum_source_ips=3, minimum_failures=10, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 65  # >= 5 source IPs


# ---------------------------------------------------------------------
# Failed -> success: 3 -> 70, 5 -> 80, 10 -> 90
# ---------------------------------------------------------------------
def test_failed_success_confidence_increases_with_failures(
    db, event_factory
):
    for count, expected in [(3, 70), (5, 80), (10, 90)]:
        start = datetime(2026, 9, 1, 11, 0, 0)

        # A UNIQUE source IP per iteration: otherwise the second and third
        # iterations hit alert deduplication (same open alert key) and
        # create_alert_if_new returns None.
        attack_ip = f"10.3.0.{count}"

        for i in range(count):
            event_factory(
                start + timedelta(seconds=i),
                source_ip=attack_ip,
                username="admin",
            )

        success_event = event_factory(
            start + timedelta(seconds=count + 5),
            source_ip=attack_ip,
            username="admin",
            result="success",
        )

        alert = DetectionService(db).detect_failed_then_success(
            success_event,
            minimum_failures=3,
            window_seconds=300,
        )
        assert alert is not None
        assert alert.confidence == expected

        db.query(success_event.__class__).delete()
        db.commit()


# ---------------------------------------------------------------------
# Credential stuffing: 50 base, 65 at >50 failures, 80 at >20 users
# ---------------------------------------------------------------------
def test_credential_stuffing_base_confidence(db, event_factory):
    last = _failures(
        event_factory, 25,
        source_ip="10.4.0.1",
        username="stuffing",
        users=[f"u{i}" for i in range(10)],
        spacing_seconds=3,
    )
    alert = DetectionService(db).detect_credential_stuffing(
        last, minimum_users=10, minimum_failures=20, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 50  # <= 50 failures, <= 20 users


def test_credential_stuffing_confidence_over_50_failures(db, event_factory):
    last = _failures(
        event_factory, 51,
        source_ip="10.4.0.2",
        username="stuffing",
        users=[f"v{i}" for i in range(10)],
        spacing_seconds=1,
    )
    alert = DetectionService(db).detect_credential_stuffing(
        last, minimum_users=10, minimum_failures=20, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 65  # > 50 failures


def test_credential_stuffing_confidence_over_20_users(db, event_factory):
    last = _failures(
        event_factory, 25,
        source_ip="10.4.0.3",
        username="stuffing",
        users=[f"w{i}" for i in range(21)],
        spacing_seconds=1,
    )
    alert = DetectionService(db).detect_credential_stuffing(
        last, minimum_users=10, minimum_failures=20, window_seconds=600,
    )
    assert alert is not None
    assert alert.confidence == 80  # > 20 distinct users


# ---------------------------------------------------------------------
# Low and slow: 50 base, 60 at >15 events
# (intervals: a 1h window / 5 intervals caps distinct intervals at 5,
# so the >7-interval rule is unreachable by the current configuration).
# ---------------------------------------------------------------------
def test_low_and_slow_base_confidence(db, event_factory):
    last = _failures(
        event_factory, 10,
        source_ip="10.5.0.1",
        username="slow",
        spacing_seconds=300,
    )
    alert = DetectionService(db).detect_low_and_slow(
        last, minimum_failures=10, window_seconds=3600,
        minimum_active_intervals=5,
    )
    assert alert is not None
    assert alert.confidence == 50


def test_low_and_slow_confidence_over_15_events(db, event_factory):
    last = _failures(
        event_factory, 16,
        source_ip="10.5.0.2",
        username="slow",
        spacing_seconds=180,
    )
    alert = DetectionService(db).detect_low_and_slow(
        last, minimum_failures=10, window_seconds=3600,
        minimum_active_intervals=5,
    )
    assert alert is not None
    assert alert.confidence == 60  # > 15 events