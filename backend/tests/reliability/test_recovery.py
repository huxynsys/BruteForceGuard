"""Phase 8 Parts 8, 9 and 10 — restart recovery, duplicates, concurrency.

These tests prove *which* state is authoritative.  All detection, alerting
and session state must live in the database so it survives a process
restart; nothing security-relevant may exist only in memory.

A file-backed SQLite database is used so an engine can genuinely be
disposed and re-opened to emulate a backend restart.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent
from app.services.detection_service import DetectionService


def _connect(url: str):
    return create_engine(url, connect_args={"check_same_thread": False})


def _event(
    *,
    source_ip: str = "10.0.0.5",
    username: str = "admin",
    result: str = "failure",
    service: str = "ssh",
    timestamp: datetime | None = None,
) -> AuthEvent:
    return AuthEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source="linux",
        source_ip=source_ip,
        username=username,
        result=result,
        service=service,
        port=22,
    )


@pytest.fixture()
def db_url(tmp_path):
    """A fresh, migrated, file-backed database URL."""
    path = tmp_path / "recovery.sqlite"
    url = f"sqlite+pysqlite:///{path.as_posix()}"
    engine = _connect(url)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    return url


# ---------------------------------------------------------------------------
# Part 8 — restart recovery
# ---------------------------------------------------------------------------


def test_persisted_state_survives_a_backend_restart(db_url):
    alert_id = session_id = event_id = None

    # ---- process #1 ----
    engine = _connect(db_url)
    with Session(bind=engine) as db:
        event = _event()
        db.add(event)
        db.commit()
        event_id = event.id

        alert = Alert(
            alert_type="single_account_bruteforce",
            severity="high",
            confidence=70,
            title="Restart probe",
            description="must survive a restart",
            source_ip="10.0.0.5",
            username="admin",
            service="ssh",
            status="open",
            evidence={"failure_count": 5},
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id

        attack_session = AttackSession(
            started_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            session_type="single_account",
            severity="high",
            event_count=5,
            source_ips=["10.0.0.5"],
            usernames=["admin"],
            services=["ssh"],
            detection_types=["single_account"],
            status="active",
        )
        db.add(attack_session)
        db.commit()
        session_id = attack_session.id
    engine.dispose()  # <- "the backend restarts"

    # ---- process #2: nothing is in memory any more ----
    engine = _connect(db_url)
    with Session(bind=engine) as db:
        assert db.get(AuthEvent, event_id) is not None
        assert db.get(Alert, alert_id) is not None
        assert db.get(AttackSession, session_id) is not None

        # Identifiers are stable across the restart.
        assert db.scalar(select(func.count()).select_from(AuthEvent)) == 1
        assert db.scalar(select(func.count()).select_from(Alert)) == 1
    engine.dispose()


def test_detection_history_is_rebuilt_from_the_database_after_restart(db_url):
    """Correlation windows come from the DB, not from process memory."""
    base = datetime.now(timezone.utc) - timedelta(minutes=1)

    # ---- process #1: four failures already stored ----
    engine = _connect(db_url)
    with Session(bind=engine) as db:
        for i in range(4):
            db.add(
                _event(
                    source_ip="10.9.9.9",
                    timestamp=base + timedelta(seconds=i),
                )
            )
        db.commit()
    engine.dispose()

    # ---- process #2: the 5th failure must still cross the threshold ----
    engine = _connect(db_url)
    with Session(bind=engine) as db:
        new_event = _event(
            source_ip="10.9.9.9",
            timestamp=base + timedelta(seconds=30),
        )
        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        alert = DetectionService(db).detect_single_account_bruteforce(
            new_event,
            threshold=5,
            window_seconds=300,
        )

        assert alert is not None
        assert alert.alert_type == "single_account_bruteforce"
        # The detector must have seen all five persisted attempts.
        assert alert.evidence["failure_count"] == 5
    engine.dispose()


# ---------------------------------------------------------------------------
# Part 9 — duplicate events
# ---------------------------------------------------------------------------


def _api_payload(**overrides) -> dict:
    payload = {
        "timestamp": "2026-09-08T10:42:01Z",
        "source": "linux",
        "source_ip": "203.0.113.9",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    return payload


def test_duplicate_events_are_separate_authentication_attempts(
    client,
    test_engine,
):
    """Preserved Phase 5/6 semantics: ingestion performs no event-level dedup.

    An identical payload repeated is a repeated authentication attempt, so
    it must be stored and must count towards detection thresholds.  This
    behaviour is asserted, not changed.
    """
    payload = _api_payload()

    for _ in range(5):
        assert client.post("/api/v1/events/", json=payload).status_code == 200

    with Session(bind=test_engine) as db:
        assert db.scalar(select(func.count()).select_from(AuthEvent)) == 5
        # The five duplicates were sufficient to trip the ssh threshold.
        assert db.scalar(select(func.count()).select_from(Alert)) == 1


def test_repeated_attempts_do_not_multiply_alerts(client, test_engine):
    """Alerts (unlike events) *are* deduplicated per open attack."""
    payload = _api_payload()

    for _ in range(12):
        assert client.post("/api/v1/events/", json=payload).status_code == 200

    with Session(bind=test_engine) as db:
        assert db.scalar(select(func.count()).select_from(AuthEvent)) == 12
        alerts = list(db.scalars(select(Alert)))
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Part 10 — concurrency / interleaving
# ---------------------------------------------------------------------------


def test_interleaved_source_ips_do_not_contaminate_each_other(
    client,
    test_engine,
):
    """Two interleaved attacks must stay two independent attacks."""
    ips = ["198.51.100.1", "198.51.100.2"]

    for i in range(10):
        response = client.post(
            "/api/v1/events/",
            json=_api_payload(source_ip=ips[i % 2]),
        )
        assert response.status_code == 200

    with Session(bind=test_engine) as db:
        alerts = list(db.scalars(select(Alert)))

        assert len(alerts) == 2
        assert {alert.source_ip for alert in alerts} == set(ips)
        # Neither attack absorbed the other's attempts.
        for alert in alerts:
            assert alert.evidence["failure_count"] == 5


def test_interleaved_usernames_do_not_contaminate_each_other(
    client,
    test_engine,
):
    users = ["alice", "bob"]

    for i in range(10):
        response = client.post(
            "/api/v1/events/",
            json=_api_payload(username=users[i % 2]),
        )
        assert response.status_code == 200

    with Session(bind=test_engine) as db:
        alerts = list(db.scalars(select(Alert)))

        assert len(alerts) == 2
        assert {alert.username for alert in alerts} == set(users)
        for alert in alerts:
            assert alert.evidence["failure_count"] == 5


def test_interleaved_services_do_not_contaminate_each_other(
    client,
    test_engine,
):
    """Services with different thresholds must be evaluated independently."""
    services = ["ssh", "web"]

    for i in range(20):
        response = client.post(
            "/api/v1/events/",
            json=_api_payload(service=services[i % 2]),
        )
        assert response.status_code == 200

    with Session(bind=test_engine) as db:
        alerts = list(db.scalars(select(Alert)))

        # ssh trips at 5, web at 10; both reach their own threshold.
        assert len(alerts) == 2
        assert {alert.service for alert in alerts} == set(services)