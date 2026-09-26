"""Phase 8 Parts 4, 5 and 7 — database failure and transaction integrity.

The API must fail predictably (never hang) when the database raises, must
not leave partially-created alerts/sessions behind, and must keep
ingesting events when only *detection* fails.
"""

from __future__ import annotations

import logging

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.main import app
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent
from app.services.detection_service import DetectionService
from app.services.event_service import EventService


def _payload(**overrides) -> dict:
    payload = {
        "timestamp": "2026-09-08T10:42:01Z",
        "source": "linux",
        "source_ip": "203.0.113.7",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    return payload


def _count(bind, model) -> int:
    with Session(bind=bind) as check:
        return check.scalar(select(func.count()).select_from(model))


def _raised_operational_error() -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception("database is gone"))


# ---------------------------------------------------------------------------
# Detection failure must not break ingestion (design guarantee)
# ---------------------------------------------------------------------------


def test_event_ingestion_survives_detection_failure(
    client,
    test_engine,
    monkeypatch,
    caplog,
):
    def boom(self, *args, **kwargs):  # noqa: ANN001
        raise _raised_operational_error()

    monkeypatch.setattr(
        DetectionService,
        "detect_single_account_bruteforce",
        boom,
    )

    with caplog.at_level(logging.WARNING):
        response = client.post("/api/v1/events/", json=_payload())

    assert response.status_code == 200
    # The event itself is persisted even though detection failed...
    assert _count(test_engine, AuthEvent) == 1
    # ...and no partial alert/session was left behind.
    assert _count(test_engine, Alert) == 0
    assert _count(test_engine, AttackSession) == 0
    assert "failed for event" in caplog.text


# ---------------------------------------------------------------------------
# Read-path database outage: predictable 500, never a hang
# ---------------------------------------------------------------------------


def test_database_outage_returns_500_without_hanging(client, monkeypatch):
    strict = TestClient(app, raise_server_exceptions=False)

    def boom(self, limit: int = 100, skip: int = 0):  # noqa: ANN001
        raise _raised_operational_error()

    monkeypatch.setattr(EventService, "get_events", boom)

    response = strict.get("/api/v1/events/")

    assert response.status_code == 500


def test_database_outage_on_alerts_returns_500_without_hanging(
    client,
    monkeypatch,
):
    """Simulate the connection dropping during a query.

    SQLite's shared in-memory connection cannot be physically taken away, so
    the failure is injected at the query-construction point, which is where
    a real ``OperationalError`` would surface.
    """
    strict = TestClient(app, raise_server_exceptions=False)

    def boom(*args, **kwargs):  # noqa: ANN001
        raise _raised_operational_error()

    monkeypatch.setattr("app.services.alert_service.select", boom)

    response = strict.get("/api/v1/alerts/")

    assert response.status_code == 500


# ---------------------------------------------------------------------------
# Transaction integrity / rollback (Part 5)
# ---------------------------------------------------------------------------


def test_rollback_discards_a_partially_written_alert(db):
    alert = Alert(
        alert_type="single_account_bruteforce",
        severity="high",
        confidence=70,
        title="Rollback probe",
        description="should never be persisted",
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        status="open",
        evidence={},
    )
    db.add(alert)
    db.flush()  # written inside the transaction, not yet committed
    db.rollback()  # the operation "failed"

    assert db.scalars(select(Alert)).all() == []


def test_rollback_discards_a_partially_written_session(db, alert_factory):
    alert = alert_factory()

    session = AttackSession(
        started_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        session_type="single_account",
        severity="high",
        event_count=1,
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
        detection_types=["single_account"],
        status="active",
    )
    db.add(session)
    db.flush()
    db.rollback()

    # No orphan session survived, and the previously committed alert is intact.
    assert db.scalars(select(AttackSession)).all() == []
    assert [a.id for a in db.scalars(select(Alert)).all()] == [alert.id]


def test_failed_session_integration_leaves_no_orphan_rows(
    client,
    test_engine,
    monkeypatch,
):
    """If session correlation fails, no session rows appear (no orphans)."""
    from app.services.attack_session_service import (
        AttackSessionIntegrationService,
    )

    def boom(self, *args, **kwargs):  # noqa: ANN001
        raise _raised_operational_error()

    monkeypatch.setattr(
        AttackSessionIntegrationService,
        "process_alert",
        boom,
    )

    for _ in range(6):
        response = client.post("/api/v1/events/", json=_payload())
        assert response.status_code == 200

    events = _count(test_engine, AuthEvent)
    alerts = _count(test_engine, Alert)
    sessions = _count(test_engine, AttackSession)

    # Ingestion and detection still completed...
    assert events == 6
    assert alerts >= 1
    # ...but the failed integration created nothing.
    assert sessions == 0

    # Every persisted alert must reference a real event-side origin.
    with Session(bind=test_engine) as check:
        for alert in check.scalars(select(Alert)).all():
            assert alert.source_ip is not None
            assert alert.alert_type
