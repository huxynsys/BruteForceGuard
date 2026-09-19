"""Phase 9.6 — liveness and readiness probes.

Liveness must never touch the database; readiness must verify the database
and report 503 without leaking connection details.
"""

from __future__ import annotations

from sqlalchemy.exc import OperationalError

from app.api.health import SERVICE_NAME, SERVICE_VERSION
from app.db.database import get_db
from app.main import app


class _UnavailableSession:
    """Session stand-in whose queries always fail (database outage)."""

    def execute(self, *args, **kwargs):
        raise OperationalError("SELECT 1", {}, Exception("database is gone"))

    def close(self):
        pass


def _use_session(session):
    """Temporarily replace the ``get_db`` override, returning the previous one."""
    previous = app.dependency_overrides[get_db]

    def _override():
        yield session

    app.dependency_overrides[get_db] = _override
    return previous


def _restore(previous) -> None:
    app.dependency_overrides[get_db] = previous


# ---------------------------------------------------------------------------
# Liveness
# ---------------------------------------------------------------------------


def test_liveness_reports_healthy(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
    }


def test_liveness_stays_healthy_while_the_database_is_down(client):
    previous = _use_session(_UnavailableSession())
    try:
        response = client.get("/health")
    finally:
        _restore(previous)

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------


def test_readiness_reports_ready_with_a_working_database(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"] == {"configuration": "ok", "database": "ok"}
    assert body["service"] == SERVICE_NAME


def test_readiness_returns_503_when_the_database_is_unavailable(client):
    previous = _use_session(_UnavailableSession())
    try:
        response = client.get("/health/ready")
    finally:
        _restore(previous)

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "error"
    assert body["detail"] == "database unavailable"


def test_readiness_failure_does_not_leak_internals(client):
    """Connection strings, credentials and tracebacks must never be returned."""

    class _LeakySession:
        def execute(self, *args, **kwargs):
            raise OperationalError(
                "SELECT 1",
                {},
                Exception(
                    "connection to "
                    "postgresql+psycopg://bfg_user:supersecret@db:5432/x failed"
                ),
            )

        def close(self):
            pass

    previous = _use_session(_LeakySession())
    try:
        response = client.get("/health/ready")
    finally:
        _restore(previous)

    assert response.status_code == 503
    text = response.text
    assert "supersecret" not in text
    assert "postgresql+psycopg" not in text
    assert "Traceback" not in text