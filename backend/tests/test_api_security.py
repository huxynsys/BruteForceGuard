"""Phase 9.5 — API security: configurable CORS and sanitized error responses."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import DEVELOPMENT_CORS_ORIGINS, Settings
from app.main import app
from app.services.event_service import EventService

PROD_DB = "postgresql+psycopg://bfg_user:secret@postgres:5432/bruteforceguard"


# ---------------------------------------------------------------------------
# CORS is configuration-driven
# ---------------------------------------------------------------------------


def test_development_cors_origin_is_allowed(client):
    origin = DEVELOPMENT_CORS_ORIGINS[0]

    response = client.get("/api/v1/events/", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_unconfigured_origin_gets_no_cors_grant(client):
    response = client.get(
        "/api/v1/events/",
        headers={"Origin": "https://evil.example.com"},
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_preflight_from_a_configured_origin_is_accepted(client):
    origin = DEVELOPMENT_CORS_ORIGINS[0]

    response = client.options(
        "/api/v1/events/",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_production_allows_only_explicitly_configured_origins():
    settings = Settings(
        app_env="production",
        database_url=PROD_DB,
        cors_allowed_origins="https://soc.example.com",
    )

    assert settings.cors_origins == ["https://soc.example.com"]
    assert "http://localhost:5173" not in settings.cors_origins


# ---------------------------------------------------------------------------
# Errors never expose internals
# ---------------------------------------------------------------------------


def test_internal_error_response_is_generic(client, monkeypatch):
    """A database-style failure must not leak SQL, DSNs, paths or tracebacks."""
    strict = TestClient(app, raise_server_exceptions=False)

    def boom(self, limit: int = 100, skip: int = 0):  # noqa: ANN001
        raise RuntimeError(
            "connection to "
            "postgresql+psycopg://bfg_user:supersecret@db:5432/x failed at "
            "/app/app/services/event_service.py"
        )

    monkeypatch.setattr(EventService, "get_events", boom)

    response = strict.get("/api/v1/events/")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}

    text = response.text
    assert "supersecret" not in text
    assert "postgresql" not in text
    assert "event_service" not in text
    assert "Traceback" not in text


def test_unknown_route_returns_a_plain_404(client):
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_validation_errors_stay_structured(client):
    response = client.post("/api/v1/events/", json={"source": "only-a-source"})

    assert response.status_code == 422
    assert "detail" in response.json()
    assert "Traceback" not in response.text


# ---------------------------------------------------------------------------
# Development-only behaviour stays development-only
# ---------------------------------------------------------------------------


def test_schema_docs_are_enabled_in_development(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_schema_docs_are_disabled_in_production():
    settings = Settings(
        app_env="production",
        database_url=PROD_DB,
        cors_allowed_origins="https://soc.example.com",
    )

    assert settings.docs_enabled is False