"""Shared pytest fixtures for the BruteForceGuard backend.

The suite runs against an in-memory SQLite database so no external
PostgreSQL server is required.  The PostgreSQL-specific column types
(INET / JSONB) are compiled to their closest SQLite equivalents so the
same models can be created on either database.
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent

# Ensure a usable database URL exists before `app.*` is imported.
# A real environment variable always wins over this test-only fallback.
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import Base

# Import the models so their tables are registered on Base.metadata.
import app.models.auth_event  # noqa: F401
import app.models.alert  # noqa: F401
import app.models.attack_session  # noqa: F401
import app.models.threat_indicator  # noqa: F401


@compiles(INET, "sqlite")
def _compile_inet(element, compiler, **kw):
    return "VARCHAR(50)"


@compiles(JSONB, "sqlite")
def _compile_jsonb(element, compiler, **kw):
    return "JSON"


@pytest.fixture(scope="session")
def test_engine():
    """Single shared in-memory SQLite engine for the whole session."""
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    yield engine
    engine.dispose()


@pytest.fixture()
def db(test_engine):
    """Fresh, empty database session for every test."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    session = Session(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
    )
    yield session
    session.close()


@pytest.fixture()
def alert_factory(db):
    """Factory that persists an Alert directly through ``db``."""

    from app.models.alert import Alert

    def _make(
        *,
        alert_type="single_account_bruteforce",
        severity="high",
        confidence=70,
        title="Test Alert",
        description="Test detection",
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
        status="open",
        evidence=None,
    ):
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            source_ip=source_ip,
            username=username,
            service=service,
            status=status,
            evidence=evidence or {},
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert

    return _make


@pytest.fixture()
def session_factory(db):
    """Factory that persists an AttackSession directly through ``db``."""

    from app.models.attack_session import AttackSession

    def _make(
        *,
        started_at=None,
        session_type="single_account",
        severity="high",
        event_count=1,
        source_ips=None,
        usernames=None,
        services=None,
        detection_types=None,
        status="active",
    ):
        started_at = started_at or datetime.now(timezone.utc)

        session = AttackSession(
            started_at=started_at,
            last_seen_at=started_at,
            session_type=session_type,
            severity=severity,
            event_count=event_count,
            source_ips=source_ips if source_ips is not None else [],
            usernames=usernames if usernames is not None else [],
            services=services if services is not None else [],
            detection_types=(
                detection_types if detection_types is not None else []
            ),
            status=status,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    return _make


@pytest.fixture()
def event_factory(db):
    """Factory that persists an AuthEvent directly through ``db``."""
    from app.models.auth_event import AuthEvent

    def _make(
        timestamp,
        *,
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
        **extra,
    ):
        event = AuthEvent(
            timestamp=timestamp,
            source=source,
            source_ip=source_ip,
            username=username,
            result=result,
            service=service,
            port=port,
            **extra,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    return _make


@pytest.fixture()
def client(test_engine, monkeypatch):
    """FastAPI TestClient with every dependency pointed at SQLite."""
    from fastapi.testclient import TestClient

    import app.main as main_module
    from app.main import app
    from app.db.database import get_db

    def _override_get_db():
        session = Session(
            bind=test_engine,
            autoflush=False,
            autocommit=False,
        )
        try:
            yield session
        finally:
            session.close()

    # Clean slate for this test.
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    app.dependency_overrides[get_db] = _override_get_db

    # Keep the application lifespan (create_all) on the SQLite engine.
    monkeypatch.setattr(main_module, "engine", test_engine)

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()