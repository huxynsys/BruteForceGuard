"""Alembic migration tests (Phase 7, Part 1 / Part 16 - Database).

Runs the real Alembic migrations against a temporary file-backed SQLite
database (the INET/JSONB PostgreSQL types compile to SQLite equivalents in
``alembic/env.py``) and verifies:

* a fresh database upgraded to head contains the full Phase 7 schema
* the migrated columns match the SQLAlchemy models exactly
* an existing Phase 6 database upgrades additively and preserves its data
* the documented ``stamp`` procedure works for ``create_all`` databases
"""

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from app.db.database import Base

# Import the models so Base.metadata knows every table.
import app.models.auth_event  # noqa: F401
import app.models.alert  # noqa: F401
import app.models.attack_session  # noqa: F401
import app.models.threat_indicator  # noqa: F401

BACKEND_DIR = Path(__file__).resolve().parent.parent
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@pytest.fixture()
def migrated_db_url(tmp_path, monkeypatch):
    """Provide a temp SQLite URL with the DATABASE_URL env var cleared.

    The env var is removed so ``alembic/env.py`` uses the URL configured on
    the Alembic Config object instead of the shared pytest in-memory DB.
    """
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return f"sqlite:///{(tmp_path / 'migration_test.db').as_posix()}"


def _upgrade(db_url: str, revision: str) -> None:
    command.upgrade(_alembic_config(db_url), revision)


def _column_names(engine, table: str) -> set[str]:
    inspector = sa.inspect(engine)
    return {col["name"] for col in inspector.get_columns(table)}


def _phase6_seed(engine) -> None:
    """Insert Phase 6-era rows through the pre-upgrade (0001) schema."""
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO auth_events (timestamp, source, source_ip, result) "
                "VALUES (CURRENT_TIMESTAMP, 'test', '10.0.0.1', 'failure')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO alerts (alert_type, severity, title, description, "
                "confidence, status) VALUES "
                "('single_account_bruteforce', 'high', 'Pre-upgrade alert', "
                "'created before the Phase 7 upgrade', 70, 'open')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO attack_sessions (started_at, last_seen_at, "
                "session_type, severity, event_count, status) VALUES "
                "(CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'single_account', "
                "'high', 5, 'active')"
            )
        )


# ---------------------------------------------------------------------------
# Fresh database -> full Phase 7 schema
# ---------------------------------------------------------------------------
def test_fresh_database_upgrade_to_head(migrated_db_url):
    """``alembic upgrade head`` on a fresh DB creates the Phase 7 schema."""
    _upgrade(migrated_db_url, "head")
    engine = sa.create_engine(migrated_db_url)
    try:
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())
        assert {
            "auth_events", "alerts", "attack_sessions", "threat_indicators",
        } <= tables

        alert_cols = _column_names(engine, "alerts")
        for column in (
            "risk_score", "risk_level", "risk_factors",
            "threat_intelligence", "source_reputation", "mitre_context",
        ):
            assert column in alert_cols

        session_cols = _column_names(engine, "attack_sessions")
        for column in (
            "risk_score", "risk_level", "risk_factors", "behavioral_profile",
        ):
            assert column in session_cols

        indicator_cols = _column_names(engine, "threat_indicators")
        for column in (
            "id", "indicator", "indicator_type", "confidence", "threat_type",
            "source", "tags", "first_seen", "last_seen", "active",
            "created_at", "updated_at",
        ):
            assert column in indicator_cols
    finally:
        engine.dispose()


def test_migrated_schema_matches_models(migrated_db_url):
    """Migrated tables expose exactly the columns the SQLAlchemy models define."""
    _upgrade(migrated_db_url, "head")
    engine = sa.create_engine(migrated_db_url)
    try:
        for table in (
            "auth_events", "alerts", "attack_sessions", "threat_indicators",
        ):
            expected = {col.name for col in Base.metadata.tables[table].columns}
            assert _column_names(engine, table) == expected
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Existing Phase 6 database -> Phase 7 upgrade (data preserved)
# ---------------------------------------------------------------------------
def test_phase6_database_upgrade_preserves_data(migrated_db_url):
    """Existing Phase 6 rows survive the additive Phase 7 upgrade."""
    _upgrade(migrated_db_url, "0001_phase6_base")
    engine = sa.create_engine(migrated_db_url)
    try:
        _phase6_seed(engine)
    finally:
        engine.dispose()

    _upgrade(migrated_db_url, "head")

    engine = sa.create_engine(migrated_db_url)
    try:
        with engine.connect() as conn:
            alert = conn.execute(
                sa.text(
                    "SELECT title, status, risk_score, risk_level FROM alerts"
                )
            ).one()
            assert alert.title == "Pre-upgrade alert"
            assert alert.status == "open"
            # New columns take their safe server defaults for existing rows.
            assert alert.risk_score == 0
            assert alert.risk_level == "informational"

            session_row = conn.execute(
                sa.text(
                    "SELECT event_count, status, risk_score, risk_level "
                    "FROM attack_sessions"
                )
            ).one()
            assert session_row.event_count == 5
            assert session_row.status == "active"
            assert session_row.risk_score == 0
            assert session_row.risk_level == "informational"

            event_row = conn.execute(
                sa.text("SELECT source_ip, result FROM auth_events")
            ).one()
            assert event_row.source_ip == "10.0.0.1"
            assert event_row.result == "failure"
    finally:
        engine.dispose()


def test_stamp_procedure_for_create_all_database(migrated_db_url):
    """A ``create_all`` Phase 6 DB (no alembic_version) follows the
    documented procedure: ``alembic stamp 0001_phase6_base`` + ``upgrade head``."""
    # Build the Phase 6 schema exactly as create_all would (via revision 0001)
    # then remove alembic_version to simulate a create_all-managed database.
    _upgrade(migrated_db_url, "0001_phase6_base")
    engine = sa.create_engine(migrated_db_url)
    try:
        _phase6_seed(engine)
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE alembic_version"))
    finally:
        engine.dispose()

    command.stamp(_alembic_config(migrated_db_url), "0001_phase6_base")
    _upgrade(migrated_db_url, "head")

    engine = sa.create_engine(migrated_db_url)
    try:
        assert "threat_indicators" in sa.inspect(engine).get_table_names()
        with engine.connect() as conn:
            alert = conn.execute(
                sa.text("SELECT title, risk_score FROM alerts")
            ).one()
            assert alert.title == "Pre-upgrade alert"
            assert alert.risk_score == 0
    finally:
        engine.dispose()


