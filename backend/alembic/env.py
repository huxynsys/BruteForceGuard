"""Alembic migration environment for BruteForceGuard.

Reads the database URL from the environment (DATABASE_URL), falling back to
the application settings, so the same migrations work for local, test and
containerized PostgreSQL deployments.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.ext.compiler import compiles

# Register SQLite compilers for the PostgreSQL-specific column types so the
# same models/migrations can also be exercised against SQLite in tests.
@compiles(INET, "sqlite")
def _compile_inet(element, compiler, **kw):
    return "VARCHAR(50)"


@compiles(JSONB, "sqlite")
def _compile_jsonb(element, compiler, **kw):
    return "JSON"


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Import the models so their tables are registered on Base.metadata.
from app.db.database import Base  # noqa: E402
import app.models.auth_event  # noqa: E402,F401
import app.models.alert  # noqa: E402,F401
import app.models.attack_session  # noqa: E402,F401
import app.models.threat_indicator  # noqa: E402,F401

target_metadata = Base.metadata

# Resolve the database URL.  Precedence: an explicit DATABASE_URL environment
# variable, then an explicit sqlalchemy.url in alembic.ini (used by the
# programmatic migration tests), then the application settings (which itself
# comes from DATABASE_URL in .env).
try:
    from app.core.config import settings
    default_url = settings.database_url
except Exception:  # pragma: no cover - settings may be unavailable offline
    default_url = "sqlite+pysqlite:///:memory:"

ini_url = (config.get_main_option("sqlalchemy.url") or "").strip()
database_url = os.environ.get("DATABASE_URL") or ini_url or default_url
config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
