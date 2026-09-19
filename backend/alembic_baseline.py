"""Resolve the correct Alembic action for the database at startup.

Historically BruteForceGuard's application startup called
``Base.metadata.create_all``, so databases created by older images are
already consistent with the models (i.e. with the migration head).  Phase 9.2
removed that startup behaviour — Alembic is the authoritative migration
mechanism now — but those legacy ``create_all`` databases still exist and
must keep starting cleanly, so the container entrypoint still has to decide
*which* Alembic bookkeeping action to take:

* ``upgrade``   - run ``alembic upgrade head`` (fresh database, or an
                  Alembic-managed database that still needs migrations)
* ``stamp-head``- the schema already matches the head revision (a Phase 7
                  ``create_all`` database, or a database that was previously
                  stamped to ``0001_phase6_base`` even though the Phase 7
                  columns already exist) -> ``alembic stamp head``
* ``stamp-0001``- a Phase 6 ``create_all`` database (tables exist but the
                  Phase 7 ``threat_indicators`` table does not) -> the
                  documented procedure: ``alembic stamp 0001_phase6_base``
                  followed by ``alembic upgrade head``

Usage:

    python alembic_baseline.py [DATABASE_URL]

With no argument the URL comes from the application settings / environment,
exactly like ``alembic/env.py``.  Prints a single action token.
"""

from __future__ import annotations

import sys

from sqlalchemy import create_engine, inspect

PHASE7_MARKER_TABLE = "threat_indicators"
ALEMBIC_VERSION_TABLE = "alembic_version"
PHASE6_BASELINE = "0001_phase6_base"


def resolve_action(tables: set[str]) -> str:
    """Map the inspected table set to an entrypoint action token."""
    has_version = ALEMBIC_VERSION_TABLE in tables
    schema_is_current = PHASE7_MARKER_TABLE in tables

    if has_version:
        # Alembic-managed database.  If the schema already matches head
        # (e.g. a previous entrypoint stamped 0001 onto a Phase 7
        # create_all database), re-stamp to head; otherwise upgrade.
        return "stamp-head" if schema_is_current else "upgrade"
    if not tables:
        # Fresh database: build the full schema through the migrations.
        return "upgrade"
    if schema_is_current:
        # Phase 7 create_all database: already consistent with head.
        return "stamp-head"
    # Phase 6 create_all database: stamp the baseline, then upgrade.
    return "stamp-0001"


def main() -> int:
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        from app.core.config import settings

        url = settings.database_url

    engine = create_engine(url)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    action = resolve_action(tables)
    print(action)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
