"""Application logging configuration (Phase 9.1).

``LOG_LEVEL`` is applied once, when the application is imported, so the
application logger and the SQLAlchemy/Alembic loggers all honour the
configured level.  Configuration itself lives in :mod:`app.core.config`.
"""

from __future__ import annotations

import logging

from app.core.config import settings

LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"

_configured = False


def configure_logging() -> None:
    """Apply the configured log level to the root logger (idempotent)."""
    global _configured

    if _configured:
        return

    level = settings.log_level_value
    logging.basicConfig(level=level, format=LOG_FORMAT)
    logging.getLogger().setLevel(level)

    _configured = True