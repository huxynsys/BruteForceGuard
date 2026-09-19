"""Liveness and readiness probes (Phase 9.6).

``GET /health`` is a lightweight liveness check: it never touches the
database, so an orchestrator can tell "the process is alive" apart from
"the process can serve traffic".

``GET /health/ready`` verifies readiness — the configuration is valid and
PostgreSQL answers a trivial query — and returns HTTP 503 when the database
is unavailable.  It never leaks connection strings, credentials, tracebacks
or filesystem paths, only a fixed, human-readable reason.
"""

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])

SERVICE_NAME = "bruteforceguard-api"
SERVICE_VERSION = "0.5.0"


@router.get("/health")
def health_check():
    """Liveness: the API process is running (no database access)."""
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
    }


@router.get("/health/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Readiness: configuration valid and the database reachable."""
    from app.intelligence.config import validate_risk_config

    checks = {"configuration": "ok", "database": "ok"}

    try:
        validate_risk_config()
    except Exception as exc:  # noqa: BLE001 - reported generically
        checks["configuration"] = "error"
        logger.error("readiness configuration check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": SERVICE_NAME,
                "checks": checks,
                "detail": "invalid application configuration",
            },
        )

    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - reported generically
        checks["database"] = "error"
        logger.warning("readiness database check failed: %s", exc)
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "service": SERVICE_NAME,
                "checks": checks,
                "detail": "database unavailable",
            },
        )

    return {
        "status": "ready",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "environment": settings.app_env,
        "checks": checks,
    }