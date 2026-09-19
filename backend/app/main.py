import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.attack_sessions import router as attack_sessions_router
from app.api.dashboard import router as dashboard_router  # Phase 6
from app.api.health import router as health_router  # Phase 9.6
from app.api.intelligence import router as intelligence_router  # Phase 7
from app.core.config import settings
from app.core.logging import configure_logging
from app.db.database import Base, engine
from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.threat_indicator import ThreatIndicator

configure_logging()

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Phase 9.2: Alembic is the authoritative schema mechanism, so startup no
    # longer creates tables.  CREATE_ALL_ON_STARTUP exists only for legacy
    # `create_all` workflows (development/tests) and is rejected in
    # production by the configuration validator.
    if settings.create_all_on_startup:
        logger.warning(
            "CREATE_ALL_ON_STARTUP is enabled: creating tables via "
            "metadata.create_all (Alembic remains authoritative)"
        )
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="BruteForceGuard API",
    description=(
        "Authentication threat detection and brute-force "
        "monitoring platform."
    ),
    version="0.5.0",  # Phase 6: dashboard & visualization
    lifespan=lifespan,
    # Interactive docs are development-only; production exposes no schema UI.
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

# CORS is configuration-driven (Phase 9.5):
#   * CORS_ALLOWED_ORIGINS unset        -> development origins (Vite dev server)
#   * CORS_ALLOWED_ORIGINS configured   -> exactly those origins
#   * APP_ENV=production                -> an explicit list is required and the
#                                          '*' wildcard is rejected at startup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return a generic 500 without exposing internals (Phase 9.5).

    SQL/connection errors, tracebacks and filesystem paths stay in the
    server log; the client only receives a fixed message.
    """
    logger.exception(
        "unhandled error handling %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# Register routers
app.include_router(health_router)  # /health, /health/ready
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(attack_sessions_router)
app.include_router(dashboard_router)  # Phase 6
app.include_router(intelligence_router)  # Phase 7