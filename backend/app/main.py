from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.attack_sessions import router as attack_sessions_router
from app.api.dashboard import router as dashboard_router  # Phase 6
from app.api.intelligence import router as intelligence_router  # Phase 7
from app.db.database import Base, engine
from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.threat_indicator import ThreatIndicator


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables
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
)

# CORS for the Phase 6 dashboard frontend (Vite dev server).
# Development origins only; production deployments should restrict this.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register routers
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(attack_sessions_router)
app.include_router(dashboard_router)  # Phase 6
app.include_router(intelligence_router)  # Phase 7


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "bruteforceguard-api",
        "version": "0.5.0",
    }