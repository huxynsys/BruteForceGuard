from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.events import router as events_router
from app.api.alerts import router as alerts_router  # NEW
from app.db.database import Base, engine
from app.models.auth_event import AuthEvent
from app.models.alert import Alert  # NEW - ensures Alert table is created


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables (auth_events + alerts)
    Base.metadata.create_all(bind=engine)

    yield


app = FastAPI(
    title="BruteForceGuard API",
    description=(
        "Authentication threat detection and brute-force "
        "monitoring platform."
    ),
    version="0.3.0",  # Updated for Phase 3
    lifespan=lifespan,
)


# Register routers
app.include_router(events_router)
app.include_router(alerts_router)  # NEW


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "bruteforceguard-api",
        "version": "0.3.0",  # Updated for Phase 3
    }