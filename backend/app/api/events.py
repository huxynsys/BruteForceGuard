from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.auth_event import (
    AuthEventCreate,
    AuthEventResponse,
)
from app.services.event_service import create_auth_event


router = APIRouter(
    prefix="/api/v1/events",
    tags=["Authentication Events"],
)


@router.post(
    "",
    response_model=AuthEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def ingest_event(
    event: AuthEventCreate,
    db: Session = Depends(get_db),
):
    return create_auth_event(db, event)