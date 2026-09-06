from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertResponse


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["alerts"],
)


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    db: Session = Depends(get_db),
):
    statement = (
        select(Alert)
        .order_by(Alert.created_at.desc())
        .limit(100)
    )

    return list(db.scalars(statement))