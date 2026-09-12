from fastapi import APIRouter, Depends, HTTPException
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


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """Get a single alert by ID (used by the alert investigation page)."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
