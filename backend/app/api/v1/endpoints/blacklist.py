from typing import List, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.crud import blacklist as crud_blacklist
from app.schemas.blacklist import BlacklistEntryCreate, BlacklistEntryResponse


router = APIRouter(
    prefix="/blacklist",
    tags=["Blacklist"],
    responses={404: {"description": "Not found"}},
)


def require_ip_management_auth(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    if not settings.ip_management_api_token_list:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IP management API is not configured",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    if token not in settings.ip_management_api_token_list:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden",
        )

    if not x_user_id or not x_user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User identity required",
        )

    return x_user_id.strip()


@router.post(
    "/", response_model=BlacklistEntryResponse, status_code=status.HTTP_201_CREATED
)
def create_blacklist_entry(
    entry: BlacklistEntryCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(require_ip_management_auth),
):
    entry.added_by = actor

    try:
        db_entry = crud_blacklist.create_blacklist_entry(db=db, entry=entry)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    if not db_entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error creating blacklist entry")

    return BlacklistEntryResponse.model_validate(db_entry)


@router.get(
    "/", response_model=List[BlacklistEntryResponse], status_code=status.HTTP_200_OK
)
def read_blacklist_entries(
    skip: int = 0,
    limit: int = Query(default=100, ge=1, le=500),
    list_type: Literal["BLOCKLIST", "WHITELIST"] | None = None,
    db: Session = Depends(get_db),
    _: str = Depends(require_ip_management_auth),
):
    entries = crud_blacklist.get_blacklist_entries(
        db,
        skip=skip,
        limit=limit,
        list_type=list_type.upper() if list_type else None,
    )
    return [BlacklistEntryResponse.model_validate(entry) for entry in entries]


@router.delete(
    "/{entry_id}",
    response_model=BlacklistEntryResponse,
    status_code=status.HTTP_200_OK,
)
def delete_blacklist_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(require_ip_management_auth),
):
    db_entry = crud_blacklist.delete_blacklist_entry(db=db, entry_id=entry_id)
    if db_entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blacklist entry not found",
        )

    return BlacklistEntryResponse.model_validate(db_entry)
