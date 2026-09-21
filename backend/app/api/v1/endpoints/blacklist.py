from typing import List, Optional
from ipaddress import IPv4Address, IPv6Address

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.crud import blacklist as crud_blacklist
from app.schemas.blacklist import BlacklistEntryCreate, BlacklistEntryResponse


router = APIRouter(
    prefix="/blacklist",
    tags=["Blacklist"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "/", response_model=BlacklistEntryResponse, status_code=status.HTTP_201_CREATED
)
def create_blacklist_entry(
    entry: BlacklistEntryCreate, db: Session = Depends(get_db)
):
    db_entry = crud_blacklist.create_blacklist_entry(db=db, entry=entry)
    if not db_entry:
        raise HTTPException(status_code=400, detail="Error creating blacklist entry")
    
    response_data = db_entry.dict() if hasattr(db_entry, 'dict') else {
        "id": db_entry.id,
        "entry_type": db_entry.entry_type,
        "ip_address": db_entry.ip_address,
        "ip_range_start": db_entry.ip_range_start,
        "ip_range_end": db_entry.ip_range_end,
        "region_code": db_entry.region_code,
        "description": db_entry.description,
        "created_at": db_entry.created_at,
        "updated_at": db_entry.updated_at,
    }

    return BlacklistEntryResponse(**response_data)


@router.get(
    "/", response_model=List[BlacklistEntryResponse], status_code=status.HTTP_200_OK
)
def read_blacklist_entries(
    skip: int = 0, limit: int = 100, db: Session = Depends(get_db)
):
    entries = crud_blacklist.get_blacklist_entries(db, skip=skip, limit=limit)
    return [
        BlacklistEntryResponse(**(e.dict() if hasattr(e, 'dict') else {
            "id": e.id,
            "entry_type": e.entry_type,
            "ip_address": e.ip_address,
            "ip_range_start": e.ip_range_start,
            "ip_range_end": e.ip_range_end,
            "region_code": e.region_code,
            "description": e.description,
            "created_at": e.created_at,
            "updated_at": e.updated_at,
        })) for e in entries
    ]


@router.delete(
    "/{entry_id}",
    response_model=BlacklistEntryResponse, # Changed to return deleted item
    status_code=status.HTTP_200_OK, # Changed to 200 for successful deletion with content
)
def delete_blacklist_entry(
    entry_id: int, db: Session = Depends(get_db)
):
    db_entry = crud_blacklist.delete_blacklist_entry(db=db, entry_id=entry_id)
    if db_entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Blacklist entry not found"
        )
    
    response_data = db_entry.dict() if hasattr(db_entry, 'dict') else {
        "id": db_entry.id,
        "entry_type": db_entry.entry_type,
        "ip_address": db_entry.ip_address,
        "ip_range_start": db_entry.ip_range_start,
        "ip_range_end": db_entry.ip_range_end,
        "region_code": db_entry.region_code,
        "description": db_entry.description,
        "created_at": db_entry.created_at,
        "updated_at": db_entry.updated_at,
    }

    return BlacklistEntryResponse(**response_data)
