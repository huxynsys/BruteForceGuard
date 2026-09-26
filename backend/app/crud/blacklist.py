from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import List, Optional, Union

from sqlalchemy.orm import Session

from app.models import BlacklistedIP, BlacklistEntryType, IPListType
from app.schemas.blacklist import BlacklistEntryCreate
from app.utils.ip_utils import get_region_from_ip  # Will create this next


def _normalize_entry_value(entry: BlacklistEntryCreate) -> str | None:
    if entry.entry_type == BlacklistEntryType.SINGLE and entry.ip_address is not None:
        return str(entry.ip_address)
    if entry.entry_type == BlacklistEntryType.RANGE and entry.ip_network is not None:
        return str(entry.ip_network)
    if entry.entry_type == BlacklistEntryType.REGION and entry.region_code is not None:
        return entry.region_code.strip().upper()
    return None


def _duplicate_exists(
    db: Session,
    *,
    list_type: IPListType,
    entry_type: BlacklistEntryType,
    lookup_value: str | None,
) -> bool:
    query = db.query(BlacklistedIP).filter(
        BlacklistedIP.list_type == list_type.value,
        BlacklistedIP.entry_type == entry_type.value,
    )

    if entry_type == BlacklistEntryType.SINGLE and lookup_value is not None:
        return query.filter(BlacklistedIP.ip_address == lookup_value).first() is not None
    if entry_type == BlacklistEntryType.RANGE and lookup_value is not None:
        return (
            query.filter(
                BlacklistedIP.ip_range_start == str(ip_address(lookup_value).exploded if False else lookup_value)
            ).first() is not None
        )
    if entry_type == BlacklistEntryType.REGION and lookup_value is not None:
        return query.filter(BlacklistedIP.region_code == lookup_value).first() is not None
    return False


def create_blacklist_entry(
    db: Session, entry: BlacklistEntryCreate
) -> BlacklistedIP:
    list_type = IPListType(entry.list_type)
    lookup_value = _normalize_entry_value(entry)

    if _duplicate_exists(
        db,
        list_type=list_type,
        entry_type=BlacklistEntryType(entry.entry_type),
        lookup_value=lookup_value,
    ):
        raise ValueError(f"{entry.entry_type} entry for {lookup_value} already exists in {list_type.value}")

    db_entry = None
    if entry.entry_type == BlacklistEntryType.SINGLE:
        db_entry = BlacklistedIP(
            list_type=list_type.value,
            entry_type=entry.entry_type,
            ip_address=str(entry.ip_address),
            description=entry.description,
            added_by=entry.added_by,
            expires_at=entry.expires_at,
        )
    elif entry.entry_type == BlacklistEntryType.RANGE:
        network = entry.ip_network
        if network:
            db_entry = BlacklistedIP(
                list_type=list_type.value,
                entry_type=entry.entry_type,
                ip_range_start=str(network.network_address),
                ip_range_end=str(network.broadcast_address if network.prefixlen != network.max_prefixlen else network.network_address),
                description=entry.description,
                added_by=entry.added_by,
                expires_at=entry.expires_at,
            )
    elif entry.entry_type == BlacklistEntryType.REGION:
        db_entry = BlacklistedIP(
            list_type=list_type.value,
            entry_type=entry.entry_type,
            region_code=entry.region_code,
            description=entry.description,
            added_by=entry.added_by,
            expires_at=entry.expires_at,
        )

    if db_entry:
        db.add(db_entry)
        db.commit()
        db.refresh(db_entry)
    return db_entry  # type: ignore


def get_blacklist_entries(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    list_type: str | None = None,
) -> List[BlacklistedIP]:
    query = db.query(BlacklistedIP)
    if list_type:
        query = query.filter(BlacklistedIP.list_type == list_type)
    return query.order_by(BlacklistedIP.created_at.desc()).offset(skip).limit(limit).all()


def get_blacklist_entry(db: Session, entry_id: int) -> Optional[BlacklistedIP]:
    return db.query(BlacklistedIP).filter(BlacklistedIP.id == entry_id).first()


def delete_blacklist_entry(db: Session, entry_id: int) -> Optional[BlacklistedIP]:
    db_entry = db.query(BlacklistedIP).filter(BlacklistedIP.id == entry_id).first()
    if db_entry:
        db.delete(db_entry)
        db.commit()
    return db_entry


def is_ip_blacklisted(db: Session, ip_to_check: Union[IPv4Address, IPv6Address]) -> bool:
    str_ip_to_check = str(ip_to_check)

    blocklist = (
        db.query(BlacklistedIP)
        .filter(
            BlacklistedIP.list_type == IPListType.BLOCKLIST.value,
            BlacklistedIP.entry_type == BlacklistEntryType.SINGLE,
            BlacklistedIP.ip_address == str_ip_to_check,
        )
        .first()
    )
    if blocklist:
        return True

    range_matches = (
        db.query(BlacklistedIP)
        .filter(
            BlacklistedIP.list_type == IPListType.BLOCKLIST.value,
            BlacklistedIP.entry_type == BlacklistEntryType.RANGE,
            BlacklistedIP.ip_range_start <= str_ip_to_check,
            BlacklistedIP.ip_range_end >= str_ip_to_check,
        )
        .all()
    )
    if range_matches:
        return True

    region_code = get_region_from_ip(str_ip_to_check)
    if region_code:
        region_match = (
            db.query(BlacklistedIP)
            .filter(
                BlacklistedIP.list_type == IPListType.BLOCKLIST.value,
                BlacklistedIP.entry_type == BlacklistEntryType.REGION,
                BlacklistedIP.region_code == region_code,
            )
            .first()
        )
        if region_match:
            return True

    return False
