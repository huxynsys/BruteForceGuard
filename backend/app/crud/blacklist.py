from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import List, Optional, Union

from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models import BlacklistedIP, BlacklistEntryType
from app.schemas.blacklist import BlacklistEntryCreate
from app.utils.ip_utils import get_region_from_ip # Will create this next


def create_blacklist_entry(
    db: Session, entry: BlacklistEntryCreate
) -> BlacklistedIP:
    db_entry = None
    if entry.entry_type == BlacklistEntryType.SINGLE:
        db_entry = BlacklistedIP(
            entry_type=entry.entry_type,
            ip_address=str(entry.ip_address),
            description=entry.description,
        )
    elif entry.entry_type == BlacklistEntryType.RANGE:
        network = entry.ip_network
        if network:
            db_entry = BlacklistedIP(
                entry_type=entry.entry_type,
                ip_range_start=str(network.network_address),
                ip_range_end=str(network.broadcast_address if network.prefixlen != network.max_prefixlen else network.network_address),
                description=entry.description,
            )
    elif entry.entry_type == BlacklistEntryType.REGION:
        db_entry = BlacklistedIP(
            entry_type=entry.entry_type,
            region_code=entry.region_code,
            description=entry.description,
        )

    if db_entry:
        db.add(db_entry)
        db.commit()
        db.refresh(db_entry)
    return db_entry # type: ignore


def get_blacklist_entries(db: Session, skip: int = 0, limit: int = 100) -> List[BlacklistedIP]:
    return db.query(BlacklistedIP).offset(skip).limit(limit).all()


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

    # Check for SINGLE IP match
    single_match = (
        db.query(BlacklistedIP)
        .filter(
            BlacklistedIP.entry_type == BlacklistEntryType.SINGLE,
            BlacklistedIP.ip_address == str_ip_to_check,
        )
        .first()
    )
    if single_match:
        return True

    # Check for RANGE IP match
    range_matches = (
        db.query(BlacklistedIP)
        .filter(
            BlacklistedIP.entry_type == BlacklistEntryType.RANGE,
            BlacklistedIP.ip_range_start <= str_ip_to_check,
            BlacklistedIP.ip_range_end >= str_ip_to_check,
        )
        .all()
    )
    if range_matches:
        return True

    # Check for REGION IP match (requires geolocation lookup)
    region_code = get_region_from_ip(str_ip_to_check)
    if region_code:
        region_match = (
            db.query(BlacklistedIP)
            .filter(
                BlacklistedIP.entry_type == BlacklistEntryType.REGION,
                BlacklistedIP.region_code == region_code,
            )
            .first()
        )
        if region_match:
            return True

    return False
