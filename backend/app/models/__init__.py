from datetime import datetime
from enum import Enum
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import TYPE_CHECKING, Union

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB

from app.db.database import Base

# Avoid circular imports with type-checking only imports
if TYPE_CHECKING:
    from app.models.auth_event import AuthEvent  # noqa
    from app.models.alert import Alert  # noqa
    from app.models.attack_session import AttackSession  # noqa
    from app.models.threat_indicator import ThreatIndicator  # noqa


class BlacklistEntryType(str, Enum):
    SINGLE = "SINGLE"
    RANGE = "RANGE"
    REGION = "REGION"


class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"

    id = Column(Integer, primary_key=True, index=True)
    entry_type = Column(String(20), nullable=False, index=True)
    ip_address = Column(INET, nullable=True)  # For SINGLE type
    ip_range_start = Column(INET, nullable=True)  # For RANGE type
    ip_range_end = Column(INET, nullable=True)  # For RANGE type
    region_code = Column(String(10), nullable=True)  # For REGION type
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        if self.entry_type == BlacklistEntryType.SINGLE:
            return f"<BlacklistedIP(id={self.id}, type={self.entry_type}, ip={self.ip_address})>"
        elif self.entry_type == BlacklistEntryType.RANGE:
            return f"<BlacklistedIP(id={self.id}, type={self.entry_type}, range={self.ip_range_start}-{self.ip_range_end})>"
        elif self.entry_type == BlacklistEntryType.REGION:
            return f"<BlacklistedIP(id={self.id}, type={self.entry_type}, region={self.region_code})>"
        return f"<BlacklistedIP(id={self.id}, type={self.entry_type})>"
