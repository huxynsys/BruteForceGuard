from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, conlist, validator
from pydantic_extra_types.inet import IPNetwork


class BlacklistEntryBase(BaseModel):
    description: Optional[str] = Field(None, max_length=500)


class BlacklistEntryCreate(BlacklistEntryBase):
    entry_type: Literal["SINGLE", "RANGE", "REGION"]
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_network: Optional[IPNetwork] = None
    region_code: Optional[str] = Field(None, max_length=10)

    @validator("ip_address", pre=True)
    def validate_ip_address(cls, v):
        if v is not None and not isinstance(v, (IPv4Address, IPv6Address)):  # type: ignore
            try:
                from ipaddress import ip_address
                return ip_address(v)
            except ValueError: # type: ignore
                raise ValueError("Invalid IP address format") # type: ignore
        return v # type: ignore

    @validator("region_code")
    def validate_region_code(cls, v):
        if v is not None: # type: ignore
            if not v.isalpha() or len(v) not in (2, 3):  # Example: 'US', 'USA'
                raise ValueError("Region code must be 2 or 3 alphabetic characters") # type: ignore
        return v # type: ignore

    @validator("entry_type", always=True)
    def validate_entry_type_fields(cls, v, values):
        ip_address = values.get("ip_address")
        ip_network = values.get("ip_network")
        region_code = values.get("region_code")

        if v == "SINGLE":
            if not ip_address or ip_network or region_code:
                raise ValueError("For 'SINGLE' type, only 'ip_address' must be provided")
        elif v == "RANGE":
            if not ip_network or ip_address or region_code:
                raise ValueError("For 'RANGE' type, only 'ip_network' must be provided")
        elif v == "REGION":
            if not region_code or ip_address or ip_network:
                raise ValueError("For 'REGION' type, only 'region_code' must be provided")
        return v


class BlacklistEntryResponse(BlacklistEntryBase):
    id: int
    entry_type: Literal["SINGLE", "RANGE", "REGION"]
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_range_start: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_range_end: Optional[Union[IPv4Address, IPv6Address]] = None
    region_code: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
