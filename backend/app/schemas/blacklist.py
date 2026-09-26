from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal, Optional, Union

from pydantic import BaseModel, Field, IPvAnyNetwork, field_validator, model_validator


class BlacklistEntryBase(BaseModel):
    description: Optional[str] = Field(None, max_length=500)
    list_type: Literal["BLOCKLIST", "WHITELIST"] = "BLOCKLIST"
    added_by: Optional[str] = Field(None, max_length=255)
    expires_at: Optional[datetime] = None


class BlacklistEntryCreate(BlacklistEntryBase):
    entry_type: Literal["SINGLE", "RANGE", "REGION"]
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_network: Optional[IPvAnyNetwork] = None
    region_code: Optional[str] = Field(None, max_length=10)

    @field_validator("ip_address", mode="before")
    @classmethod
    def validate_ip_address(cls, v):
        if v is not None and not isinstance(v, (IPv4Address, IPv6Address)):
            try:
                from ipaddress import ip_address

                return ip_address(v)
            except ValueError as exc:  # pragma: no cover - pydantic surfaces the error
                raise ValueError("Invalid IP address format") from exc
        return v

    @field_validator("region_code")
    @classmethod
    def validate_region_code(cls, v):
        if v is not None:
            if not v.isalpha() or len(v) not in (2, 3):
                raise ValueError("Region code must be 2 or 3 alphabetic characters")
        return v

    @model_validator(mode="after")
    def validate_entry_type_fields(self):
        ip_address = self.ip_address
        ip_network = self.ip_network
        region_code = self.region_code

        if self.entry_type == "SINGLE":
            if not ip_address or ip_network or region_code:
                raise ValueError("For 'SINGLE' type, only 'ip_address' must be provided")
        elif self.entry_type == "RANGE":
            if not ip_network or ip_address or region_code:
                raise ValueError("For 'RANGE' type, only 'ip_network' must be provided")
        elif self.entry_type == "REGION":
            if not region_code or ip_address or ip_network:
                raise ValueError("For 'REGION' type, only 'region_code' must be provided")
        return self


class BlacklistEntryResponse(BlacklistEntryBase):
    id: int
    entry_type: Literal["SINGLE", "RANGE", "REGION"]
    ip_address: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_range_start: Optional[Union[IPv4Address, IPv6Address]] = None
    ip_range_end: Optional[Union[IPv4Address, IPv6Address]] = None
    region_code: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
