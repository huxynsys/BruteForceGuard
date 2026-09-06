from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class AuthResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuthEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime

    source: str = Field(
        min_length=1,
        max_length=50,
    )

    source_ip: IPvAnyAddress

    destination_ip: IPvAnyAddress | None = None

    username: str | None = Field(
        default=None,
        max_length=255,
    )

    result: AuthResult

    service: str | None = Field(
        default=None,
        max_length=100,
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
    )

    hostname: str | None = Field(
        default=None,
        max_length=255,
    )

    user_agent: str | None = None

    event_id: str | None = Field(
        default=None,
        max_length=100,
    )

    raw_event: dict | None = None


class AuthEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source: str

    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress | None

    username: str | None
    result: AuthResult
    service: str | None
    port: int | None
    hostname: str | None
    user_agent: str | None
    event_id: str | None
    raw_event: dict | None
    created_at: datetime