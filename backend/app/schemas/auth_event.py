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


class EventGroupResponse(BaseModel):
    """One correlation group (grouped by ``source_ip``) for the events page.

    ``alert_types`` and ``session_ids`` are derived from alerts that share the
    group's source IP — raw events are not linked to sessions in the data
    model, so this is the only real attack context available for a group.
    ``events`` holds the (capped) most recent events of the group so the
    expanded accordion row can render without a second request.
    """

    group_key: str
    group_field: str
    event_count: int
    success_count: int
    failure_count: int
    usernames: list[str]
    services: list[str]
    first_seen: datetime
    last_seen: datetime
    alert_types: list[str]
    session_ids: list[int]
    events: list[AuthEventResponse]


class EventGroupPage(BaseModel):
    """Server-side paginated envelope for the grouped events endpoint."""

    items: list[EventGroupResponse]
    total: int