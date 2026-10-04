"""Schemas for admin user management (``/api/v1/users``)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    """Payload to create an account (admin only)."""

    username: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Letters, digits, dot, underscore and hyphen only",
    )
    #: Hashed server-side (PBKDF2); plaintext is never stored or logged.
    password: str = Field(min_length=1, max_length=1024)
    role: Literal["admin", "analyst"]


class UserUpdate(BaseModel):
    """Partial update; omitted fields are left untouched."""

    role: Literal["admin", "analyst"] | None = None
    is_active: bool | None = None
    #: New password (subject to the password policy); revokes all sessions.
    password: str | None = Field(default=None, max_length=1024)


class UserResponse(BaseModel):
    """Account summary - deliberately excludes the password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None
