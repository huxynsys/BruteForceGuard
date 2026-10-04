"""Schemas for the interactive authentication endpoints (login/logout/me)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    """Username/password pair submitted to ``POST /api/v1/auth/login``.

    No strength policy here on purpose: the policy applies when a password is
    *set*, never when it is presented, so a future policy change cannot lock
    existing users out of authenticating.
    """

    username: str = Field(min_length=1, max_length=100)
    #: Never logged, never audited, never stored (hashed at rest only).
    password: str = Field(min_length=1, max_length=1024)


class AuthUser(BaseModel):
    """The authenticated identity as the UI should see it."""

    model_config = ConfigDict(from_attributes=True)

    username: str
    role: Literal["admin", "analyst"]


class LoginResponse(BaseModel):
    """Successful login: opaque bearer token + its server-side expiry."""

    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: AuthUser


class MeResponse(BaseModel):
    """Who the current credential authenticates as (``GET /auth/me``)."""

    user: AuthUser
    #: ``session`` for login tokens, ``token`` for static API tokens.
    via: str
    #: Present only for login sessions; ``None`` for static tokens.
    session_expires_at: datetime | None = None


class LogoutResponse(BaseModel):
    """Session revoked (idempotent from the client's perspective)."""

    message: str
