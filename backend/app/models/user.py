"""Interactive user accounts and their server-side login sessions.

These tables back the RBAC layer: ``users`` holds the login identity and its
``admin`` / ``analyst`` role, while ``auth_sessions`` stores one row per issued
login token.  Only a SHA-256 hash of the session token is persisted, the
plaintext token is returned exactly once (at login) and passwords are stored
as salted PBKDF2 hashes (``app.core.security``) - no plaintext secret ever
reaches the database.

Sessions are revoked (never deleted) on logout, and automatically on password
change, deactivation or role change, so a privilege change takes effect for
live sessions immediately.  Expiry is enforced at resolution time against
``expires_at``.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base

#: Roles a user account may hold (mirrors ``TRIAGE_ROLES`` in the lifecycle
#: state machine; the CHECK constraint keeps the vocabulary enforced in the
#: database as well).
VALID_ROLES: frozenset[str] = frozenset({"admin", "analyst"})

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"


class User(Base):
    """One interactive login account (never a service/collector token)."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'analyst')", name="ck_users_role"),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )

    #: Login name (unique).  Displayed in the UI and recorded as the audit
    #: actor for session-authenticated actions.
    username: Mapped[str] = mapped_column(
        String(100), nullable=False, unique=True, index=True
    )

    #: Salted PBKDF2-HMAC-SHA256 hash (``pbkdf2_sha256$iters$salt$digest``).
    #: The plaintext password is never stored, logged or audited.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    #: ``admin`` or ``analyst`` (see :data:`VALID_ROLES`).
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")

    #: Deactivated accounts can no longer log in and their live sessions are
    #: revoked at deactivation time.
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    #: Set on every successful login (None until the first login).
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    sessions: Mapped[list["AuthSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"<User(id={self.id}, username={self.username!r}, "
            f"role={self.role!r}, active={self.is_active})>"
        )


class AuthSession(Base):
    """One issued login token (hashed) with an explicit lifetime."""

    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    #: SHA-256 hex of the opaque bearer token - the plaintext exists only in
    #: the login response, so this column is useless to an attacker who
    #: obtains a database dump.
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    #: Hard expiry - resolution refuses tokens at or past this moment.
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    #: Set on logout / password change / role change / deactivation.
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_active(self) -> bool:
        """Whether the session may still authenticate a request."""

        if self.revoked_at is not None:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires > datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return (
            f"<AuthSession(id={self.id}, user_id={self.user_id}, "
            f"expires_at={self.expires_at!r}, revoked={self.revoked_at is not None})>"
        )
