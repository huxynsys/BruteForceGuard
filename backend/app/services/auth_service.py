"""Interactive authentication: login, sessions and user lifecycle.

This is the *one* authentication system for interactive users; the stateless
API tokens (``ALERT_TRIAGE_API_TOKENS`` / ``IP_MANAGEMENT_API_TOKENS``) remain
the machine-to-machine credentials and both are resolved into the same
principal shape in ``app.api.deps``, so authorization logic never cares which
credential type authenticated the request.

Security properties:

* passwords are salted PBKDF2 hashes (``app.core.security``), compared in
  constant time, and never stored, logged or audited in plaintext;
* session tokens are opaque random values - the database keeps only their
  SHA-256 hash, with an explicit ``expires_at`` and ``revoked_at``;
* a password verification for a non-existent user is equalized with a dummy
  hash so response timing does not reveal account existence;
* failed logins are rate-limited per (client IP, username) window and every
  outcome is appended to the immutable security audit log.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.models.user import ROLE_ADMIN, VALID_ROLES, AuthSession, User

logger = logging.getLogger(__name__)

#: Salted hash verified when the username does not exist, so an unknown
#: account costs the same time as a wrong password (timing equalization).
#: Built lazily because it depends on the configured iteration count.
_dummy_hash: str | None = None
_dummy_hash_lock = threading.Lock()


class InvalidCredentialsError(Exception):
    """Username/password pair rejected (or the account is deactivated)."""


class DuplicateUsernameError(Exception):
    """A user with that username already exists."""


class UnknownRoleError(Exception):
    """Role outside the ``admin`` / ``analyst`` vocabulary."""


class LastAdminError(Exception):
    """The change would leave the system without an active administrator."""


class LoginRateLimitedError(Exception):
    """Too many failed logins inside the configured window."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Too many failed login attempts")
        self.retry_after_seconds = max(1, retry_after_seconds)


# ---------------------------------------------------------------------------
# Login rate limiting (per-process sliding window)
# ---------------------------------------------------------------------------

_failures: dict[str, list[float]] = {}
_failures_lock = threading.Lock()


def _rate_limit_key(source_ip: str | None, username: str) -> str:
    return f"{source_ip or 'unknown'}:{username.strip().lower()}"


def check_login_rate_limit(source_ip: str | None, username: str) -> None:
    """Raise :class:`LoginRateLimitedError` when the window is saturated."""

    key = _rate_limit_key(source_ip, username)
    window = max(1, settings.auth_login_window_seconds)
    max_failures = max(1, settings.auth_login_max_failures)
    now = time.monotonic()

    with _failures_lock:
        recent = [t for t in _failures.get(key, []) if now - t < window]
        if recent:
            _failures[key] = recent
        elif key in _failures:
            del _failures[key]

        if len(recent) >= max_failures:
            oldest = min(recent)
            raise LoginRateLimitedError(int(window - (now - oldest)) + 1)


def register_login_failure(source_ip: str | None, username: str) -> None:
    """Count one failed attempt against the (IP, username) window."""

    key = _rate_limit_key(source_ip, username)
    window = max(1, settings.auth_login_window_seconds)
    now = time.monotonic()

    with _failures_lock:
        recent = [t for t in _failures.get(key, []) if now - t < window]
        recent.append(now)
        _failures[key] = recent


def clear_login_failures(source_ip: str | None, username: str) -> None:
    """Reset the window after a successful login."""

    key = _rate_limit_key(source_ip, username)
    with _failures_lock:
        _failures.pop(key, None)


def reset_login_rate_limiter() -> None:
    """Drop all windows (used by the test suite between tests)."""

    with _failures_lock:
        _failures.clear()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username.strip()))


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)))


def count_active_admins(db: Session, *, excluding_user_id: int | None = None) -> int:
    """Active ``admin`` accounts (optionally excluding one user)."""

    statement = select(func.count(User.id)).where(
        User.is_active.is_(True), User.role == ROLE_ADMIN
    )
    if excluding_user_id is not None:
        statement = statement.where(User.id != excluding_user_id)
    return int(db.scalar(statement) or 0)


def ensure_not_last_admin(db: Session, user: User) -> None:
    """Guard for changes that would remove the last active administrator."""

    if user.role == ROLE_ADMIN and user.is_active:
        if count_active_admins(db, excluding_user_id=user.id) == 0:
            raise LastAdminError("Cannot remove the last active administrator")


def create_user(db: Session, *, username: str, password: str, role: str) -> User:
    """Create an account with a hashed password (plaintext is discarded)."""

    normalized_role = (role or "").strip().lower()
    if normalized_role not in VALID_ROLES:
        raise UnknownRoleError(
            f"Unknown role {role!r}; expected one of {sorted(VALID_ROLES)}"
        )

    username = username.strip()
    if get_user_by_username(db, username) is not None:
        raise DuplicateUsernameError(f"Username {username!r} already exists")

    # Raises security.PasswordPolicyError (mapped to 422 by the endpoint).
    security.validate_password_strength(password)

    user = User(
        username=username,
        password_hash=security.hash_password(password),
        role=normalized_role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("user created username=%s role=%s", user.username, user.role)
    return user


def set_password(db: Session, user: User, password: str) -> None:
    """Rotate a password; every live session of that user is revoked."""

    security.validate_password_strength(password)
    user.password_hash = security.hash_password(password)
    revoke_user_sessions(db, user)
    db.commit()


def set_role(db: Session, user: User, role: str) -> None:
    """Change a role; sessions are revoked so the change applies immediately."""

    normalized = (role or "").strip().lower()
    if normalized not in VALID_ROLES:
        raise UnknownRoleError(
            f"Unknown role {role!r}; expected one of {sorted(VALID_ROLES)}"
        )
    if user.role == normalized:
        return
    ensure_not_last_admin(db, user)
    user.role = normalized
    revoke_user_sessions(db, user)
    db.commit()


def set_active(db: Session, user: User, active: bool) -> None:
    """Activate/deactivate; deactivation revokes the account's sessions."""

    active = bool(active)
    if user.is_active and not active:
        ensure_not_last_admin(db, user)
    user.is_active = active
    if not active:
        revoke_user_sessions(db, user)
    db.commit()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def _timing_equalized_dummy_hash() -> str:
    """Hash spent on unknown usernames, equal to one real verification."""

    global _dummy_hash
    with _dummy_hash_lock:
        if _dummy_hash is None:
            _dummy_hash = security.hash_password(
                "timing-equalizer-not-a-real-password"
            )
        return _dummy_hash


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the active user for ``username``/``password`` or ``None``.

    Unknown usernames, wrong passwords and deactivated accounts are
    indistinguishable to the caller (and to a stopwatch), so the login
    response never leaks which part of the credential was wrong.
    """

    user = get_user_by_username(db, username)
    if user is None:
        security.verify_password(password, _timing_equalized_dummy_hash())
        return None

    if not security.verify_password(password, user.password_hash):
        return None

    if not user.is_active:
        return None

    return user


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def purge_expired_sessions(db: Session) -> None:
    """Delete expired or revoked session rows (they store no secret)."""

    now = _utcnow()
    db.execute(
        delete(AuthSession).where(
            (AuthSession.expires_at <= now) | (AuthSession.revoked_at.is_not(None))
        )
    )
    db.commit()


def create_session(db: Session, user: User) -> tuple[str, datetime]:
    """Issue a session token; returns ``(plaintext_token, expires_at)``.

    The plaintext token is returned exactly once - only its SHA-256 hash is
    persisted, so the stored row can never be replayed as a credential.
    """

    now = _utcnow()
    expires_at = now + timedelta(minutes=max(1, settings.auth_session_ttl_minutes))
    token = security.generate_session_token()

    db.add(
        AuthSession(
            user_id=user.id,
            token_hash=security.hash_session_token(token),
            expires_at=expires_at,
        )
    )
    user.last_login_at = now
    db.commit()

    return token, expires_at


def resolve_session(db: Session, token: str) -> tuple[User, AuthSession] | None:
    """Look up a live session for ``token`` (``None`` when unusable).

    Refuses revoked sessions, expired sessions and sessions belonging to a
    deactivated user - all three are re-checked on every request, so
    revocation takes effect immediately.
    """

    if not token:
        return None

    session_row = db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == security.hash_session_token(token)
        )
    )
    if session_row is None:
        return None
    if not session_row.is_active:
        return None

    user = session_row.user
    if user is None or not user.is_active:
        return None

    return user, session_row


def revoke_session(db: Session, session_row: AuthSession) -> None:
    """Revoke one session (logout); idempotent."""

    if session_row.revoked_at is None:
        session_row.revoked_at = _utcnow()
        db.commit()


def revoke_user_sessions(db: Session, user: User) -> None:
    """Revoke every live session of ``user`` (password/role/deactivation)."""

    db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=_utcnow())
    )
    db.flush()


# ---------------------------------------------------------------------------
# First-run bootstrap
# ---------------------------------------------------------------------------


def bootstrap_admin(db: Session) -> User | None:
    """Create the initial admin from env settings, once.

    Returns the created user, or ``None`` when disabled or when the account
    already exists (an existing password is never overwritten at startup -
    rotate it through ``PATCH /api/v1/users/{id}`` instead).
    """

    password = settings.auth_bootstrap_admin_password
    if not password:
        return None

    username = settings.auth_bootstrap_admin_username.strip() or "admin"
    if get_user_by_username(db, username) is not None:
        return None

    return create_user(db, username=username, password=password, role=ROLE_ADMIN)


