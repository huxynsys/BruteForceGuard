"""Password hashing and session-token primitives.

Interactive login (``POST /api/v1/auth/login``) uses these primitives:

* **Passwords** are stored only as salted PBKDF2-HMAC-SHA256 hashes in the
  format ``pbkdf2_sha256$<iterations>$<salt>$<hex digest>``.  The iteration
  count travels inside the hash, so cost can be raised over time without
  invalidating existing passwords.  Verification is constant-time
  (``hmac.compare_digest``) and plaintext passwords are never stored, logged,
  audited or echoed back.
* **Session tokens** are opaque ``secrets.token_urlsafe`` values handed to
  the client once; the database stores only their SHA-256 hash, so a database
  leak cannot be replayed as a live session.

Nothing in this module logs or prints the values it processes.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from app.core.config import settings

#: Hashing scheme identifier prefixed to every stored password hash.
PASSWORD_SCHEME = "pbkdf2_sha256"

#: Bytes of random salt per password (stored alongside the digest).
SALT_BYTES = 16

#: Minimum length accepted when *setting* a password (login is unrestricted
#: so a policy change can never lock existing users out of authenticating).
MIN_PASSWORD_LENGTH = 12

#: Length of generated session tokens (base64url characters).
SESSION_TOKEN_BYTES = 32


class PasswordPolicyError(ValueError):
    """Raised when a proposed password does not meet the storage policy."""


def validate_password_strength(password: str) -> None:
    """Reject passwords that are too short to be worth hashing.

    Raises :class:`PasswordPolicyError`; callers translate that into a 422.
    """

    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )


def hash_password(password: str, *, iterations: int | None = None) -> str:
    """Return a salted PBKDF2-HMAC-SHA256 hash of ``password``."""

    if iterations is None:
        iterations = settings.auth_password_iterations
    salt = secrets.token_hex(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"{PASSWORD_SCHEME}${iterations}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of ``password`` against a stored hash.

    Returns ``False`` for malformed or unknown-format values instead of
    raising, so a corrupt row can never crash a login attempt into a 500.
    """

    try:
        scheme, iterations_text, salt, expected_hex = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(iterations_text)
        if iterations < 1:
            return False
    except (AttributeError, ValueError):
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return hmac.compare_digest(candidate.hex(), expected_hex)


def generate_session_token() -> str:
    """Return a fresh opaque session token for a successful login."""

    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    """Return the SHA-256 hex hash stored for a session token.

    Only the hash is persisted, so the database never contains a value that
    can be replayed as a credential.
    """

    return hashlib.sha256(token.encode("utf-8")).hexdigest()
