"""Immutable security audit log (append-only evidence).

Records who performed which security-sensitive action, when, with what
result and against which target - alert triage transitions, IP blocklist /
whitelist changes, and failed authentication attempts on token-gated
endpoints.  Only safe metadata is ever stored: the sanitizer in
``app.services.audit_service`` redacts secret-looking values and the auth
hooks never pass the presented token itself.

Immutability is enforced in three layers:

1. The API exposes ``GET /api/v1/audit/`` only - there is no create, update
   or delete endpoint for normal users.
2. SQLAlchemy ``before_update`` / ``before_delete`` listeners raise
   :class:`AuditLogImmutableError`, so no application code path can mutate
   a row through the ORM.
3. The Alembic migration (``0006_security_audit_log``) installs database
   triggers that abort ``UPDATE`` / ``DELETE`` statements outright, covering
   raw SQL access outside the application.

The design mirrors ``AlertStatusHistory`` (the per-alert audit trail): rows
are written once, in the same transaction as the change they describe where
possible, and read back newest-first.
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, Integer, String, Text, func, event
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class AuditAction(str, Enum):
    """Canonical action vocabulary recorded in ``security_audit_logs``.

    ``LOGIN`` / ``LOGOUT`` / ``SETTINGS_CHANGE`` / ``ROLE_CHANGE`` are
    reserved for future endpoints: BruteForceGuard currently authenticates
    with stateless bearer tokens (no sessions to log out of) and configures
    roles/settings via the environment, so neither has a request path to
    hook yet.  Successful authenticated actions record their own row with
    the acting identity instead.
    """

    # Alert triage (PATCH /api/v1/alerts/{id})
    ALERT_STATUS_CHANGE = "alert.status_change"

    # IP management (POST/DELETE /api/v1/blacklist/)
    IP_BLOCKLIST_ADD = "ip.blocklist.add"
    IP_BLOCKLIST_REMOVE = "ip.blocklist.remove"
    IP_WHITELIST_ADD = "ip.whitelist.add"
    IP_WHITELIST_REMOVE = "ip.whitelist.remove"

    # Failed authentication on any token-gated endpoint
    AUTH_FAILED = "auth.failed"

    # Reserved vocabulary for endpoints that do not exist yet
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    SETTINGS_CHANGE = "settings.change"
    ROLE_CHANGE = "role.change"


class AuditResult(str, Enum):
    """Outcome recorded for an audit entry."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditLogImmutableError(PermissionError):
    """Raised when application code tries to update or delete an audit row."""


class SecurityAuditLog(Base):
    """One row per security-sensitive action (append-only)."""

    __tablename__ = "security_audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    #: Canonical action (see :class:`AuditAction`).
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    #: Identity from ``X-User-Id`` (or ``anonymous`` for unauthenticated
    #: failures where no identity header was presented).
    actor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="anonymous",
        index=True,
    )

    #: Role bound to the acting token server-side (``analyst`` / ``admin``),
    #: NULL when the authentication method carries no role.
    actor_role: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    #: What was acted upon: ``alert``, ``blacklist_entry``, ``endpoint``...
    target_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    #: Identifier of the target: alert id, blacklist entry id, request path...
    target_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    #: Outcome (see :class:`AuditResult`).
    result: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    #: Client address the request came from (NULL when unresolvable).
    source_ip: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    #: Sanitized structured context (transition details, reason, entry
    #: value...).  Never secrets - redacted on write by the audit service.
    detail: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    #: Optional free-text note (kept separate from ``detail`` so simple
    #: messages stay queryable).
    note: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityAuditLog(id={self.id}, action={self.action!r}, "
            f"actor={self.actor!r}, result={self.result!r})>"
        )


# ---------------------------------------------------------------------------
# ORM-level immutability: no UPDATE / DELETE may pass through the session.
# (The Alembic migration adds matching database triggers for raw SQL.)
# ---------------------------------------------------------------------------
@event.listens_for(SecurityAuditLog, "before_update")
def _reject_audit_update(mapper, connection, target) -> None:
    raise AuditLogImmutableError(
        "Security audit log rows are append-only and cannot be updated"
    )


@event.listens_for(SecurityAuditLog, "before_delete")
def _reject_audit_delete(mapper, connection, target) -> None:
    raise AuditLogImmutableError(
        "Security audit log rows are append-only and cannot be deleted"
    )
