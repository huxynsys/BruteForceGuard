"""Writing security audit entries (append-only, secret-free).

`AuditService.record` is the single entry point used by API endpoints and
auth dependencies to append a `SecurityAuditLog` row.  Every `detail` payload
passes through the sanitizer first:

* values whose key *looks* secret (password, token, secret, authorization,
  api key...) are replaced with ``[REDACTED]`` - never stored,
* long strings are truncated so one oversized payload cannot bloat the log,
* non-JSON scalars (datetimes, UUIDs...) are stringified so the JSONB column
  always serializes.

The service never updates or deletes rows (the model rejects both at the ORM
level, the database rejects both with triggers).  Recording is deliberately
best-effort in failure paths: `record_auth_failure` swallows database errors
so an audit hiccup can never turn a 401/403 into a 500.
"""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit_log import AuditAction, AuditResult, SecurityAuditLog

logger = logging.getLogger(__name__)

#: Placeholder stored in place of a secret-looking value.
REDACTED = "[REDACTED]"

#: Key fragments treated as secret (case-insensitive substring match).
SECRET_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "cookie",
    "session_id",
    "bearer",
)

#: Longest string kept verbatim in the log (everything else is truncated).
MAX_STRING_LENGTH = 500

#: Maximum nesting depth sanitized before giving up on a payload.
MAX_DEPTH = 5


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS)


def client_ip(request: Any) -> str | None:
    """Best-effort client address for an audit row (``None`` if unusable).

    Prefers the direct peer address; deployments behind the Nginx proxy
    should rely on the standard forwarded handling at the proxy layer.
    """

    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    if not host:
        return None
    # Strip an IPv6 zone/bracket form and reject non-address text so the
    # INET column never receives garbage like "testclient".
    try:
        from ipaddress import ip_address

        return str(ip_address(host.strip("[]")))
    except ValueError:
        return None


def sanitize_detail(value: Any, *, _depth: int = 0) -> Any:
    """Return a JSON-safe copy of ``value`` with secrets redacted.

    Dict keys that look secret cause their value to be replaced entirely;
    strings (redacted or not) are truncated to ``MAX_STRING_LENGTH``;
    anything non-JSON-serializable is converted with ``str()``.  Nesting
    beyond ``MAX_DEPTH`` is flattened to a placeholder rather than risking
    unbounded recursion on pathological payloads.
    """

    if _depth > MAX_DEPTH:
        return "[truncated: max depth exceeded]"

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if _is_secret_key(key_str):
                sanitized[key_str] = REDACTED
            else:
                sanitized[key_str] = sanitize_detail(item, _depth=_depth + 1)
        return sanitized

    if isinstance(value, (list, tuple, set)):
        return [sanitize_detail(item, _depth=_depth + 1) for item in value]

    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            return value[:MAX_STRING_LENGTH] + "...[truncated]"
        return value

    if value is None or isinstance(value, (bool, int, float)):
        return value

    # datetimes, UUIDs, IPv4Address, enums... -> stable string form.
    return sanitize_detail(str(value), _depth=_depth + 1)


class AuditService:
    """Append and query the immutable security audit log."""

    def __init__(self, db: Session):
        self.db = db

    def record(
        self,
        *,
        action: AuditAction | str,
        result: AuditResult | str,
        actor: str | None = None,
        actor_role: str | None = None,
        target_type: str | None = None,
        target_id: str | int | None = None,
        source_ip: str | None = None,
        detail: dict[str, Any] | None = None,
        note: str | None = None,
        commit: bool = True,
    ) -> SecurityAuditLog:
        """Append one audit row and return it.

        ``commit=False`` lets the caller group the audit row with the change
        it describes in a single transaction (used by alert triage); every
        other caller commits here so the row survives even when the enclosing
        request fails afterwards.
        """

        action_value = action.value if isinstance(action, AuditAction) else str(action)
        result_value = result.value if isinstance(result, AuditResult) else str(result)

        entry = SecurityAuditLog(
            action=action_value[:100],
            actor=(actor or "anonymous").strip()[:255] or "anonymous",
            actor_role=(actor_role.strip()[:50] if actor_role and actor_role.strip() else None),
            target_type=target_type[:50] if target_type else None,
            target_id=str(target_id)[:255] if target_id is not None else None,
            result=result_value[:20],
            source_ip=source_ip or None,
            detail=sanitize_detail(detail) if detail is not None else None,
            note=(note.strip()[:MAX_STRING_LENGTH] if note and note.strip() else None),
        )

        self.db.add(entry)
        if commit:
            self.db.commit()
            self.db.refresh(entry)

        logger.info(
            "security_audit action=%s result=%s actor=%s role=%s target=%s:%s",
            entry.action,
            entry.result,
            entry.actor,
            entry.actor_role or "-",
            entry.target_type or "-",
            entry.target_id or "-",
        )

        return entry

    def record_auth_failure(
        self,
        *,
        action: AuditAction | str = AuditAction.AUTH_FAILED,
        actor: str | None = None,
        target_id: str | None = None,
        source_ip: str | None = None,
        note: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort record of a rejected authentication attempt.

        Called from auth dependencies right before raising 401/403: any
        database error is logged and swallowed so the caller still returns
        its rejection status instead of a 500.  The presented credential is
        never passed in - only the reason and the request path.
        """

        try:
            self.record(
                action=action,
                result=AuditResult.FAILURE,
                actor=actor,
                target_type="endpoint",
                target_id=target_id,
                source_ip=source_ip,
                detail=detail,
                note=note,
            )
        except Exception:  # pragma: no cover - defensive
            logger.exception(
                "failed to record auth audit entry (path=%s note=%s)",
                target_id,
                note,
            )
            self.db.rollback()

    # ------------------------------------------------------------------
    # Queries (read-only)
    # ------------------------------------------------------------------
    @staticmethod
    def _conditions(
        *,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        since: Any = None,
        until: Any = None,
    ) -> list:
        """Build the shared WHERE clauses (used by list and count)."""

        conditions = []
        if action:
            conditions.append(SecurityAuditLog.action == action)
        if actor:
            conditions.append(SecurityAuditLog.actor == actor)
        if result:
            conditions.append(SecurityAuditLog.result == result)
        if since is not None:
            conditions.append(SecurityAuditLog.created_at >= since)
        if until is not None:
            conditions.append(SecurityAuditLog.created_at <= until)
        return conditions

    def list_entries(
        self,
        *,
        skip: int = 0,
        limit: int = 100,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        since: Any = None,
        until: Any = None,
    ) -> list[SecurityAuditLog]:
        """Newest-first page of audit rows matching every supplied filter."""

        from sqlalchemy import select

        statement = (
            select(SecurityAuditLog)
            .where(
                *self._conditions(
                    action=action,
                    actor=actor,
                    result=result,
                    since=since,
                    until=until,
                )
            )
            .order_by(SecurityAuditLog.created_at.desc(), SecurityAuditLog.id.desc())
            .offset(skip)
            .limit(limit)
        )

        return list(self.db.scalars(statement))

    def count_entries(
        self,
        *,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        since: Any = None,
        until: Any = None,
    ) -> int:
        """Number of audit rows matching the filters (drives pagination)."""

        from sqlalchemy import func, select

        statement = select(func.count(SecurityAuditLog.id)).where(
            *self._conditions(
                action=action,
                actor=actor,
                result=result,
                since=since,
                until=until,
            )
        )
        return int(self.db.execute(statement).scalar_one())

