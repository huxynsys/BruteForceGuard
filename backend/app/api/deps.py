"""Shared authentication + authorization dependencies (backend RBAC).

Every protected route resolves its caller through this module.  Two
credential families are accepted and unified into one :class:`Principal`:

* **Sessions** - the interactive login tokens issued by
  ``POST /api/v1/auth/login`` (role taken from the ``users`` row, re-checked
  on every request for expiry / revocation / deactivation);
* **Static API tokens** - the existing deployment credentials
  (``ALERT_TRIAGE_API_TOKENS`` role-bound, ``IP_MANAGEMENT_API_TOKENS``
  explicitly authorized), behaviour unchanged.

The role is always resolved *server-side* from the credential itself; no
client-supplied header can influence it.  Frontend gating is cosmetic - the
enforcement point is here.

Status-code contract (kept consistent with the pre-existing endpoints):

* ``401`` - no credential presented (or session invalid/expired), with
  ``WWW-Authenticate: Bearer``; audited as ``auth.failed``;
* ``403`` - credential valid but insufficient role / unknown static token;
* ``503`` - fail-closed deployment state (no static tokens configured *and*
  no session), never audited because it would repeat on every request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.models.user import ROLE_ADMIN, AuthSession, User
from app.services import auth_service
from app.services.audit_service import AuditService, client_ip

#: Roles understood by the authorization layer.
ROLE_ANALYST = "analyst"


@dataclass(frozen=True)
class Principal:
    """Authenticated identity performing a request."""

    #: Username (session) or ``X-User-Id`` (static token) - the audit actor.
    user: str
    #: ``admin`` or ``analyst``, always bound to the credential server-side.
    role: str
    #: ``session`` (interactive login) or ``token`` (static API token).
    via: str
    #: Session row id when ``via == "session"`` (else ``None``).
    session_id: int | None = None
    #: Session expiry when ``via == "session"`` (else ``None``).
    expires_at: datetime | None = None
    #: Resolved user row for session principals (``None`` for tokens).
    user_row: User | None = None
    #: Live session row for session principals (``None`` for tokens).
    session_row: AuthSession | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


def bearer_token(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization: Bearer ...`` header."""

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return token or None
    return None


def _session_principal(db: Session, token: str) -> Principal | None:
    """Resolve a live login session to a principal (``None`` otherwise)."""

    resolved = auth_service.resolve_session(db, token)
    if resolved is None:
        return None
    user, session_row = resolved
    return Principal(
        user=user.username,
        role=user.role,
        via="session",
        session_id=session_row.id,
        expires_at=session_row.expires_at,
        user_row=user,
        session_row=session_row,
    )


def resolve_principal(
    db: Session, token: str | None, x_user_id: str | None
) -> Principal | None:
    """Resolve any accepted credential to a :class:`Principal`.

    Order: login session first (works even when no static tokens are
    configured), then role-bound triage tokens, then explicitly authorized
    IP-management tokens (admin-equivalent, since those tokens may change
    blocklists).  Returns ``None`` for absent/unknown credentials.
    """

    if not token:
        return None

    principal = _session_principal(db, token)
    if principal is not None:
        return principal

    role = settings.alert_triage_token_roles.get(token)
    if role is not None:
        return Principal(
            user=(x_user_id or "api-token").strip() or "api-token",
            role=role,
            via="token",
        )

    if token in settings.ip_management_api_token_list:
        return Principal(
            user=(x_user_id or "api-token").strip() or "api-token",
            role=ROLE_ADMIN,
            via="token",
        )

    return None


def _statics_unconfigured() -> bool:
    """True when no static API token is configured at all (fail-closed)."""

    return not settings.alert_triage_token_roles and not (
        settings.ip_management_api_token_list
    )


# ---------------------------------------------------------------------------
# require_reader: any authenticated principal (admin or analyst)
# ---------------------------------------------------------------------------


def require_reader(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    request: Request = None,
    db: Session = Depends(get_db),
) -> Principal:
    """Authenticate a *read* of security data (admin or analyst may view).

    Static-token reads do not require an identity header: the role is bound
    to the token itself and reads perform no audited action.  Rejections are
    appended to the security audit log without the presented credential.
    """

    audit = AuditService(db)
    source_ip = client_ip(request)
    path = request.url.path if request is not None else None

    def _deny(note: str, status_code: int, detail: str, **headers) -> HTTPException:
        audit.record_auth_failure(
            actor=(
                x_user_id.strip() if x_user_id and x_user_id.strip() else "anonymous"
            ),
            target_id=path,
            source_ip=source_ip,
            note=note,
            detail={"path": path, "status": status_code},
        )
        return HTTPException(
            status_code=status_code, detail=detail, headers=headers or None
        )

    token = bearer_token(authorization)
    if token is None:
        raise _deny(
            "Read rejected: bearer token missing",
            401,
            "Authentication required",
            **{"WWW-Authenticate": "Bearer"},
        )

    principal = resolve_principal(db, token, x_user_id)
    if principal is None:
        raise _deny(
            "Read rejected: unknown or expired credentials",
            401,
            "Authentication required",
            **{"WWW-Authenticate": "Bearer"},
        )

    return principal


# ---------------------------------------------------------------------------
# require_admin: admin role only
# ---------------------------------------------------------------------------


def make_require_admin(service_name: str):
    """Build an admin-only dependency with a service-specific 503 message."""

    def require_admin(
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_user_id: str | None = Header(default=None, alias="X-User-Id"),
        request: Request = None,
        db: Session = Depends(get_db),
    ) -> Principal:
        """Authenticate and require the ``admin`` role.

        A live admin session authenticates even when no static tokens are
        configured; static tokens keep the original fail-closed semantics
        (503 unconfigured, 401 missing identity, 403 wrong role/unknown).
        """

        audit = AuditService(db)
        source_ip = client_ip(request)
        path = request.url.path if request is not None else None

        def _deny(note: str, status_code: int, detail: str, **headers) -> HTTPException:
            audit.record_auth_failure(
                actor=(
                    x_user_id.strip()
                    if x_user_id and x_user_id.strip()
                    else "anonymous"
                ),
                target_id=path,
                source_ip=source_ip,
                note=note,
                detail={"path": path, "status": status_code},
            )
            return HTTPException(
                status_code=status_code, detail=detail, headers=headers or None
            )

        token = bearer_token(authorization)

        if token is not None:
            principal = _session_principal(db, token)
            if principal is not None:
                if not principal.is_admin:
                    raise _deny(
                        f"{service_name} rejected: insufficient role",
                        403,
                        "This action requires the admin role",
                    )
                return principal

            # Static-token path (roles bound to the token, never to headers).
            role = settings.alert_triage_token_roles.get(token)
            if role is None and token in settings.ip_management_api_token_list:
                role = ROLE_ADMIN

            if role is not None:
                if role != ROLE_ADMIN:
                    raise _deny(
                        f"{service_name} rejected: analyst token",
                        403,
                        "This action requires the admin role",
                    )
                if not x_user_id or not x_user_id.strip():
                    raise _deny(
                        f"{service_name} rejected: identity header missing",
                        401,
                        "User identity required",
                    )
                return Principal(
                    user=x_user_id.strip(), role=ROLE_ADMIN, via="token"
                )

        # No usable session and no matching static token: distinguish a
        # fail-closed deployment (503, not audited) from a rejected attempt.
        if _statics_unconfigured():
            raise HTTPException(
                status_code=503,
                detail=f"{service_name} API is not configured",
            )

        if token is None:
            raise _deny(
                f"{service_name} rejected: bearer token missing",
                401,
                "Authentication required",
                **{"WWW-Authenticate": "Bearer"},
            )

        raise _deny(
            f"{service_name} rejected: unknown token",
            403,
            "Forbidden",
        )

    require_admin.__name__ = (
        f"require_{service_name.lower().replace(' ', '_').replace('-', '_')}_admin"
    )
    return require_admin


#: Generic admin dependency (user management and other admin-only routes).
require_admin = make_require_admin("Admin action")


