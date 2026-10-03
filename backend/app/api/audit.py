"""Security audit log API - read-only access to immutable evidence.

* ``GET /api/v1/audit/``  newest-first, server-side paginated listing with
  optional ``action`` / ``user`` / ``result`` / ``since`` / ``until`` filters.

There is intentionally **no** POST/PATCH/PUT/DELETE route: audit rows are
append-only evidence written by server-side hooks (triage transitions, IP
list changes, failed authentication) and cannot be created or modified
through the API.  The model rejects ORM updates/deletes and the database
installs triggers that reject raw ``UPDATE`` / ``DELETE`` statements.

Reads require an ``admin``-role bearer token from ``ALERT_TRIAGE_API_TOKENS``
plus an ``X-User-Id`` identity header - the same fail-closed posture as
triage writes, because the log exposes actor identities and attack context.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.schemas.audit_log import AuditLogPage, AuditLogResponse
from app.services.audit_service import AuditService


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["audit"],
)

RESULT_VALUES = ("success", "failure", "denied")


def require_audit_admin(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
) -> str:
    """Authenticate an audit-log read and require the admin role.

    Follows ``require_alert_triage_auth``: the role is bound to the *token*
    server-side, so an analyst token can never read the audit log even if it
    claims a role header.  Unconfigured deployments fail closed with 503.
    """

    token_roles = settings.alert_triage_token_roles
    if not token_roles:
        raise HTTPException(
            status_code=503,
            detail="Audit log API is not configured",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    role = token_roles.get(token)
    if role is None:
        raise HTTPException(status_code=403, detail="Forbidden")

    if role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Reading the audit log requires the admin role",
        )

    if not x_user_id or not x_user_id.strip():
        raise HTTPException(
            status_code=401,
            detail="User identity required",
        )

    return x_user_id.strip()


@router.get("/", response_model=AuditLogPage)
def list_audit_entries(
    db: Session = Depends(get_db),
    _: str = Depends(require_audit_admin),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=100),
    user: str | None = Query(default=None, max_length=255),
    result: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
):
    """List audit entries newest first (paginated, optionally filtered)."""

    if result is not None and result not in RESULT_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"result must be one of {', '.join(RESULT_VALUES)}",
        )

    service = AuditService(db)
    filters = {
        "action": action,
        "actor": user,
        "result": result,
        "since": since,
        "until": until,
    }

    return AuditLogPage(
        items=[
            AuditLogResponse.model_validate(entry)
            for entry in service.list_entries(skip=skip, limit=limit, **filters)
        ],
        total=service.count_entries(**filters),
    )
