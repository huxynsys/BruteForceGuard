"""Security audit log API - read-only access to immutable evidence.

* ``GET /api/v1/audit/``  newest-first, server-side paginated listing with
  optional ``action`` / ``user`` / ``result`` / ``since`` / ``until`` filters.

There is intentionally **no** POST/PATCH/PUT/DELETE route: audit rows are
append-only evidence written by server-side hooks (triage transitions, IP
list changes, failed authentication) and cannot be created or modified
through the API.  The model rejects ORM updates/deletes and the database
installs triggers that reject raw ``UPDATE`` / ``DELETE`` statements.

Reads require the ``admin`` role - an admin login session or an
``admin``-role bearer token from ``ALERT_TRIAGE_API_TOKENS`` plus an
``X-User-Id`` identity header - the same fail-closed posture as triage
writes, because the log exposes actor identities and attack context.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, make_require_admin
from app.db.database import get_db
from app.schemas.audit_log import AuditLogPage, AuditLogResponse
from app.services.audit_service import AuditService


router = APIRouter(
    prefix="/api/v1/audit",
    tags=["audit"],
)

RESULT_VALUES = ("success", "failure", "denied")

# Admin-only authentication with the historical fail-closed 503 wording
# ("Audit log API is not configured") and identity semantics preserved:
# the role is bound to the credential server-side, so an analyst session or
# analyst token can never read the audit log even with a role header.
require_audit_admin = make_require_admin("Audit log")


@router.get("/", response_model=AuditLogPage)
def list_audit_entries(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_audit_admin),
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
