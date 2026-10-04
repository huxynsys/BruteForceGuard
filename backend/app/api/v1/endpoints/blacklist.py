from typing import List, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import Principal, bearer_token, require_reader
from app.core.config import settings
from app.db.database import get_db
from app.crud import blacklist as crud_blacklist
from app.models.audit_log import AuditAction, AuditResult
from app.schemas.blacklist import BlacklistEntryCreate, BlacklistEntryResponse
from app.services import auth_service
from app.services.audit_service import AuditService, client_ip


router = APIRouter(
    prefix="/blacklist",
    tags=["Blacklist"],
    responses={404: {"description": "Not found"}},
)


def require_ip_management_auth(
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    request: Request = None,
    db: Session = Depends(get_db),
) -> str:
    """Authenticate an IP-management write and return the acting identity.

    Two credentials are accepted, in order:

    * a live **admin login session** (``POST /api/v1/auth/login``) - the
      analyst role is rejected with 403 because blocklist/whitelist changes
      are admin-only unless explicitly authorized;
    * the static bearer token (``IP_MANAGEMENT_API_TOKENS``) - an explicitly
      authorized deployment credential, unchanged behaviour.

    ``X-User-Id`` names the actor for the static-token path (session
    identities come from the account).  Every rejection is appended to the
    security audit log before the exception is raised - without the presented
    token, which is never stored.  An unconfigured deployment fails closed
    with 503 (a configuration state rather than an authentication attempt,
    so it is not audited).
    """

    audit = AuditService(db)
    source_ip = client_ip(request)
    path = request.url.path if request is not None else None

    def _deny(note: str, status_code: int, detail: str, **headers) -> HTTPException:
        audit.record_auth_failure(
            actor=x_user_id.strip() if x_user_id and x_user_id.strip() else None,
            target_id=path,
            source_ip=source_ip,
            note=note,
            detail={"path": path, "status": status_code},
        )
        return HTTPException(status_code=status_code, detail=detail, headers=headers or None)

    # Admin login sessions authenticate even when no static tokens are
    # configured; analyst sessions are explicitly not authorized here.
    token = bearer_token(authorization)
    if token:
        resolved = auth_service.resolve_session(db, token)
        if resolved is not None:
            user, _session_row = resolved
            if user.role != "admin":
                raise _deny(
                    "IP management write rejected: insufficient role",
                    status.HTTP_403_FORBIDDEN,
                    "IP management requires the admin role or an authorized token",
                )
            return user.username

    if not settings.ip_management_api_token_list:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IP management API is not configured",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise _deny(
            "IP management write rejected: bearer token missing",
            status.HTTP_401_UNAUTHORIZED,
            "Authentication required",
            **{"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    if token not in settings.ip_management_api_token_list:
        raise _deny(
            "IP management write rejected: unknown token",
            status.HTTP_403_FORBIDDEN,
            "Forbidden",
        )

    if not x_user_id or not x_user_id.strip():
        raise _deny(
            "IP management write rejected: identity header missing",
            status.HTTP_401_UNAUTHORIZED,
            "User identity required",
        )

    return x_user_id.strip()


def _entry_value(db_entry) -> str | None:
    """Human-readable identifier of a list entry (never a secret)."""

    return (
        db_entry.ip_address
        or db_entry.ip_range_start
        or db_entry.region_code
    )


@router.post(
    "/", response_model=BlacklistEntryResponse, status_code=status.HTTP_201_CREATED
)
def create_blacklist_entry(
    entry: BlacklistEntryCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(require_ip_management_auth),
):
    """Add a blocklist or whitelist entry and record who added it.

    Success is appended to the security audit log as ``ip.blocklist.add`` or
    ``ip.whitelist.add`` (chosen from the entry's list type); a duplicate
    (409) is recorded as a ``failure`` so rejected writes leave evidence too.
    """

    entry.added_by = actor

    try:
        db_entry = crud_blacklist.create_blacklist_entry(db=db, entry=entry)
    except ValueError as exc:
        AuditService(db).record(
            action=(
                AuditAction.IP_WHITELIST_ADD
                if entry.list_type == "WHITELIST"
                else AuditAction.IP_BLOCKLIST_ADD
            ),
            result=AuditResult.FAILURE,
            actor=actor,
            target_type="blacklist_entry",
            target_id=f"{entry.list_type}:{entry.entry_type}",
            source_ip=client_ip(request),
            detail={
                "list_type": entry.list_type,
                "entry_type": entry.entry_type,
                "value": str(
                    entry.ip_address
                    or entry.ip_network
                    or (entry.region_code or "").upper()
                    or ""
                )
                or None,
                "description": entry.description,
            },
            note=str(exc),
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    if not db_entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error creating blacklist entry")

    AuditService(db).record(
        action=(
            AuditAction.IP_WHITELIST_ADD
            if db_entry.list_type == "WHITELIST"
            else AuditAction.IP_BLOCKLIST_ADD
        ),
        result=AuditResult.SUCCESS,
        actor=actor,
        target_type="blacklist_entry",
        target_id=db_entry.id,
        source_ip=client_ip(request),
        detail={
            "list_type": db_entry.list_type,
            "entry_type": db_entry.entry_type,
            "value": _entry_value(db_entry),
            "description": db_entry.description,
            "expires_at": db_entry.expires_at,
        },
    )

    return BlacklistEntryResponse.model_validate(db_entry)


@router.get(
    "/", response_model=List[BlacklistEntryResponse], status_code=status.HTTP_200_OK
)
def read_blacklist_entries(
    skip: int = 0,
    limit: int = Query(default=100, ge=1, le=500),
    list_type: Literal["BLOCKLIST", "WHITELIST"] | None = None,
    db: Session = Depends(get_db),
    # Viewing the lists is "view security data": any authenticated analyst
    # or admin.  Changing them (POST/DELETE) stays admin/token-gated above.
    _: Principal = Depends(require_reader),
):
    entries = crud_blacklist.get_blacklist_entries(
        db,
        skip=skip,
        limit=limit,
        list_type=list_type.upper() if list_type else None,
    )
    return [BlacklistEntryResponse.model_validate(entry) for entry in entries]


@router.delete(
    "/{entry_id}",
    response_model=BlacklistEntryResponse,
    status_code=status.HTTP_200_OK,
)
def delete_blacklist_entry(
    entry_id: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: str = Depends(require_ip_management_auth),
):
    """Remove a blocklist/whitelist entry and record the actor.

    The entry's fields are captured into the audit row *before* the delete
    commits, so the log preserves which list and value were removed even
    though the row itself is gone.  Unknown ids (404) leave no audit row.
    """

    db_entry = crud_blacklist.delete_blacklist_entry(db=db, entry_id=entry_id)
    if db_entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blacklist entry not found",
        )

    AuditService(db).record(
        action=(
            AuditAction.IP_WHITELIST_REMOVE
            if db_entry.list_type == "WHITELIST"
            else AuditAction.IP_BLOCKLIST_REMOVE
        ),
        result=AuditResult.SUCCESS,
        actor=actor,
        target_type="blacklist_entry",
        target_id=entry_id,
        source_ip=client_ip(request),
        detail={
            "list_type": db_entry.list_type,
            "entry_type": db_entry.entry_type,
            "value": _entry_value(db_entry),
            "description": db_entry.description,
            "added_by": db_entry.added_by,
        },
    )

    return BlacklistEntryResponse.model_validate(db_entry)
