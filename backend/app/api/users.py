"""Admin-only user management (``/api/v1/users``).

* ``GET   /api/v1/users/``       list accounts (never password hashes)
* ``POST  /api/v1/users/``       create an account (admin|analyst)
* ``PATCH /api/v1/users/{id}``   change role / reset password / toggle active

Every route requires the ``admin`` role (session or admin-role static
token).  The system will not let the last active administrator be demoted or
deactivated, and any privilege or password change revokes that user's live
sessions immediately so the new state applies at once.  All changes are
appended to the security audit log.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_admin
from app.core import security
from app.db.database import get_db
from app.models.audit_log import AuditAction, AuditResult
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services import auth_service
from app.services.audit_service import AuditService, client_ip

router = APIRouter(
    prefix="/api/v1/users",
    tags=["users"],
    dependencies=[Depends(require_admin)],
)


def _not_found(user_id: int) -> HTTPException:
    return HTTPException(status_code=404, detail="User not found")


@router.get("/", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_admin),
):
    """List all accounts (admin only; password hashes are never exposed)."""

    return auth_service.list_users(db)


@router.post("/", response_model=UserResponse, status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_admin),
):
    """Create an account; the password is hashed before it touches storage."""

    try:
        user = auth_service.create_user(
            db,
            username=payload.username,
            password=payload.password,
            role=payload.role,
        )
    except auth_service.DuplicateUsernameError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except auth_service.UnknownRoleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except security.PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    AuditService(db).record(
        action=AuditAction.USER_CREATE,
        result=AuditResult.SUCCESS,
        actor=actor.user,
        actor_role=actor.role,
        target_type="user",
        target_id=user.id,
        source_ip=client_ip(request),
        detail={"username": user.username, "role": user.role},
    )

    return user


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_admin),
):
    """Change role / active flag / password of one account.

    Demoting or deactivating the last active administrator is rejected with
    409.  Role and password changes revoke the target's sessions; the change
    is audited (``role.change`` for role transitions).
    """

    user = auth_service.get_user_by_id(db, user_id)
    if user is None:
        raise _not_found(user_id)

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(
            status_code=422, detail="No changes requested"
        )

    # Guard first so a partially applied change can never strand the system.
    removing_admin = (
        user.role == "admin"
        and user.is_active
        and (
            (payload.role is not None and payload.role != "admin")
            or (payload.is_active is False)
        )
    )
    if removing_admin:
        auth_service.ensure_not_last_admin(db, user)

    # Validate the whole payload before mutating anything, so an invalid
    # password can never be applied after a valid role change.
    if payload.password is not None:
        try:
            security.validate_password_strength(payload.password)
        except security.PasswordPolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        if payload.role is not None:
            auth_service.set_role(db, user, payload.role)
        if payload.is_active is not None:
            auth_service.set_active(db, user, payload.is_active)
        if payload.password is not None:
            auth_service.set_password(db, user, payload.password)
    except auth_service.LastAdminError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except security.PasswordPolicyError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if payload.role is not None:
        action, note = AuditAction.ROLE_CHANGE, f"Role set to {payload.role}"
    elif payload.password is not None:
        action, note = AuditAction.USER_UPDATE, "Password reset"
    else:
        action, note = AuditAction.USER_UPDATE, (
            "Activated" if payload.is_active else "Deactivated"
        )

    AuditService(db).record(
        action=action,
        result=AuditResult.SUCCESS,
        actor=actor.user,
        actor_role=actor.role,
        target_type="user",
        target_id=user.id,
        source_ip=client_ip(request),
        detail={
            "username": user.username,
            "changes": sorted(changes.keys()),
            "new_role": payload.role,
            "is_active": payload.is_active,
            # No password material of any kind reaches the audit log.
            "password_changed": payload.password is not None,
        },
        note=note,
    )

    return user
