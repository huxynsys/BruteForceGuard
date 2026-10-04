"""Interactive authentication API - login, logout, session introspection.

* ``POST /api/v1/auth/login``   verify username/password, issue a session
* ``POST /api/v1/auth/logout``  revoke the caller's live session
* ``GET  /api/v1/auth/me``      identity + role of the current credential

Sessions are opaque bearer tokens: the response returns the token exactly
once and the database keeps only its SHA-256 hash with an explicit expiry
(``AUTH_SESSION_TTL_MINUTES``).  Every outcome - success, invalid
credentials, rate limiting, logout - is appended to the immutable security
audit log using the reserved ``auth.login`` / ``auth.logout`` actions; the
presented password or token is never part of any audit row.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import Principal, bearer_token, require_reader
from app.db.database import get_db
from app.models.audit_log import AuditAction, AuditResult
from app.schemas.auth import (
    AuthUser,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    MeResponse,
)
from app.services import auth_service
from app.services.audit_service import AuditService, client_ip

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

LOGIN_PATH = "/api/v1/auth/login"


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Verify credentials and start a session.

    Unknown user, wrong password and deactivated account all answer the same
    401 so account existence is never leaked.  Repeated failures per
    (client IP, username) answer 429 with ``Retry-After``.
    """

    source_ip = client_ip(request)
    audit = AuditService(db)

    try:
        auth_service.check_login_rate_limit(source_ip, payload.username)
    except auth_service.LoginRateLimitedError as exc:
        audit.record(
            action=AuditAction.LOGIN,
            result=AuditResult.DENIED,
            actor=payload.username.strip().lower() or "anonymous",
            target_type="user",
            target_id=payload.username.strip().lower() or None,
            source_ip=source_ip,
            note="Login blocked by rate limit",
        )
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts; try again later",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc

    user = auth_service.authenticate(db, payload.username, payload.password)

    if user is None:
        auth_service.register_login_failure(source_ip, payload.username)
        audit.record(
            action=AuditAction.LOGIN,
            result=AuditResult.FAILURE,
            actor=payload.username.strip().lower() or "anonymous",
            target_type="user",
            target_id=payload.username.strip().lower() or None,
            source_ip=source_ip,
            note="Invalid credentials",
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_service.clear_login_failures(source_ip, payload.username)
    token, expires_at = auth_service.create_session(db, user)

    audit.record(
        action=AuditAction.LOGIN,
        result=AuditResult.SUCCESS,
        actor=user.username,
        actor_role=user.role,
        target_type="user",
        target_id=user.id,
        source_ip=source_ip,
        detail={"username": user.username, "role": user.role},
    )

    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        user=AuthUser(username=user.username, role=user.role),
    )


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),
):
    """Revoke the caller's session.

    Only login sessions can be logged out: a static API token is a deployment
    credential with no session to revoke, so it answers 401.
    """

    token = bearer_token(authorization)
    resolved = auth_service.resolve_session(db, token or "")
    if resolved is None:
        raise HTTPException(
            status_code=401,
            detail="No active session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user, session_row = resolved
    auth_service.revoke_session(db, session_row)

    AuditService(db).record(
        action=AuditAction.LOGOUT,
        result=AuditResult.SUCCESS,
        actor=user.username,
        actor_role=user.role,
        target_type="user",
        target_id=user.id,
        source_ip=client_ip(request),
        detail={"username": user.username},
    )

    return LogoutResponse(message="Session revoked")


@router.get("/me", response_model=MeResponse)
def me(
    principal: Principal = Depends(require_reader),
):
    """Identity and role of the current credential (session or token)."""

    return MeResponse(
        user=AuthUser(username=principal.user, role=principal.role),
        via=principal.via,
        session_expires_at=principal.expires_at,
    )
