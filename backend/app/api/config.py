"""Runtime configuration API - load, save and reset detection settings.

* ``GET  /api/v1/config/``         effective configuration (persisted or built-in
                                   defaults) plus its version and last-writer
                                   metadata
* ``PUT  /api/v1/config/``         versioned full-profile replace (optimistic
                                   lock -> 409 on concurrent edit), validated
                                   server-side by ``app.schemas.system_config``
* ``POST /api/v1/config/reset``    restore the engine's built-in defaults

Every route requires the ``admin`` role (admin login session or admin-role
bearer token plus ``X-User-Id``) - the same fail-closed posture as the audit
log, because the profile controls detection policy.  Every successful write is
appended to the security audit log (``settings.change``); secrets never enter
this API, the store, or the audit log.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import Principal, make_require_admin
from app.db.database import get_db
from app.schemas.system_config import (
    RuntimeConfigData,
    SystemConfigResponse,
    SystemConfigUpdate,
)
from app.services import config_service
from app.services.audit_service import client_ip

router = APIRouter(
    prefix="/api/v1/config",
    tags=["config"],
)

# Admin-only authentication with the fail-closed 503 wording preserved:
# the role is bound to the credential server-side, so an analyst session or
# analyst token can never read or write detection configuration.
require_config_admin = make_require_admin("System configuration")


def _masked(response: SystemConfigResponse) -> SystemConfigResponse:
    """Re-render the response with any secret-looking key redacted.

    The schema forbids secret-like keys, so this is defence in depth - it
    guarantees the API never surfaces plaintext secrets even if a future
    profile drifts from that rule.
    """
    payload = response.model_dump(mode="json")
    payload["config"] = config_service.mask_secrets(payload["config"])
    return SystemConfigResponse.model_validate(payload)


@router.get("/", response_model=SystemConfigResponse)
def get_config(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_config_admin),
) -> SystemConfigResponse:
    """Return the effective configuration and its version."""
    return _masked(config_service.effective_config(db))


@router.put("/", response_model=SystemConfigResponse)
def update_config(
    payload: SystemConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_config_admin),
) -> SystemConfigResponse:
    """Persist a validated profile, apply it to the engine and audit it.

    ``payload.version`` is the optimistic lock: a 409 tells the caller the
    profile changed under it and to reload before retrying.
    """
    try:
        response = config_service.save_config(
            db,
            config=payload.config,
            expected_version=payload.version,
            actor=actor.user,
            actor_role=actor.role,
            source_ip=client_ip(request),
        )
    except config_service.ConfigVersionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _masked(response)


@router.post("/reset", response_model=SystemConfigResponse)
def reset_config(
    request: Request,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_config_admin),
) -> SystemConfigResponse:
    """Restore the built-in defaults and apply them to the engine."""
    response = config_service.reset_config(
        db,
        actor=actor.user,
        actor_role=actor.role,
        source_ip=client_ip(request),
    )
    return _masked(response)
