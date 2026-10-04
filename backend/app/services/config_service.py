"""Runtime configuration service - persist, validate, apply, audit.

Single entry point behind ``/api/v1/config`` that:

* loads the persisted profile (or engine defaults when no row exists yet),
* saves a versioned full-profile replace with an optimistic lock,
* resets the profile to the engine's built-in defaults,
* applies the profile to the process-local tuning in
  ``app.core.detection_config`` so the running detection engine uses it
  immediately, and
* appends a ``settings.change`` entry to the immutable security audit log on
  every successful update/reset (never storing secret material - the audit
  sanitizer in ``app.services.audit_service`` redacts anything secret-looking
  and this profile contains no secrets by design).
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError

from sqlalchemy.orm import Session

from app.core.detection_config import (
    reset_runtime_tuning,
    set_runtime_tuning,
)
from app.models.audit_log import AuditAction, AuditResult
from app.models.system_config import SYSTEM_CONFIG_SINGLETON_ID, SystemConfig
from app.schemas.system_config import (
    RuntimeConfigData,
    SystemConfigResponse,
    default_runtime_config,
)
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class ConfigVersionConflictError(Exception):
    """A concurrent update bumped the version between read and write."""


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def load_config_row(db: Session) -> SystemConfig | None:
    """The persisted configuration row (``None`` before the first save)."""
    return db.get(SystemConfig, SYSTEM_CONFIG_SINGLETON_ID)


def parse_stored_config(data: dict[str, Any]) -> RuntimeConfigData | None:
    """Parse and validate raw stored configuration data.

    Returns ``None`` on validation error.
    """
    try:
        return RuntimeConfigData.model_validate(data)
    except ValidationError as e:
        logger.warning("stored system_config failed validation: %s", e)
        return None


def effective_config(db: Session) -> SystemConfigResponse:
    """The effective configuration: persisted profile or engine defaults.

    An invalid/corrupt stored profile never bricks the API or the engine: it
    is logged and replaced by the built-in defaults.
    """
    row = load_config_row(db)
    if row is None:
        return SystemConfigResponse(
            version=0,
            config=default_runtime_config(),
        )

    data = parse_stored_config(row.data)
    if data is None:
        logger.warning(
            "stored system_config version=%s failed validation; using defaults",
            row.version,
        )
        return SystemConfigResponse(
            version=row.version,
            config=default_runtime_config(),
            updated_at=row.updated_at,
            updated_by=row.updated_by,
            updated_by_role=row.updated_by_role,
        )

    return SystemConfigResponse(
        version=row.version,
        config=data,
        updated_at=row.updated_at,
        updated_by=row.updated_by,
        updated_by_role=row.updated_by_role,
    )


# ---------------------------------------------------------------------------
# Apply to the live detection engine (process-local tuning)
# ---------------------------------------------------------------------------


def apply_config_to_tuning(data: RuntimeConfigData) -> None:
    """Push a validated profile into the process-local engine tuning."""
    detection = data.detection

    set_runtime_tuning(
        service_overrides={
            service: thresholds.model_dump()
            for service, thresholds in detection.services.items()
        },
        rule_windows=detection.rules.model_dump(),
        correlation_timeout_seconds=detection.session_correlation_timeout_seconds,
    )


def load_config_into_tuning(db: Session) -> bool:
    """Startup hook: apply the persisted profile to the engine tuning.

    Returns ``True`` when a profile was applied, ``False`` when the engine is
    running on its built-in defaults (no row, or the table does not exist
    yet).  Never raises - startup must not fail on a bad row.
    """
    try:
        response = effective_config(db)
    except Exception:  # noqa: BLE001 - table missing / db unavailable
        logger.exception("failed to load runtime configuration at startup")
        return False

    apply_config_to_tuning(response.config)
    return response.version > 0


# ---------------------------------------------------------------------------
# Writes (versioned save + reset)
# ---------------------------------------------------------------------------


def save_config(
    db: Session,
    config: RuntimeConfigData,
    expected_version: int,
    *,
    actor: str,
    actor_role: str,
    source_ip: str | None,
) -> SystemConfigResponse:
    """Persist a versioned profile, apply it and audit the change.

    Raises :class:`ConfigVersionConflictError` when ``expected_version`` does
    not match the persisted version (or a stale first-write when a row was
    created meanwhile), so a concurrent editor can never clobber silently.
    """
    row = load_config_row(db)

    if row is None:
        if expected_version != 0:
            raise ConfigVersionConflictError(
                "configuration was updated by someone else; reload and retry"
            )
        row = SystemConfig(id=SYSTEM_CONFIG_SINGLETON_ID, version=1)
        db.add(row)
    else:
        if row.version != expected_version:
            raise ConfigVersionConflictError(
                "configuration was updated by someone else; reload and retry"
            )
        row.version += 1

    row.data = config.model_dump(mode="json")
    row.updated_by = actor
    row.updated_by_role = actor_role
    db.commit()
    db.refresh(row)

    apply_config_to_tuning(config)

    _audit(
        db,
        actor=actor,
        actor_role=actor_role,
        source_ip=source_ip,
        note="Detection configuration updated",
        detail={"version": row.version, "reset": False},
    )

    return SystemConfigResponse(
        version=row.version,
        config=config,
        updated_at=row.updated_at,
        updated_by=row.updated_by,
        updated_by_role=row.updated_by_role,
    )


def reset_config(
    db: Session,
    *,
    actor: str,
    actor_role: str,
    source_ip: str | None,
) -> SystemConfigResponse:
    """Restore the engine's built-in defaults and drop the persisted profile."""
    row = load_config_row(db)
    config = default_runtime_config()

    if row is not None:
        db.delete(row)
        db.commit()

    reset_runtime_tuning()

    _audit(
        db,
        actor=actor,
        actor_role=actor_role,
        source_ip=source_ip,
        note="Detection configuration reset to defaults",
        detail={"version": 0, "reset": True},
    )

    return SystemConfigResponse(
        version=0,
        config=config,
        updated_by=actor,
        updated_by_role=actor_role,
    )


def _audit(
    db: Session,
    *,
    actor: str,
    actor_role: str,
    source_ip: str | None,
    note: str,
    detail: dict[str, Any],
) -> None:
    """Append a ``settings.change`` entry (secret-free by construction)."""
    AuditService(db).record(
        action=AuditAction.SETTINGS_CHANGE,
        result=AuditResult.SUCCESS,
        actor=actor,
        actor_role=actor_role,
        target_type="system_config",
        target_id=str(SYSTEM_CONFIG_SINGLETON_ID),
        source_ip=source_ip,
        detail=detail,
        note=note,
    )


# ---------------------------------------------------------------------------
# Secret hygiene (defence in depth)
# ---------------------------------------------------------------------------

#: Reserved secret-looking *exact* key names.  Matching is exact or by
#: explicit suffix only - never a bare substring - because legitimate engine
#: field names such as ``password_spray_users`` and
#: ``credential_stuffing_failures`` contain fragments like "password" or
#: "credential" yet hold ordinary integers.  The schema forbids unknown
#: fields, so no current profile can carry a secret; this is purely a guard
#: against a future profile drifting from that rule without corrupting real
#: values.
_RESERVED_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "token",
        "access_token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
        "cookie",
    }
)

_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "_password",
    "_passwd",
    "_token",
    "_secret",
    "_apikey",
    "_api_key",
    "_credential",
    "_private_key",
    "_webhook_url",
)

REDACTED_PLACEHOLDER = "[REDACTED]"


def _is_secret_key(key: str) -> bool:
    lowered = str(key).lower().strip()
    if lowered in _RESERVED_SECRET_KEYS:
        return True
    return any(lowered.endswith(suffix) for suffix in _SECRET_KEY_SUFFIXES)


def mask_secrets(value: Any) -> Any:
    """Return a copy of ``value`` with any secret-looking field redacted.

    Applied to the payload of the configuration endpoints so a stored profile
    can never surface secret material in plaintext.  Today there are no secret
    fields (the schema forbids unknown keys), so for a valid profile this is a
    structural no-op that never touches legitimate values.
    """
    if isinstance(value, dict):
        masked: dict[str, Any] = {}
        for key, item in value.items():
            if _is_secret_key(key):
                masked[key] = REDACTED_PLACEHOLDER
            else:
                masked[key] = mask_secrets(item)
        return masked
    if isinstance(value, list):
        return [mask_secrets(item) for item in value]
    return value



