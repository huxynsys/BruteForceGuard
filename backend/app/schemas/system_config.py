"""Pydantic schemas for the runtime configuration API (``/api/v1/config``).

Validation rules live here once and are enforced by FastAPI on every write,
so an out-of-range or unknown value is rejected server-side with a 422 before
it can reach the detection engine.  Every field maps to a knob the engine
genuinely consumes:

* ``detection.services.<svc>``             -> :func:`get_service_thresholds`
* ``detection.rules.*``                     -> :func:`get_rule_windows`
* ``detection.session_correlation_timeout`` -> session correlation window

Fields the requirements sometimes ask for but that have **no consumer** in
this codebase are deliberately *not* modelled: account lockout duration (the
engine performs no account lockout), event polling interval / batch size
(events arrive one-at-a-time over HTTP - nothing polls or batches) and
notification channels (no email/Slack/webhook subsystem exists).  Exposing
those would produce config values that silently do nothing, which the
project explicitly forbids.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.detection_config import (
    CREDENTIAL_STUFFING_WINDOW_SECONDS,
    FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
    FAILED_THEN_SUCCESS_WINDOW_SECONDS,
    LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
    LOW_AND_SLOW_MINIMUM_FAILURES,
    LOW_AND_SLOW_WINDOW_SECONDS,
    SERVICE_THRESHOLDS,
    SESSION_CORRELATION_TIMEOUT_SECONDS,
)

#: The only services the detection engine can tune (same vocabulary as
#: ``SERVICE_THRESHOLDS``).  Anything else is rejected, not ignored.
KNOWN_SERVICES: tuple[str, ...] = ("ssh", "rdp", "web", "api")

#: Categories intentionally not configurable (see module docstring); surfaced
#: in the API response so operators know they are absent by design.
DEFERRED_SECTIONS: tuple[str, ...] = (
    "detection.alert_lockout_duration",
    "event_processing.polling_interval",
    "event_processing.event_batch_size",
    "notifications.email",
    "notifications.slack_or_webhook",
)


class ServiceThresholds(BaseModel):
    """Per-service detection thresholds (all consumed by the engine)."""

    model_config = ConfigDict(extra="forbid")

    failure_threshold: int = Field(5, ge=1, le=1000)
    window_seconds: int = Field(300, ge=1, le=2_592_000)
    password_spray_users: int = Field(5, ge=1, le=1000)
    distributed_ips: int = Field(3, ge=1, le=1000)
    credential_stuffing_users: int = Field(10, ge=1, le=1000)
    credential_stuffing_failures: int = Field(20, ge=1, le=10_000)


class RuleWindows(BaseModel):
    """Service-independent detector windows (``get_rule_windows``)."""

    model_config = ConfigDict(extra="forbid")

    failed_then_success_minimum_failures: int = Field(3, ge=1, le=1000)
    failed_then_success_window_seconds: int = Field(300, ge=1, le=2_592_000)
    credential_stuffing_window_seconds: int = Field(600, ge=1, le=2_592_000)
    low_and_slow_minimum_failures: int = Field(10, ge=1, le=1000)
    low_and_slow_window_seconds: int = Field(3600, ge=60, le=2_592_000)
    low_and_slow_minimum_active_intervals: int = Field(5, ge=1, le=500)


class DetectionConfig(BaseModel):
    """The detection engine's tunable surface."""

    model_config = ConfigDict(extra="forbid")

    services: dict[str, ServiceThresholds]
    rules: RuleWindows
    session_correlation_timeout_seconds: int = Field(
        SESSION_CORRELATION_TIMEOUT_SECONDS, ge=60, le=2_592_000
    )

    @model_validator(mode="after")
    def _validate_service_keys(self) -> "DetectionConfig":
        unknown = set(self.services) - set(KNOWN_SERVICES)
        if unknown:
            raise ValueError(
                "detection.services may only contain "
                f"{', '.join(KNOWN_SERVICES)}; got {', '.join(sorted(unknown))}"
            )
        missing = set(KNOWN_SERVICES) - set(self.services)
        if missing:
            raise ValueError(
                "detection.services must include every known service; "
                f"missing {', '.join(sorted(missing))}"
            )
        return self


class RuntimeConfigData(BaseModel):
    """The complete runtime configuration profile (whole-document replace)."""

    model_config = ConfigDict(extra="forbid")

    detection: DetectionConfig


class SystemConfigUpdate(BaseModel):
    """Body of ``PUT /api/v1/config/``: a versioned full-profile replace."""

    model_config = ConfigDict(extra="forbid")

    #: Expected current version (optimistic lock); 409 when already bumped.
    version: int = Field(ge=0)
    config: RuntimeConfigData


class SystemConfigResponse(BaseModel):
    """Effective configuration returned by the API (GET / PUT / reset)."""

    version: int
    config: RuntimeConfigData
    updated_at: datetime | None = None
    updated_by: str | None = None
    updated_by_role: str | None = None
    #: Categories intentionally not configurable (see module docstring).
    deferred_sections: list[str] = list(DEFERRED_SECTIONS)


# ---------------------------------------------------------------------------
# Defaults derived from the engine configuration (single source of truth)
# ---------------------------------------------------------------------------


def _default_services() -> dict[str, ServiceThresholds]:
    return {
        service: ServiceThresholds(**SERVICE_THRESHOLDS[service])
        for service in KNOWN_SERVICES
    }


def default_runtime_config() -> RuntimeConfigData:
    """Build the default profile straight from the engine's own defaults.

    Kept in lock-step with ``app.core.detection_config`` so a fresh deployment
    (no persisted row) behaves exactly like the pre-configuration engine.
    """
    return RuntimeConfigData(
        detection=DetectionConfig(
            services=_default_services(),
            rules=RuleWindows(
                failed_then_success_minimum_failures=FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
                failed_then_success_window_seconds=FAILED_THEN_SUCCESS_WINDOW_SECONDS,
                credential_stuffing_window_seconds=CREDENTIAL_STUFFING_WINDOW_SECONDS,
                low_and_slow_minimum_failures=LOW_AND_SLOW_MINIMUM_FAILURES,
                low_and_slow_window_seconds=LOW_AND_SLOW_WINDOW_SECONDS,
                low_and_slow_minimum_active_intervals=LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
            ),
            session_correlation_timeout_seconds=SESSION_CORRELATION_TIMEOUT_SECONDS,
        )
    )

