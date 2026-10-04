SERVICE_THRESHOLDS = {
    "ssh": {
        "failure_threshold": 5,
        "window_seconds": 300,
        "password_spray_users": 5,
        "distributed_ips": 3,
        "credential_stuffing_users": 10,
        "credential_stuffing_failures": 20,
    },
    "rdp": {
        "failure_threshold": 5,
        "window_seconds": 300,
        "password_spray_users": 5,
        "distributed_ips": 3,
        "credential_stuffing_users": 10,
        "credential_stuffing_failures": 20,
    },
    "web": {
        "failure_threshold": 10,
        "window_seconds": 300,
        "password_spray_users": 8,
        "distributed_ips": 4,
        "credential_stuffing_users": 15,
        "credential_stuffing_failures": 30,
    },
    "api": {
        "failure_threshold": 20,
        "window_seconds": 300,
        "password_spray_users": 10,
        "distributed_ips": 5,
        "credential_stuffing_users": 20,
        "credential_stuffing_failures": 40,
    },
}

DEFAULT_THRESHOLDS = {
    "failure_threshold": 5,
    "window_seconds": 300,
    "password_spray_users": 5,
    "distributed_ips": 3,
    "credential_stuffing_users": 10,
    "credential_stuffing_failures": 20,
}

# ---------------------------------------------------------------------------
# Runtime tuning (persisted configuration override)
#
# The static dictionaries above are the *built-in defaults*.  A deployment may
# override any of them at runtime through ``PUT /api/v1/config/``; the saved
# profile is persisted in the ``system_config`` table and applied to this
# process-local holder at startup and on every save/reset by
# ``app.services.config_service``.  ``get_service_thresholds`` and friends
# consult the holder, so the live detection engine runs with the operator's
# values immediately - no restart, no env var round-trip.
#
# Only values the detection engine genuinely consumes are exposed (see
# `app.schemas.system_config`).  Nothing here invents knobs the engine cannot
# act on (account lockout, polling intervals, notification channels): those
# subsystems do not exist in this codebase, so configuration for them would
# silently do nothing.
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field as _dataclass_field  # noqa: E402

#: Time an attack session stays relevant without further detections
#: (``AttackSessionIntegrationService`` correlates alerts to an active session
#: only inside this window).  Was previously a hard-coded literal of 600.
SESSION_CORRELATION_TIMEOUT_SECONDS = 600


@dataclass
class RuntimeTuning:
    """Process-local detection overrides layered above the built-in defaults."""

    #: Per-service threshold overrides (merged over ``SERVICE_THRESHOLDS``).
    service_overrides: dict[str, dict[str, int]] = _dataclass_field(
        default_factory=dict
    )
    #: Service-independent rule-window overrides (merged over the constants).
    rule_windows: dict[str, int] = _dataclass_field(default_factory=dict)
    #: Attack-session correlation timeout in seconds.
    correlation_timeout_seconds: int = SESSION_CORRELATION_TIMEOUT_SECONDS


_runtime_tuning = RuntimeTuning()


def get_runtime_tuning() -> RuntimeTuning:
    """Return the process-local runtime tuning (defaults when untouched)."""
    return _runtime_tuning


def set_runtime_tuning(
    *,
    service_overrides: dict[str, dict[str, int]] | None = None,
    rule_windows: dict[str, int] | None = None,
    correlation_timeout_seconds: int | None = None,
) -> None:
    """Replace the runtime overrides (called from the config service)."""
    if service_overrides is not None:
        _runtime_tuning.service_overrides = {
            str(service): {
                str(field): int(value)
                for field, value in overrides.items()
                if value is not None
            }
            for service, overrides in service_overrides.items()
        }
    if rule_windows is not None:
        _runtime_tuning.rule_windows = {
            str(name): int(value)
            for name, value in rule_windows.items()
            if value is not None
        }
    if correlation_timeout_seconds is not None:
        _runtime_tuning.correlation_timeout_seconds = int(correlation_timeout_seconds)


def reset_runtime_tuning() -> None:
    """Restore the built-in defaults (startup, config reset and every test)."""
    global _runtime_tuning
    _runtime_tuning = RuntimeTuning()


def get_service_thresholds(service: str | None):
    """Get the *effective* thresholds for a service.

    Built-in defaults, layered with any runtime override the operator saved
    through the configuration API.  Unknown/missing services keep the
    default thresholds untouched, so a configuration scoped to the four
    known services never changes behaviour for an unrecognised collector.
    """
    if service and service in SERVICE_THRESHOLDS:
        base = dict(SERVICE_THRESHOLDS[service])
    else:
        base = dict(DEFAULT_THRESHOLDS)

    override = _runtime_tuning.service_overrides.get(service or "", {})
    base.update(
        {key: value for key, value in override.items() if value is not None}
    )
    return base



# Rule parameters that are independent of the target service.
#
# These are the single source of truth for both ingestion (``app.api.events``)
# and the rule description returned with an alert (``get_detection_rule``), so
# the investigation UI never has to duplicate - and drift from - the values the
# detection engine actually ran with.
FAILED_THEN_SUCCESS_MINIMUM_FAILURES = 3
FAILED_THEN_SUCCESS_WINDOW_SECONDS = 300
CREDENTIAL_STUFFING_WINDOW_SECONDS = 600
LOW_AND_SLOW_MINIMUM_FAILURES = 10
LOW_AND_SLOW_WINDOW_SECONDS = 3600
LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS = 5

#: Default values for the service-independent rule windows.  The runtime
#: configuration API can override these (layered on by :func:`get_rule_windows`).
RULE_WINDOW_DEFAULTS = {
    "failed_then_success_minimum_failures": FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
    "failed_then_success_window_seconds": FAILED_THEN_SUCCESS_WINDOW_SECONDS,
    "credential_stuffing_window_seconds": CREDENTIAL_STUFFING_WINDOW_SECONDS,
    "low_and_slow_minimum_failures": LOW_AND_SLOW_MINIMUM_FAILURES,
    "low_and_slow_window_seconds": LOW_AND_SLOW_WINDOW_SECONDS,
    "low_and_slow_minimum_active_intervals": LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
}


def get_rule_windows() -> dict[str, int]:
    """Effective service-independent rule windows (defaults + runtime tuning).

    Detectors and :func:`get_detection_rule` both read through this so the
    rule context shown in the investigation UI always matches the values the
    engine actually runs with.
    """
    merged = dict(RULE_WINDOW_DEFAULTS)
    merged.update(
        {
            key: value
            for key, value in _runtime_tuning.rule_windows.items()
            if value is not None
        }
    )
    return merged


def get_rule_window(name: str, default: int) -> int:
    """Resolve one rule-window value, falling back to a caller-supplied default."""
    return get_rule_windows().get(name, default)


def get_detection_rule(
    alert_type: str,
    service: str | None = None,
) -> dict | None:
    """Describe the rule parameters behind an ``alerts.alert_type``.

    The numbers are derived from the same configuration ingestion uses
    (:func:`get_service_thresholds` plus :func:`get_rule_windows` - both of
    which resolve any runtime tuning the operator saved), so an analyst sees
    what the engine required rather than a browser-side copy that could
    drift.  Unknown alert types return ``None``, and callers then fall back to
    the persisted detection evidence alone.

    Caveat: this reports the *current* configuration.  If the configuration
    changed after an alert was raised, the returned values may differ from the
    ones in force at detection time - ``evidence.window_seconds`` on the alert
    always holds the window the detector actually used.
    """

    thresholds = get_service_thresholds(service)
    windows = get_rule_windows()

    failure_threshold: int = thresholds["failure_threshold"]
    window_seconds: int = thresholds["window_seconds"]

    spray_failures = failure_threshold * 2
    spray_users: int = thresholds["password_spray_users"]
    distributed_failures = failure_threshold * 2
    distributed_ips: int = thresholds["distributed_ips"]
    stuffing_failures: int = thresholds["credential_stuffing_failures"]
    stuffing_users: int = thresholds["credential_stuffing_users"]

    failed_min = windows["failed_then_success_minimum_failures"]
    failed_window = windows["failed_then_success_window_seconds"]
    stuffing_window = windows["credential_stuffing_window_seconds"]
    slow_min = windows["low_and_slow_minimum_failures"]
    slow_window = windows["low_and_slow_window_seconds"]
    slow_intervals = windows["low_and_slow_minimum_active_intervals"]

    rules: dict[str, dict] = {
        "single_account_bruteforce": {
            "label": "Single Account Brute Force",
            "threshold_label": "Failed attempts against the same account",
            "threshold": failure_threshold,
            "secondary_label": None,
            "secondary_threshold": None,
            "window_seconds": window_seconds,
            "requirement": (
                f"{failure_threshold} failed authentication attempts against "
                f"the same account from the same source IP within "
                f"{window_seconds} seconds."
            ),
        },
        "password_spraying": {
            "label": "Password Spray",
            "threshold_label": "Failed attempts from the source IP",
            "threshold": spray_failures,
            "secondary_label": "Distinct accounts targeted",
            "secondary_threshold": spray_users,
            "window_seconds": window_seconds,
            "requirement": (
                f"{spray_failures} failed authentication attempts spread over "
                f"{spray_users} distinct accounts from one source IP within "
                f"{window_seconds} seconds."
            ),
        },
        "distributed_bruteforce": {
            "label": "Distributed Brute Force",
            "threshold_label": "Failed attempts against the same account",
            "threshold": distributed_failures,
            "secondary_label": "Distinct source IPs",
            "secondary_threshold": distributed_ips,
            "window_seconds": window_seconds,
            "requirement": (
                f"{distributed_failures} failed authentication attempts against "
                f"the same account from {distributed_ips} distinct source IPs "
                f"within {window_seconds} seconds."
            ),
        },
        "failed_then_success": {
            "label": "Failed -> Success",
            "threshold_label": "Failed attempts before the successful login",
            "threshold": failed_min,
            "secondary_label": None,
            "secondary_threshold": None,
            "window_seconds": failed_window,
            "requirement": (
                f"{failed_min} failed authentication "
                f"attempts followed by a successful login from the same source "
                f"IP within {failed_window} seconds."
            ),
        },
        "credential_stuffing": {
            "label": "Credential Stuffing",
            "threshold_label": "Failed attempts from the source IP",
            "threshold": stuffing_failures,
            "secondary_label": "Distinct accounts targeted",
            "secondary_threshold": stuffing_users,
            "window_seconds": stuffing_window,
            "requirement": (
                f"{stuffing_failures} failed authentication attempts spread over "
                f"{stuffing_users} distinct accounts from one source IP within "
                f"{stuffing_window} seconds."
            ),
        },
        "low_and_slow": {
            "label": "Low & Slow Attack",
            "threshold_label": "Failed attempts against the same account",
            "threshold": slow_min,
            "secondary_label": "Active time intervals",
            "secondary_threshold": slow_intervals,
            "window_seconds": slow_window,
            "requirement": (
                f"{slow_min} failed authentication attempts "
                f"against the same account spread over at least "
                f"{slow_intervals} intervals within "
                f"{slow_window} seconds."
            ),
        },
    }

    rule = rules.get(alert_type)
    if rule is None:
        return None

    return {"alert_type": alert_type, **rule}