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


def get_service_thresholds(service: str | None):
    """Get thresholds for a specific service."""
    if service and service in SERVICE_THRESHOLDS:
        return SERVICE_THRESHOLDS[service]
    return DEFAULT_THRESHOLDS


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


def get_detection_rule(
    alert_type: str,
    service: str | None = None,
) -> dict | None:
    """Describe the rule parameters behind an ``alerts.alert_type``.

    The numbers are derived from the same configuration ingestion uses
    (:func:`get_service_thresholds` plus the constants above), so an analyst
    sees what the engine required rather than a browser-side copy that could
    drift.  Unknown alert types return ``None``, and callers then fall back to
    the persisted detection evidence alone.

    Caveat: this reports the *current* configuration.  If the configuration
    changed after an alert was raised, the returned values may differ from the
    ones in force at detection time - ``evidence.window_seconds`` on the alert
    always holds the window the detector actually used.
    """

    thresholds = get_service_thresholds(service)

    failure_threshold: int = thresholds["failure_threshold"]
    window_seconds: int = thresholds["window_seconds"]

    spray_failures = failure_threshold * 2
    spray_users: int = thresholds["password_spray_users"]
    distributed_failures = failure_threshold * 2
    distributed_ips: int = thresholds["distributed_ips"]
    stuffing_failures: int = thresholds["credential_stuffing_failures"]
    stuffing_users: int = thresholds["credential_stuffing_users"]

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
            "threshold": FAILED_THEN_SUCCESS_MINIMUM_FAILURES,
            "secondary_label": None,
            "secondary_threshold": None,
            "window_seconds": FAILED_THEN_SUCCESS_WINDOW_SECONDS,
            "requirement": (
                f"{FAILED_THEN_SUCCESS_MINIMUM_FAILURES} failed authentication "
                f"attempts followed by a successful login from the same source "
                f"IP within {FAILED_THEN_SUCCESS_WINDOW_SECONDS} seconds."
            ),
        },
        "credential_stuffing": {
            "label": "Credential Stuffing",
            "threshold_label": "Failed attempts from the source IP",
            "threshold": stuffing_failures,
            "secondary_label": "Distinct accounts targeted",
            "secondary_threshold": stuffing_users,
            "window_seconds": CREDENTIAL_STUFFING_WINDOW_SECONDS,
            "requirement": (
                f"{stuffing_failures} failed authentication attempts spread over "
                f"{stuffing_users} distinct accounts from one source IP within "
                f"{CREDENTIAL_STUFFING_WINDOW_SECONDS} seconds."
            ),
        },
        "low_and_slow": {
            "label": "Low & Slow Attack",
            "threshold_label": "Failed attempts against the same account",
            "threshold": LOW_AND_SLOW_MINIMUM_FAILURES,
            "secondary_label": "Active time intervals",
            "secondary_threshold": LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS,
            "window_seconds": LOW_AND_SLOW_WINDOW_SECONDS,
            "requirement": (
                f"{LOW_AND_SLOW_MINIMUM_FAILURES} failed authentication attempts "
                f"against the same account spread over at least "
                f"{LOW_AND_SLOW_MINIMUM_ACTIVE_INTERVALS} intervals within "
                f"{LOW_AND_SLOW_WINDOW_SECONDS} seconds."
            ),
        },
    }

    rule = rules.get(alert_type)
    if rule is None:
        return None

    return {"alert_type": alert_type, **rule}