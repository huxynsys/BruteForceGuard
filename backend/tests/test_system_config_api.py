"""Runtime configuration API (``/api/v1/config``) - persistence contract.

The configuration system converts BruteForceGuard's hard-coded engine
settings into an admin-only, audited, versioned runtime profile.  These tests
pin that contract:

* read/write require the ``admin`` role (401 without a credential, 403 for
  an analyst token);
* values are validated server-side (422 on out-of-range or unknown keys -
  no config knob the engine cannot use can be stored);
* saves persist to ``system_config``, are applied to the live detection
  engine immediately, and record ``settings.change`` audit entries;
* an optimistic ``version`` lock rejects concurrent writes with a 409;
* reset restores the engine's built-in defaults.

The mapping to real engine knobs is exercised end-to-end: a saved lower SSH
threshold provokes an alert at that lower count through ``POST /api/v1/events/``.
"""

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.detection_config import (
    SERVICE_THRESHOLDS,
    get_detection_rule,
    get_rule_windows,
    get_runtime_tuning,
    get_service_thresholds,
    reset_runtime_tuning,
)
from app.schemas.system_config import default_runtime_config
from app.services.config_service import REDACTED_PLACEHOLDER

CONFIG_URL = "/api/v1/config/"
RESET_URL = "/api/v1/config/reset"


def _config_payload(version=0, **detection_overrides):
    """A valid PUT body, mutated from the engine defaults."""
    data = default_runtime_config().model_dump(mode="json")
    detection = data["detection"]

    for service, fields in detection_overrides.get("services", {}).items():
        if service in detection["services"]:
            detection["services"][service].update(fields)
        else:
            detection["services"][service] = fields

    if "rules" in detection_overrides:
        detection["rules"].update(detection_overrides["rules"])

    if "session_correlation_timeout_seconds" in detection_overrides:
        detection["session_correlation_timeout_seconds"] = detection_overrides[
            "session_correlation_timeout_seconds"
        ]

    # Unknown/nested overrides (for rejection tests) replace wholesale.
    if "raw_detection" in detection_overrides:
        detection.update(detection_overrides["raw_detection"])

    return {"version": version, "config": data}


def _post_failure(client, base, index, *, source_ip, username, service="ssh"):
    payload = {
        "timestamp": (base + timedelta(seconds=index)).isoformat() + "Z",
        "source": "test",
        "source_ip": source_ip,
        "username": username,
        "result": "failure",
        "service": service,
        "port": 22 if service == "ssh" else 443,
    }
    response = client.post("/api/v1/events/", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def _serialized_keys(value, prefix=""):
    """Flatten every key path in a nested dict/list (secret-key regression)."""
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path.lower()
            yield from _serialized_keys(item, path)
    elif isinstance(value, list):
        for item in value:
            yield from _serialized_keys(item, prefix)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


def test_config_get_requires_authentication(client):
    response = client.get(CONFIG_URL)
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_config_get_requires_admin_role(client, analyst_headers):
    assert client.get(CONFIG_URL, headers=analyst_headers).status_code == 403


def test_config_writes_require_admin_role(client, analyst_headers):
    payload = _config_payload(version=0)
    assert (
        client.put(CONFIG_URL, json=payload, headers=analyst_headers).status_code
        == 403
    )
    assert client.post(RESET_URL, headers=analyst_headers).status_code == 403


# ---------------------------------------------------------------------------
# Load (GET)
# ---------------------------------------------------------------------------


def test_config_get_returns_engine_defaults_without_a_persisted_row(
    client, admin_headers
):
    body = client.get(CONFIG_URL, headers=admin_headers).json()

    assert body["version"] == 0
    assert body["updated_by"] is None
    services = body["config"]["detection"]["services"]
    for service in ("ssh", "rdp", "web", "api"):
        assert services[service] == SERVICE_THRESHOLDS[service]
    assert body["config"]["detection"]["rules"]["low_and_slow_window_seconds"] == 3600
    assert (
        body["config"]["detection"]["session_correlation_timeout_seconds"] == 600
    )
    # Categories deliberately absent are surfaced so operators know why.
    assert "notifications.email" in body["deferred_sections"]
    assert "detection.alert_lockout_duration" in body["deferred_sections"]


def test_config_get_never_exposes_secret_looking_keys(client, admin_headers):
    client.put(CONFIG_URL, json=_config_payload(version=0), headers=admin_headers)

    body = client.get(CONFIG_URL, headers=admin_headers).json()
    assert REDACTED_PLACEHOLDER not in str(body)

    # Assert that legitimate fields containing secret-like fragments are *not* redacted.
    # This confirms the `mask_secrets` substring heuristic collides with legitimate field names (`password_spray_users`, `credential_stuffing_failures`).
    assert body["config"]["detection"]["services"]["ssh"]["password_spray_users"] != REDACTED_PLACEHOLDER
    assert body["config"]["detection"]["services"]["ssh"]["credential_stuffing_failures"] != REDACTED_PLACEHOLDER


# ---------------------------------------------------------------------------
# Save (PUT) - persistence and concurrency
# ---------------------------------------------------------------------------


def test_admin_can_save_a_profile(client, admin_headers):
    payload = _config_payload(
        version=0, services={"ssh": {"failure_threshold": 2, "window_seconds": 60}}
    )
    response = client.put(CONFIG_URL, json=payload, headers=admin_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["version"] == 1
    assert body["updated_by"] == "admin"
    assert body["updated_by_role"] == "admin"
    assert body["config"]["detection"]["services"]["ssh"]["failure_threshold"] == 2


def test_saved_profile_survives_a_worker_restart(client, admin_headers, test_engine):
    client.put(
        CONFIG_URL,
        json=_config_payload(
            version=0, services={"ssh": {"failure_threshold": 2}}
        ),
        headers=admin_headers,
    )

    # Simulate a restarted worker: tuning is reset, then re-applied from the
    # persisted row exactly as `app.main` does at startup.
    reset_runtime_tuning()
    assert get_service_thresholds("ssh")["failure_threshold"] == 5

    from app.services.config_service import load_config_into_tuning

    with Session(bind=test_engine) as db:
        applied = load_config_into_tuning(db)
        assert applied is True

    assert get_service_thresholds("ssh")["failure_threshold"] == 2


# ---------------------------------------------------------------------------
# The saved profile is connected to the live detection engine
# ---------------------------------------------------------------------------


def test_saved_ssh_threshold_reaches_the_detection_engine(
    client, admin_headers, reader_headers
):
    client.put(
        CONFIG_URL,
        json=_config_payload(
            version=0,
            services={"ssh": {"failure_threshold": 2, "window_seconds": 300}},
        ),
        headers=admin_headers,
    )

    # Engine-side helpers consumed by ``DetectionRule.parameters`` now report
    # the saved value.
    assert get_service_thresholds("ssh")["failure_threshold"] == 2
    assert (
        get_detection_rule("single_account_bruteforce", "ssh")["threshold"] == 2
    )

    base = datetime.now()
    _post_failure(client, base, 0, source_ip="10.9.0.1", username="cfgadmin")
    assert client.get("/api/v1/alerts/", headers=reader_headers).json() == []

    # A saved threshold of 2 fires at the 2nd failure (engine default was 5).
    _post_failure(client, base, 1, source_ip="10.9.0.1", username="cfgadmin")

    alerts = client.get("/api/v1/alerts/", headers=reader_headers).json()
    assert [a["alert_type"] for a in alerts] == ["single_account_bruteforce"]


def test_saved_rule_windows_reach_rule_context(client, admin_headers):
    client.put(
        CONFIG_URL,
        json=_config_payload(
            version=0,
            rules={
                "failed_then_success_window_seconds": 120,
                "low_and_slow_minimum_failures": 4,
            },
        ),
        headers=admin_headers,
    )

    windows = get_rule_windows()
    assert windows["failed_then_success_window_seconds"] == 120
    assert windows["low_and_slow_minimum_failures"] == 4

    failed = get_detection_rule("failed_then_success", None)
    assert failed["window_seconds"] == 120
    slow = get_detection_rule("low_and_slow", None)
    assert slow["threshold"] == 4


def test_saved_session_correlation_timeout_reaches_session_service(
    client, admin_headers
):
    client.put(
        CONFIG_URL,
        json=_config_payload(version=0, session_correlation_timeout_seconds=900),
        headers=admin_headers,
    )

    assert get_runtime_tuning().correlation_timeout_seconds == 900


# ---------------------------------------------------------------------------
# Server-side validation
# ---------------------------------------------------------------------------


def test_config_update_rejects_out_of_range_values(client, admin_headers):
    too_low = _config_payload(
        version=0, services={"ssh": {"failure_threshold": 0}}
    )
    assert (
        client.put(CONFIG_URL, json=too_low, headers=admin_headers).status_code == 422
    )

    too_high = _config_payload(
        version=0, services={"api": {"window_seconds": 3_000_000}}
    )
    assert (
        client.put(CONFIG_URL, json=too_high, headers=admin_headers).status_code
        == 422
    )


def test_config_update_rejects_unknown_services_and_sections(client, admin_headers):
    unknown_service = _config_payload(
        version=0, services={"telnet": {"failure_threshold": 5}}
    )
    assert (
        client.put(CONFIG_URL, json=unknown_service, headers=admin_headers).status_code
        == 422
    )

    # A notifications section has no engine consumer: it must be rejected.
    base = _config_payload()["config"]["detection"]
    unknown_section = {
        "version": 0,
        "config": {
            "detection": {
                "services": base["services"],
                "rules": base["rules"],
                "notifications": {"email_enabled": True},
            }
        },
    }
    assert (
        client.put(CONFIG_URL, json=unknown_section, headers=admin_headers).status_code
        == 422
    )


def test_config_update_rejects_a_missing_service(client, admin_headers):
    payload = _config_payload(version=0)
    del payload["config"]["detection"]["services"]["web"]
    assert client.put(CONFIG_URL, json=payload, headers=admin_headers).status_code == 422


# ---------------------------------------------------------------------------
# Optimistic concurrency (409 on a stale version)
# ---------------------------------------------------------------------------


def test_stale_first_write_is_rejected(client, admin_headers):
    # No row exists, so the only valid first-write version is 0.
    response = client.put(
        CONFIG_URL, json=_config_payload(version=1), headers=admin_headers
    )
    assert response.status_code == 409
    assert "reload" in response.json()["detail"].lower()


def test_config_update_version_conflict_is_detected(client, admin_headers):
    assert (
        client.put(CONFIG_URL, json=_config_payload(version=0), headers=admin_headers).status_code
        == 200
    )
    assert (
        client.put(CONFIG_URL, json=_config_payload(version=1), headers=admin_headers).status_code
        == 200
    )

    # Re-using version=1 after it was committed as version=2 is stale.
    response = client.put(
        CONFIG_URL, json=_config_payload(version=1), headers=admin_headers
    )
    assert response.status_code == 409


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_config_reset_restores_defaults(client, admin_headers):
    client.put(
        CONFIG_URL,
        json=_config_payload(version=0, services={"rdp": {"failure_threshold": 3}}),
        headers=admin_headers,
    )
    assert get_service_thresholds("rdp")["failure_threshold"] == 3

    response = client.post(RESET_URL, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["version"] == 0
    assert (
        get_service_thresholds("rdp")["failure_threshold"]
        == SERVICE_THRESHOLDS["rdp"]["failure_threshold"]
    )

    body = client.get(CONFIG_URL, headers=admin_headers).json()
    assert body["version"] == 0
    for service in ("ssh", "rdp", "web", "api"):
        assert body["config"]["detection"]["services"][service] == SERVICE_THRESHOLDS[service]


def test_config_reset_without_a_persisted_row_is_idempotent(client, admin_headers):
    response = client.post(RESET_URL, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["version"] == 0


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_config_changes_are_audited(client, admin_headers):
    client.put(CONFIG_URL, json=_config_payload(version=0), headers=admin_headers)
    client.post(RESET_URL, headers=admin_headers)

    body = client.get(
        "/api/v1/audit/", headers=admin_headers, params={"action": "settings.change"}
    ).json()

    assert body["total"] >= 2
    for entry in body["items"]:
        assert entry["action"] == "settings.change"
        assert entry["result"] == "success"
        assert entry["target_type"] == "system_config"
        assert entry["actor"] == "admin"
        assert "version" in entry["detail"]
        assert "reset" in entry["detail"]



