"""Detection-rule context returned with an alert.

The alert-details panel explains *why* a rule triggered, so the rule parameters
(threshold, window, human-readable requirement) must come from the same
configuration the detectors run with rather than a browser-side copy that could
drift.  These tests pin the mapping from ``alerts.alert_type`` +
``alerts.service`` to that context and the fact that the existing alert
endpoints return it (no new endpoint was added).
"""

from app.core.detection_config import (
    DEFAULT_THRESHOLDS,
    SERVICE_THRESHOLDS,
    get_detection_rule,
)

# Every alert type the detection engine can persist.
ENGINE_ALERT_TYPES = (
    "single_account_bruteforce",
    "password_spraying",
    "distributed_bruteforce",
    "failed_then_success",
    "credential_stuffing",
    "low_and_slow",
)

RULE_LABELS = {
    "single_account_bruteforce": "Single Account Brute Force",
    "password_spraying": "Password Spray",
    "distributed_bruteforce": "Distributed Brute Force",
    "failed_then_success": "Failed -> Success",
    "credential_stuffing": "Credential Stuffing",
    "low_and_slow": "Low & Slow Attack",
}


# ---------------------------------------------------------------------------
# Rule context (configuration)
# ---------------------------------------------------------------------------


def test_every_engine_alert_type_has_a_complete_rule():
    for alert_type in ENGINE_ALERT_TYPES:
        rule = get_detection_rule(alert_type, "ssh")

        assert rule is not None, alert_type
        assert rule["alert_type"] == alert_type
        assert rule["label"] == RULE_LABELS[alert_type]
        assert rule["threshold"] > 0
        assert rule["window_seconds"] > 0
        assert rule["threshold_label"]
        # The requirement sentence must state the threshold it enforces.
        assert str(rule["threshold"]) in rule["requirement"]


def test_single_account_rule_follows_the_service_thresholds():
    for service in ("ssh", "rdp", "web", "api"):
        rule = get_detection_rule("single_account_bruteforce", service)
        thresholds = SERVICE_THRESHOLDS[service]

        assert rule is not None
        assert rule["threshold"] == thresholds["failure_threshold"]
        assert rule["window_seconds"] == thresholds["window_seconds"]


def test_unknown_or_missing_service_falls_back_to_the_defaults():
    for service in (None, "unknown-service"):
        rule = get_detection_rule("single_account_bruteforce", service)

        assert rule is not None
        assert rule["threshold"] == DEFAULT_THRESHOLDS["failure_threshold"]
        assert rule["window_seconds"] == DEFAULT_THRESHOLDS["window_seconds"]


def test_spray_rule_scales_with_the_service():
    ssh = get_detection_rule("password_spraying", "ssh")
    web = get_detection_rule("password_spraying", "web")

    assert ssh is not None and web is not None
    # password_spray runs with failure_threshold * 2 failed attempts.
    assert ssh["threshold"] == SERVICE_THRESHOLDS["ssh"]["failure_threshold"] * 2
    assert web["threshold"] == SERVICE_THRESHOLDS["web"]["failure_threshold"] * 2
    assert (
        ssh["secondary_threshold"]
        == SERVICE_THRESHOLDS["ssh"]["password_spray_users"]
    )
    assert ssh["secondary_label"] == "Distinct accounts targeted"


def test_distributed_rule_reports_the_distinct_source_ips():
    rule = get_detection_rule("distributed_bruteforce", "ssh")

    assert rule is not None
    assert rule["secondary_label"] == "Distinct source IPs"
    assert rule["secondary_threshold"] == SERVICE_THRESHOLDS["ssh"]["distributed_ips"]


def test_credential_stuffing_rule_uses_its_own_thresholds():
    rule = get_detection_rule("credential_stuffing", "rdp")

    assert rule is not None
    assert (
        rule["threshold"]
        == SERVICE_THRESHOLDS["rdp"]["credential_stuffing_failures"]
    )
    assert (
        rule["secondary_threshold"]
        == SERVICE_THRESHOLDS["rdp"]["credential_stuffing_users"]
    )


def test_fixed_rules_ignore_the_service():
    """failed_then_success and low_and_slow are not service-tunable."""
    for service in (None, "ssh", "api"):
        failed = get_detection_rule("failed_then_success", service)
        slow = get_detection_rule("low_and_slow", service)

        assert failed is not None and slow is not None
        assert failed["threshold"] == 3
        assert failed["window_seconds"] == 300
        assert slow["threshold"] == 10
        assert slow["window_seconds"] == 3600
        assert slow["secondary_label"] == "Active time intervals"
        assert slow["secondary_threshold"] == 5


def test_unknown_alert_type_has_no_rule():
    """Unknown/legacy types must return None, never a fabricated threshold."""
    assert get_detection_rule("legacy_custom_rule", "ssh") is None
    assert get_detection_rule("", None) is None


# ---------------------------------------------------------------------------
# Alert endpoints (same endpoints, richer response)
# ---------------------------------------------------------------------------


def test_alert_detail_returns_the_detection_rule(client, alert_factory):
    alert = alert_factory(alert_type="single_account_bruteforce", service="ssh")

    body = client.get(f"/api/v1/alerts/{alert.id}").json()

    rule = body["detection_rule"]
    assert rule["alert_type"] == "single_account_bruteforce"
    assert rule["threshold"] == SERVICE_THRESHOLDS["ssh"]["failure_threshold"]
    assert rule["window_seconds"] == SERVICE_THRESHOLDS["ssh"]["window_seconds"]


def test_rule_threshold_follows_the_alert_service(client, alert_factory):
    alert = alert_factory(alert_type="single_account_bruteforce", service="api")

    rule = client.get(f"/api/v1/alerts/{alert.id}").json()["detection_rule"]

    assert rule["threshold"] == SERVICE_THRESHOLDS["api"]["failure_threshold"]


def test_alert_list_returns_the_detection_rule(client, alert_factory):
    alert_factory(alert_type="low_and_slow", service="ssh")

    body = client.get("/api/v1/alerts/").json()

    assert body[0]["detection_rule"]["threshold"] == 10


def test_triage_transition_keeps_the_detection_rule(client, alert_factory):
    alert = alert_factory(status="open")

    body = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "false_positive"},
    ).json()

    assert body["status"] == "false_positive"
    assert body["detection_rule"]["alert_type"] == "single_account_bruteforce"


def test_unknown_alert_type_serializes_as_null(client, alert_factory):
    alert = alert_factory(alert_type="legacy_custom_rule")

    body = client.get(f"/api/v1/alerts/{alert.id}").json()

    assert body["alert_type"] == "legacy_custom_rule"
    assert body["detection_rule"] is None
