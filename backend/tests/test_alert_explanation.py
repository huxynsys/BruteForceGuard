"""Alert explainability: structured fields + generated human-readable text.

Every alert must carry enough structured context for an analyst to understand
why it exists (detection type, rule name, threshold, observed value, time
window, failure/success counts, target, reason, detection timestamp), and the
human-readable sentence must be *generated* from those fields - never
hard-coded.  These tests pin both properties, plus the safety rule that the
explanation never leaks non-engine data (credentials, raw payloads, internal
errors).
"""

import json

from app.core.detection_config import get_detection_rule
from app.services.alert_explanation import build_alert_explanation

# ---------------------------------------------------------------------------
# Structured fields
# ---------------------------------------------------------------------------


def test_detail_returns_every_structured_field(client, alert_factory):
    alert = alert_factory(
        alert_type="single_account_bruteforce",
        service="ssh",
        source_ip="192.168.1.50",
        username="admin",
        evidence={"failure_count": 37, "window_seconds": 300},
    )

    explanation = client.get(f"/api/v1/alerts/{alert.id}").json()["explanation"]

    assert explanation["detection_type"] == "single_account_bruteforce"
    assert explanation["rule_name"] == "Single Account Brute Force"
    assert explanation["threshold"] == 5
    assert (
        explanation["threshold_label"]
        == "Failed attempts against the same account"
    )
    assert explanation["observed_value"] == 37
    assert explanation["window_seconds"] == 300
    assert explanation["failure_count"] == 37
    assert explanation["success_count"] == 0
    assert explanation["source_ip"] == "192.168.1.50"
    assert explanation["username"] == "admin"
    assert explanation["service"] == "ssh"
    assert explanation["reason"]
    assert explanation["detected_at"]
    assert explanation["text"]


def test_list_and_triage_responses_carry_the_explanation(
    client, alert_factory, analyst_headers
):
    alert = alert_factory(evidence={"failure_count": 12, "window_seconds": 300})

    listed = client.get("/api/v1/alerts/").json()
    patched = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "acknowledged"},
        headers=analyst_headers,
    ).json()

    assert listed[0]["explanation"]["failure_count"] == 12
    assert patched["explanation"]["failure_count"] == 12
    assert patched["explanation"]["text"]


# ---------------------------------------------------------------------------
# Generated (never hard-coded) human-readable sentence
# ---------------------------------------------------------------------------


def test_text_is_generated_from_the_structured_fields(client, alert_factory):
    alert = alert_factory(
        alert_type="single_account_bruteforce",
        service="ssh",
        source_ip="192.168.1.50",
        username="admin",
        evidence={"failure_count": 37, "window_seconds": 300},
    )

    text = client.get(f"/api/v1/alerts/{alert.id}").json()["explanation"]["text"]

    assert text == (
        "37 failed SSH authentication attempts from 192.168.1.50 "
        "against user admin within 5 minutes "
        "exceeded the configured threshold of 5."
    )


def test_text_changes_when_the_structured_fields_change(alert_factory):
    rule = get_detection_rule("single_account_bruteforce", "ssh")

    small = alert_factory(
        source_ip="10.0.0.1",
        evidence={"failure_count": 7, "window_seconds": 300},
    )
    large = alert_factory(
        source_ip="10.0.0.2",
        evidence={"failure_count": 55, "window_seconds": 600},
    )

    small_text = build_alert_explanation(small, rule).text
    large_text = build_alert_explanation(large, rule).text

    # The wording is derived from the numbers, so different inputs must give
    # different sentences - a fixed template would not vary like this.
    assert small_text != large_text
    assert "7 failed" in small_text
    assert "10 minutes" in large_text
    assert "55 failed" in large_text


def test_text_adapts_to_alert_shapes_without_a_source_ip_or_user(alert_factory):
    distributed = alert_factory(
        source_ip=None,
        username="admin",
        evidence={
            "failure_count": 12,
            "window_seconds": 300,
            "distinct_source_ips": 4,
        },
    )
    spray = alert_factory(
        username=None,
        evidence={
            "failure_count": 20,
            "window_seconds": 600,
            "distinct_users": 6,
        },
    )

    distributed_text = build_alert_explanation(
        distributed, get_detection_rule("distributed_bruteforce", "ssh")
    ).text
    spray_text = build_alert_explanation(
        spray, get_detection_rule("password_spraying", "ssh")
    ).text

    assert "from 4 distinct source IPs" in distributed_text
    assert "across 6 distinct accounts" in spray_text
    # A spray has no single target user, so no username clause is invented.
    assert "against user" not in spray_text
    # Long windows are humanized (600 s -> 10 minutes).
    assert "within 10 minutes" in spray_text


def test_successful_login_is_counted_and_explained(alert_factory):
    alert = alert_factory(
        alert_type="failed_then_success",
        source_ip="10.0.0.8",
        username="administrator",
        evidence={
            "failed_attempts": 5,
            "successful_login": True,
            "window_seconds": 300,
        },
    )
    rule = get_detection_rule("failed_then_success", "ssh")

    explanation = build_alert_explanation(alert, rule)

    # failed_then_success records its count as `failed_attempts`.
    assert explanation.failure_count == 5
    assert explanation.observed_value == 5
    assert explanation.success_count == 1
    assert "followed by a successful login" in explanation.text
    assert explanation.reason == "5 failures exceeded the threshold of 3."


def test_recorded_window_wins_over_the_current_configuration(alert_factory):
    alert = alert_factory(evidence={"failure_count": 40, "window_seconds": 600})

    # The current ssh rule window is 300 s; the evidence holds the window the
    # detector actually used and must be reported instead.
    explanation = build_alert_explanation(
        alert, get_detection_rule("single_account_bruteforce", "ssh")
    )

    assert explanation.window_seconds == 600
    assert "within 10 minutes" in explanation.text


def test_low_and_slow_window_is_humanized_as_an_hour(alert_factory):
    alert = alert_factory(
        alert_type="low_and_slow",
        evidence={"failure_count": 12, "window_seconds": 3600},
    )

    text = build_alert_explanation(
        alert, get_detection_rule("low_and_slow", "ssh")
    ).text

    assert "within 1 hour" in text
    assert "within 60 minutes" not in text


# ---------------------------------------------------------------------------
# Unknown alert types still get an explanation (without fabricated numbers)
# ---------------------------------------------------------------------------


def test_unknown_alert_type_explains_itself_without_fabricating_a_rule(
    client, alert_factory
):
    alert = alert_factory(
        alert_type="legacy_custom_rule",
        evidence={"failure_count": 9},
    )

    body = client.get(f"/api/v1/alerts/{alert.id}").json()
    explanation = body["explanation"]

    assert body["detection_rule"] is None
    assert explanation["detection_type"] == "legacy_custom_rule"
    assert explanation["rule_name"] is None
    assert explanation["threshold"] is None
    assert explanation["failure_count"] == 9
    assert "9 failed" in explanation["text"]
    assert explanation["reason"] == (
        "Rule parameters unavailable; recorded evidence only."
    )
    # No threshold was invented for an unknown rule.
    assert "configured threshold" not in explanation["text"]


def test_alert_without_recorded_counts_still_explains_itself(alert_factory):
    alert = alert_factory(evidence={})

    explanation = build_alert_explanation(
        alert, get_detection_rule("single_account_bruteforce", "ssh")
    )

    assert explanation.failure_count is None
    assert explanation.observed_value is None
    assert "Single Account Brute Force detection" in explanation.text
    assert "configured threshold of 5" in explanation.text


# ---------------------------------------------------------------------------
# Safety: no credentials, payloads or internal details in the explanation
# ---------------------------------------------------------------------------


def test_explanation_never_leaks_non_engine_evidence(client, alert_factory):
    alert = alert_factory(
        evidence={
            "failure_count": 12,
            "window_seconds": 300,
            # Collector-supplied / sensitive keys that must never surface.
            "password": "hunter2",
            "token": "tok_secret_123",
            "raw_event": "Failed password for admin from 10.0.0.1 port 22",
            "stack_trace": "Traceback (most recent call last): ...",
        },
    )

    explanation = client.get(f"/api/v1/alerts/{alert.id}").json()["explanation"]
    serialized = json.dumps(explanation)

    assert "hunter2" not in serialized
    assert "tok_secret_123" not in serialized
    assert "Failed password" not in serialized
    assert "Traceback" not in serialized
    assert "port 22" not in serialized


