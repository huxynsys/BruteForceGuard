from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.core.detection_config import SERVICE_THRESHOLDS
from app.services.detection_engine import (
    DetectionEngine,
    RULES,
    normalize_event,
    service_family,
)


def make_event(**overrides):
    values = {
        "id": 17,
        "timestamp": datetime(2026, 9, 1, 10, 0, 0),
        "source_ip": "2001:0db8::1",
        "result": "failure",
        "username": "admin",
        "service": "ssh",
        "port": 22,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("event_values", "expected_family", "expected_rule"),
    [
        ({"service": "SSH", "port": None}, "ssh", "ssh_bruteforce"),
        ({"service": "rdp", "port": None}, "rdp", "rdp_bruteforce"),
        ({"service": "web", "port": None}, "web", "web_auth_bruteforce"),
        ({"service": None, "port": 443}, "web", "web_auth_bruteforce"),
    ],
)
def test_service_family_dispatches_independent_bruteforce_rules(
    event_values, expected_family, expected_rule
):
    normalized = normalize_event(make_event(**event_values))

    assert normalized is not None
    assert service_family(normalized) == expected_family

    alert = SimpleNamespace(
        alert_type="single_account_bruteforce",
        source_ip=normalized.source_ip,
        username=normalized.username,
        severity="high",
        confidence=65,
        description="Repeated failures for admin from one source.",
        evidence={"failure_count": 7, "window_seconds": 300},
    )
    detector = Mock(return_value=alert)
    service = SimpleNamespace(detect_single_account_bruteforce=detector)

    results = DetectionEngine(service).run(make_event(**event_values))

    assert len(results) == 1
    result = results[0]
    assert result.rule_id == expected_rule
    assert result.detection_type == "single_account_bruteforce"
    assert result.source_ip == "2001:db8::1"
    assert result.username == "admin"
    assert result.failed_attempts == 7
    assert result.time_window == 300
    assert result.threshold == SERVICE_THRESHOLDS[expected_family]["failure_threshold"]
    assert result.reason == alert.description
    assert result.confidence == 65
    assert result.alert is alert


def test_duplicate_alert_result_is_omitted():
    service = SimpleNamespace(
        detect_single_account_bruteforce=Mock(return_value=None)
    )

    results = DetectionEngine(service).run(make_event())

    assert results == []


@pytest.mark.parametrize(
    "event",
    [
        SimpleNamespace(timestamp=datetime.now(), result="failure", source_ip="bad-ip"),
        SimpleNamespace(timestamp="not-a-timestamp", result="failure", source_ip="192.0.2.1"),
        SimpleNamespace(timestamp=datetime.now(), result="unknown", source_ip="192.0.2.1"),
    ],
)
def test_malformed_event_is_skipped(event):
    service = SimpleNamespace()

    assert DetectionEngine(service).run(event) == []


def test_rule_registry_contains_supported_detection_families():
    rule_ids = {rule.rule_id for rule in RULES}

    assert {
        "ssh_bruteforce",
        "rdp_bruteforce",
        "web_auth_bruteforce",
        "distributed_bruteforce",
        "credential_stuffing",
    }.issubset(rule_ids)