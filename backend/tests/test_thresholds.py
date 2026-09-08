"""
Service-specific threshold tests (Phase 5, Section 5.24).

The event endpoint resolves thresholds through
``get_service_thresholds(service)``.  These tests verify that each
supported service maps to the right thresholds and that the detectors
honour them through the real HTTP pipeline.
"""

from datetime import datetime, timedelta

from app.core.detection_config import (
    DEFAULT_THRESHOLDS,
    SERVICE_THRESHOLDS,
    get_service_thresholds,
)


def test_known_service_thresholds_are_defined():
    for service in ("ssh", "rdp", "web", "api"):
        assert service in SERVICE_THRESHOLDS
        thresholds = SERVICE_THRESHOLDS[service]
        assert thresholds["failure_threshold"] > 0
        assert thresholds["window_seconds"] > 0
        assert thresholds["password_spray_users"] > 0
        assert thresholds["distributed_ips"] > 0
        assert thresholds["credential_stuffing_users"] > 0
        assert thresholds["credential_stuffing_failures"] > 0


def test_get_service_thresholds_returns_matching_config():
    assert get_service_thresholds("ssh") == SERVICE_THRESHOLDS["ssh"]
    assert get_service_thresholds("rdp") == SERVICE_THRESHOLDS["rdp"]
    assert get_service_thresholds("web") == SERVICE_THRESHOLDS["web"]
    assert get_service_thresholds("api") == SERVICE_THRESHOLDS["api"]


def test_unknown_or_missing_service_uses_defaults():
    assert get_service_thresholds(None) == DEFAULT_THRESHOLDS
    assert get_service_thresholds("unknown-service") == DEFAULT_THRESHOLDS


def _post(client, timestamp, *, source_ip, username, service="ssh"):
    payload = {
        "timestamp": timestamp,
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


def test_ssh_threshold_honored_over_http(client):
    """
    ssh failure_threshold is 5, so 4 failures must NOT alert
    (negative case from Section 5.23).
    """
    base = datetime.now()

    for i in range(4):
        _post(
            client,
            (base + timedelta(seconds=i)).isoformat() + "Z",
            source_ip="10.0.0.1",
            username="admin",
            service="ssh",
        )

    assert client.get("/api/v1/alerts/").json() == []

    # The fifth failure crosses the threshold.
    _post(
        client,
        (base + timedelta(seconds=5)).isoformat() + "Z",
        source_ip="10.0.0.1",
        username="admin",
        service="ssh",
    )

    alerts = client.get("/api/v1/alerts/").json()
    assert [a["alert_type"] for a in alerts] == [
        "single_account_bruteforce"
    ]


def test_web_threshold_is_higher_than_ssh(client):
    """
    web failure_threshold is 10, so 9 failures from one account must
    NOT alert where the same volume on ssh would have.
    """
    base = datetime.now()

    for i in range(9):
        _post(
            client,
            (base + timedelta(seconds=i)).isoformat() + "Z",
            source_ip="10.0.0.2",
            username="webadmin",
            service="web",
        )

    assert client.get("/api/v1/alerts/").json() == []

    # 10th failure crosses the web threshold.
    _post(
        client,
        (base + timedelta(seconds=10)).isoformat() + "Z",
        source_ip="10.0.0.2",
        username="webadmin",
        service="web",
    )

    alerts = client.get("/api/v1/alerts/").json()
    assert [a["alert_type"] for a in alerts] == [
        "single_account_bruteforce"
    ]


def test_api_threshold_requires_more_evidence(client):
    """
    api failure_threshold is 20, so 15 failures must NOT alert.
    """
    base = datetime.now()

    for i in range(15):
        _post(
            client,
            (base + timedelta(seconds=i)).isoformat() + "Z",
            source_ip="10.0.0.3",
            username="apiuser",
            service="api",
        )

    assert client.get("/api/v1/alerts/").json() == []