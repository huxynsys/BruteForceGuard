"""Phase 7 - intelligence API endpoints (7.16, 7.30-7.33).

7.30  Intelligence API exists.
7.31  Reputation API exists.
7.32  MITRE API exists.
7.33  Indicator operations are validated.
"""

import pytest
from fastapi.testclient import TestClient

from app.intelligence.schemas import ThreatIndicatorCreate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def sample_indicator(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": "203.0.113.50",
            "indicator_type": "ipv4",
            "confidence": 90,
            "threat_type": "brute_force",
            "source": "test",
            "tags": ["scanner"],
            "active": True,
        },
    )
    assert response.status_code == 201
    return response.json()


# ---------------------------------------------------------------------------
# 7.30 Intelligence API exists
# ---------------------------------------------------------------------------
def test_lookup_ip_endpoint(client: TestClient, sample_indicator: dict):
    response = client.get("/api/v1/intelligence/ip/203.0.113.50")
    assert response.status_code == 200
    data = response.json()
    assert data["known"] is True
    assert data["confidence"] == 90
    assert data["indicator_type"] == "ipv4"


def test_lookup_ip_unknown(client: TestClient):
    response = client.get("/api/v1/intelligence/ip/198.51.100.1")
    assert response.status_code == 200
    data = response.json()
    assert data["known"] is False


# ---------------------------------------------------------------------------
# 7.31 Reputation API exists
# ---------------------------------------------------------------------------
def test_reputation_endpoint(client: TestClient):
    response = client.get("/api/v1/intelligence/reputation/10.0.0.1")
    assert response.status_code == 200
    data = response.json()
    assert "internal_reputation_score" in data
    assert "internal_reputation_level" in data
    assert data["source_ip"] == "10.0.0.1"


def test_reputation_new_ip(client: TestClient):
    response = client.get("/api/v1/intelligence/reputation/192.168.1.1")
    assert response.status_code == 200
    data = response.json()
    assert data["internal_reputation_score"] == 0
    assert data["internal_reputation_level"] == "unknown"


# ---------------------------------------------------------------------------
# 7.32 MITRE API exists
# ---------------------------------------------------------------------------
def test_mitre_endpoint(client: TestClient):
    response = client.get("/api/v1/intelligence/mitre/T1110.001")
    assert response.status_code == 200
    data = response.json()
    assert data["technique_id"] == "T1110.001"
    assert data["technique_name"] == "Password Guessing"
    assert data["tactic"] == "Credential Access"
    assert data["is_mapped"] is True


def test_mitre_by_detection_type(client: TestClient):
    response = client.get("/api/v1/intelligence/mitre/single_account_bruteforce")
    assert response.status_code == 200
    data = response.json()
    assert data["technique_id"] == "T1110.001"
    assert data["is_mapped"] is True




# ---------------------------------------------------------------------------
# 7.33 Indicator operations are validated
# ---------------------------------------------------------------------------
def test_create_indicator(client: TestClient):
    response = client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": "10.0.0.99",
            "indicator_type": "ipv4",
            "confidence": 75,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["indicator"] == "10.0.0.99"
    assert data["indicator_type"] == "ipv4"
    assert data["confidence"] == 75
    assert data["active"] is True


def test_create_indicator_invalid_type(client: TestClient):
    response = client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": "test",
            "indicator_type": "invalid",
            "confidence": 50,
        },
    )
    assert response.status_code == 422


def test_create_indicator_confidence_out_of_range(client: TestClient):
    response = client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": "test",
            "indicator_type": "ipv4",
            "confidence": 150,
        },
    )
    assert response.status_code == 422


def test_list_indicators(client: TestClient, sample_indicator: dict):
    response = client.get("/api/v1/intelligence/indicators")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1


def test_list_indicators_filter_type(client: TestClient, sample_indicator: dict):
    response = client.get("/api/v1/intelligence/indicators?indicator_type=ipv4")
    assert response.status_code == 200
    data = response.json()
    assert all(item["indicator_type"] == "ipv4" for item in data)


def test_list_indicators_active_only(client: TestClient, sample_indicator: dict):
    response = client.get("/api/v1/intelligence/indicators?active_only=true")
    assert response.status_code == 200
    data = response.json()
    assert all(item["active"] is True for item in data)


def test_delete_indicator(client: TestClient, sample_indicator: dict):
    indicator_id = sample_indicator["id"]
    response = client.delete(f"/api/v1/intelligence/indicators/{indicator_id}")
    assert response.status_code == 204


def test_delete_nonexistent_indicator(client: TestClient):
    response = client.delete("/api/v1/intelligence/indicators/9999")
    assert response.status_code == 404
def test_mitre_unknown_404(client: TestClient):
    response = client.get("/api/v1/intelligence/mitre/unknown_technique")
    assert response.status_code == 404


def test_list_mitre_mappings(client: TestClient):
    response = client.get("/api/v1/intelligence/mitre")
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert any(entry["technique_id"] == "T1110.001" for entry in data)