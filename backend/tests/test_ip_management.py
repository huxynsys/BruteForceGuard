import pytest

from app.core.config import settings


def test_blocklist_requires_authorization_and_validates_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "ip_management_api_tokens", "test-token", raising=False)

    response = client.post(
        "/api/v1/blacklist/",
        json={
            "entry_type": "SINGLE",
            "list_type": "BLOCKLIST",
            "ip_address": "not-an-ip",
            "description": "Spammer",
            "added_by": "analyst",
        },
    )

    assert response.status_code == 401

    response = client.post(
        "/api/v1/blacklist/",
        json={
            "entry_type": "SINGLE",
            "list_type": "BLOCKLIST",
            "ip_address": "not-an-ip",
            "description": "Spammer",
            "added_by": "analyst",
        },
        headers={"Authorization": "Bearer test-token", "X-User-Id": "analyst"},
    )

    assert response.status_code == 422
    assert "Invalid IP address format" in response.text


def test_blocklist_and_whitelist_prevent_duplicate_entries(client, monkeypatch):
    monkeypatch.setattr(settings, "ip_management_api_tokens", "test-token", raising=False)
    headers = {"Authorization": "Bearer test-token", "X-User-Id": "analyst"}

    payload = {
        "entry_type": "SINGLE",
        "list_type": "BLOCKLIST",
        "ip_address": "203.0.113.10",
        "description": "Repeated attack",
        "added_by": "analyst",
    }

    first = client.post("/api/v1/blacklist/", json=payload, headers=headers)
    assert first.status_code == 201

    duplicate = client.post("/api/v1/blacklist/", json=payload, headers=headers)
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"].lower()

    whitelist = client.post(
        "/api/v1/blacklist/",
        json={
            **payload,
            "list_type": "WHITELIST",
            "ip_address": "203.0.113.10",
            "description": "Trusted internal scanner",
            "added_by": "analyst",
        },
        headers=headers,
    )
    assert whitelist.status_code == 201


def test_blocklist_list_and_delete_support_whitelist_entries(client, monkeypatch):
    monkeypatch.setattr(settings, "ip_management_api_tokens", "test-token", raising=False)
    headers = {"Authorization": "Bearer test-token", "X-User-Id": "analyst"}

    response = client.post(
        "/api/v1/blacklist/",
        json={
            "entry_type": "SINGLE",
            "list_type": "WHITELIST",
            "ip_address": "198.51.100.7",
            "description": "Trusted VPN",
            "added_by": "analyst",
        },
        headers=headers,
    )
    assert response.status_code == 201

    listed = client.get("/api/v1/blacklist/", params={"list_type": "WHITELIST"}, headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["list_type"] == "WHITELIST"

    entry_id = listed.json()[0]["id"]
    deleted = client.delete(f"/api/v1/blacklist/{entry_id}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json()["id"] == entry_id
