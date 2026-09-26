"""Grouped events API contract: ``GET /api/v1/events/groups``.

Covers server-side grouping by ``source_ip`` (the strongest correlation
identifier on ``AuthEvent`` — there is no session/event linkage in the
schema), aggregate counts, bounded per-group event lists, alert-derived
attack context, search/result filters, sorting, pagination and validation.
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

BASE = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)


def _iso(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat()


def _get(client: TestClient, query: str = "") -> dict:
    response = client.get(f"/api/v1/events/groups{query}")
    assert response.status_code == 200, response.text
    return response.json()


def _seed(client: TestClient, **overrides) -> dict:
    """Ingest one event through the public API (like production traffic)."""
    payload = {
        "timestamp": _iso(0),
        "source": "linux",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    response = client.post("/api/v1/events/", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Grouping and aggregates
# ---------------------------------------------------------------------------


def test_empty_database_returns_empty_page(client):
    body = _get(client)

    assert body["items"] == []
    assert body["total"] == 0


def test_events_are_grouped_by_source_ip(client):
    for minute in (0, 1):
        _seed(client, timestamp=_iso(minute), source_ip="10.0.0.1")
    _seed(client, timestamp=_iso(2), source_ip="10.0.0.2", result="success")

    body = _get(client)

    assert body["total"] == 2
    assert len(body["items"]) == 2
    keys = {group["group_key"] for group in body["items"]}
    assert keys == {"10.0.0.1", "10.0.0.2"}
    assert all(g["group_field"] == "source_ip" for g in body["items"])


def test_group_aggregates_count_success_and_failure(client):
    _seed(client, timestamp=_iso(0), source_ip="10.0.0.1", result="failure")
    _seed(client, timestamp=_iso(5), source_ip="10.0.0.1", result="failure")
    _seed(client, timestamp=_iso(10), source_ip="10.0.0.1", result="success")

    body = _get(client)
    group = body["items"][0]

    assert group["group_key"] == "10.0.0.1"
    assert group["event_count"] == 3
    assert group["success_count"] == 1
    assert group["failure_count"] == 2
    # first/last seen come from the aggregates, newest group first.
    assert group["first_seen"] < group["last_seen"]
    assert group["usernames"] == ["admin"]
    assert group["services"] == ["ssh"]


def test_group_users_and_services_are_deduplicated(client):
    _seed(client, timestamp=_iso(0), username="root")
    _seed(client, timestamp=_iso(1), username="root")
    _seed(client, timestamp=_iso(2), username="root", service="web", port=443)

    group = _get(client)["items"][0]

    assert group["usernames"] == ["root"]
    assert group["services"] == ["ssh", "web"]


def test_group_events_are_bounded_by_events_limit(client):
    for minute in range(5):
        _seed(client, timestamp=_iso(minute), source_ip="10.0.0.7")

    body = _get(client, "?events_limit=2")
    group = body["items"][0]

    # Aggregates cover all 5 events, but only the 2 most recent are shipped.
    assert group["event_count"] == 5
    assert len(group["events"]) == 2
    # Newest first within the group.
    assert group["events"][0]["timestamp"] >= group["events"][1]["timestamp"]
    assert body["total"] == 1


def test_group_usernames_stay_complete_beyond_events_limit(client):
    _seed(client, timestamp=_iso(0), source_ip="10.0.0.8", username="alpha")
    _seed(client, timestamp=_iso(1), source_ip="10.0.0.8", username="beta")
    _seed(client, timestamp=_iso(2), source_ip="10.0.0.8", username="gamma")

    group = _get(client, "?events_limit=1")["items"][0]

    # Aggregates and context come from ALL events, not the capped list.
    assert group["event_count"] == 3
    assert len(group["events"]) == 1
    assert group["usernames"] == ["alpha", "beta", "gamma"]


def test_group_attack_context_is_derived_from_alerts(client, alert_factory):
    _seed(client, timestamp=_iso(0), source_ip="10.0.0.9")
    alert_factory(
        alert_type="password_spray",
        source_ip="10.0.0.9",
        evidence={"session_id": 3},
    )

    group = _get(client)["items"][0]

    assert group["alert_types"] == ["password_spray"]
