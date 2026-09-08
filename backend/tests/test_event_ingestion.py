"""
Event-ingestion tests (Phase 5, Sections 5.16 / 5.29).

These exercise the *HTTP* pipeline — request validation, persistence,
and retrieval — rather than calling Python methods directly.
"""

from datetime import datetime, timedelta


def _payload(**overrides):
    payload = {
        "timestamp": "2026-09-01T10:00:00Z",
        "source": "linux",
        "source_ip": "10.10.10.10",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    return payload


def test_valid_event_is_accepted_and_persisted(client):
    response = client.post("/api/v1/events/", json=_payload())
    assert response.status_code == 200, response.text

    body = response.json()
    assert body["source_ip"] == "10.10.10.10"
    assert body["username"] == "admin"
    assert body["result"] == "failure"
    assert body["service"] == "ssh"
    assert body["port"] == 22

    # Persisted and retrievable.
    events = client.get("/api/v1/events/").json()
    assert len(events) == 1
    assert events[0]["id"] == body["id"]

    event_id = body["id"]
    single = client.get(f"/api/v1/events/{event_id}")
    assert single.status_code == 200
    assert single.json()["id"] == event_id


def test_event_without_username_is_accepted(client):
    payload = _payload(username=None)
    assert client.post("/api/v1/events/", json=payload).status_code == 200


def test_invalid_result_is_rejected(client):
    payload = _payload(result="maybe")
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_invalid_timestamp_is_rejected(client):
    payload = _payload(timestamp="not-a-date")
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_invalid_ip_is_rejected(client):
    payload = _payload(source_ip="999.1.1.1")
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_missing_required_field_is_rejected(client):
    payload = _payload()
    del payload["source_ip"]
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_extra_fields_are_rejected(client):
    payload = _payload(not_a_real_field="x")
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_invalid_event_creates_no_partial_rows(client):
    """Section 5.29: a rejected request must not partially insert anything."""
    # Start empty.
    assert client.get("/api/v1/events/").json() == []

    bad = _payload(result="maybe")
    assert client.post("/api/v1/events/", json=bad).status_code == 422

    assert client.get("/api/v1/events/").json() == []


def test_invalid_port_is_rejected(client):
    payload = _payload(port=0)
    assert client.post("/api/v1/events/", json=payload).status_code == 422

    payload = _payload(port=70000)
    assert client.post("/api/v1/events/", json=payload).status_code == 422


def test_event_retrieval_returns_404_for_missing(client):
    assert client.get("/api/v1/events/999999").status_code == 404


def test_list_events_pagination(client):
    base = datetime(2026, 9, 1, 10, 0, 0)

    for i in range(5):
        ts = (base + timedelta(minutes=i)).isoformat() + "Z"
        client.post("/api/v1/events/", json=_payload(timestamp=ts))

    all_events = client.get("/api/v1/events/", params={"limit": 100}).json()
    assert len(all_events) == 5

    page = client.get("/api/v1/events/", params={"limit": 2, "skip": 0}).json()
    assert len(page) == 2


def test_success_event_does_not_create_bruteforce_alert(client):
    """Section 5.23: successful logins must not alert."""
    response = client.post(
        "/api/v1/events/",
        json=_payload(result="success"),
    )
    assert response.status_code == 200
    assert client.get("/api/v1/alerts/").json() == []
    assert client.get("/api/v1/attack-sessions/").json() == []