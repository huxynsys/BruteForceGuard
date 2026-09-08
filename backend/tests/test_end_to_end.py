from datetime import datetime, timedelta


def _post_event(
    client,
    timestamp,
    *,
    result="failure",
    source_ip="192.168.50.10",
    username="admin",
    service="ssh",
):
    payload = {
        "timestamp": timestamp,
        "source": "linux",
        "source_ip": source_ip,
        "username": username,
        "result": result,
        "service": service,
        "port": 22,
    }
    response = client.post("/api/v1/events/", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_full_pipeline_end_to_end(client):
    """
    POST /events
        -> event saved
        -> detection triggered
        -> alert created
        -> session created
        -> deduplication works
        -> failed-then-success adds a second detection signal
        -> API can retrieve everything
    """
    base = datetime.now()

    # ---- 5 failures: detection -> alert -> session ----
    for i in range(5):
        _post_event(client, (base + timedelta(seconds=i * 5)).isoformat() + "Z")

    events = client.get("/api/v1/events/").json()
    assert len(events) == 5

    alerts = client.get("/api/v1/alerts/").json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "single_account_bruteforce"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["status"] == "open"

    sessions = client.get("/api/v1/attack-sessions/").json()
    assert len(sessions) == 1
    session_id = sessions[0]["id"]
    assert sessions[0]["session_type"] == "single_account"
    assert sessions[0]["status"] == "active"
    assert sessions[0]["event_count"] == 1

    # ---- 6th failure: event saved, alert DEDUPLICATED, session unchanged ----
    _post_event(client, (base + timedelta(seconds=30)).isoformat() + "Z")

    assert len(client.get("/api/v1/events/").json()) == 6

    alerts = client.get("/api/v1/alerts/").json()
    assert len(alerts) == 1

    sessions = client.get("/api/v1/attack-sessions/").json()
    assert len(sessions) == 1
    assert sessions[0]["id"] == session_id

    # ---- success after failures -> failed_then_success (2nd detection) ----
    _post_event(
        client,
        (base + timedelta(seconds=40)).isoformat() + "Z",
        result="success",
    )

    assert len(client.get("/api/v1/events/").json()) == 7

    alert_types = {
        a["alert_type"] for a in client.get("/api/v1/alerts/").json()
    }
    assert "single_account_bruteforce" in alert_types
    assert "failed_then_success" in alert_types

    # Section 5.9: both detection signals describe ONE attack, so they
    # live in the SAME attack session and the session records both
    # detection types.
    sessions = client.get("/api/v1/attack-sessions/").json()
    assert len(sessions) == 1
    assert sessions[0]["id"] == session_id
    assert sessions[0]["session_type"] == "single_account"
    assert "single_account" in sessions[0]["detection_types"]
    assert "failed_success" in sessions[0]["detection_types"]
    assert sessions[0]["event_count"] == 2

    # ---- the session still exists and can be retrieved by ID ----
    assert client.get(f"/api/v1/attack-sessions/{session_id}").status_code == 200

    # ---- active stats reflect the updated session ----
    stats = client.get("/api/v1/attack-sessions/stats/active").json()
    assert stats["active_sessions"] == 1
    assert stats["total_events"] == 2
    assert stats["unique_source_ips"] == 1
    assert stats["unique_usernames"] == 1