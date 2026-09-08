from datetime import datetime, timedelta


def _post_failure(
    client,
    timestamp,
    *,
    source_ip,
    username,
    service="ssh",
):
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


def _trigger_session(client, *, source_ip, username, service="ssh"):
    """Five failures from one source -> single_account session."""
    start = datetime.now()

    for i in range(5):
        _post_failure(
            client,
            (start + timedelta(seconds=i * 5)).isoformat() + "Z",
            source_ip=source_ip,
            username=username,
            service=service,
        )


def test_list_attack_sessions(client):
    _trigger_session(client, source_ip="192.168.50.10", username="admin")

    response = client.get("/api/v1/attack-sessions/")
    assert response.status_code == 200

    sessions = response.json()
    assert len(sessions) == 1

    session = sessions[0]
    assert session["session_type"] == "single_account"
    assert session["status"] == "active"
    assert session["severity"] == "high"
    assert session["event_count"] == 1
    assert session["source_ips"] == ["192.168.50.10"]
    assert session["usernames"] == ["admin"]
    assert session["services"] == ["ssh"]
    assert session["detection_types"] == ["single_account"]
    assert session["started_at"] == session["last_seen_at"]


def test_get_attack_session_by_id(client):
    _trigger_session(client, source_ip="192.168.50.10", username="admin")

    session_id = client.get("/api/v1/attack-sessions/").json()[0]["id"]

    response = client.get(f"/api/v1/attack-sessions/{session_id}")
    assert response.status_code == 200
    assert response.json()["id"] == session_id
    assert response.json()["status"] == "active"


def test_close_attack_session(client):
    _trigger_session(client, source_ip="192.168.50.11", username="admin")

    session_id = client.get("/api/v1/attack-sessions/").json()[0]["id"]

    # Session starts active.
    assert client.get(f"/api/v1/attack-sessions/{session_id}").json()["status"] == "active"

    # Close it.
    response = client.post(f"/api/v1/attack-sessions/{session_id}/close")
    assert response.status_code == 200
    assert response.json()["status"] == "closed"

    # It stays closed.
    assert client.get(f"/api/v1/attack-sessions/{session_id}").json()["status"] == "closed"


def test_active_session_stats(client):
    _trigger_session(client, source_ip="192.168.50.12", username="bob")
    _trigger_session(client, source_ip="192.168.50.13", username="carol")

    stats = client.get("/api/v1/attack-sessions/stats/active").json()

    assert stats["active_sessions"] == 2
    assert stats["total_events"] == 2
    assert stats["unique_source_ips"] == 2
    assert stats["unique_usernames"] == 2


def test_active_stats_reflect_closed_sessions(client):
    _trigger_session(client, source_ip="192.168.50.14", username="dave")

    session_id = client.get("/api/v1/attack-sessions/").json()[0]["id"]
    client.post(f"/api/v1/attack-sessions/{session_id}/close")

    stats = client.get("/api/v1/attack-sessions/stats/active").json()
    assert stats["active_sessions"] == 0
    assert stats["total_events"] == 0


def test_missing_session_returns_404(client):
    assert client.get("/api/v1/attack-sessions/999999").status_code == 404

    response = client.post("/api/v1/attack-sessions/999999/close")
    assert response.status_code == 404