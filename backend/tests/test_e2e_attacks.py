"""
API-level end-to-end tests for the remaining four detectors
(Phase 5, Sections 5.18 / 5.19 / 5.21 / 5.22).

Each test drives the real HTTP pipeline and then inspects both the
resulting alerts and the correlated attack sessions.
"""

from datetime import datetime, timedelta


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


# ---------------------------------------------------------------------
# 5.18 Password spraying E2E
# ---------------------------------------------------------------------
def test_password_spray_end_to_end(client):
    base = datetime.now()
    users = ["alice", "bob", "charlie", "david", "eve"]
    ip = "10.10.10.20"

    # 10 failures against 5 distinct accounts from one source IP.
    for i in range(10):
        _post(
            client,
            (base + timedelta(seconds=i * 10)).isoformat() + "Z",
            source_ip=ip,
            username=users[i % len(users)],
        )

    alert_types = {
        a["alert_type"] for a in client.get("/api/v1/alerts/").json()
    }
    assert "password_spraying" in alert_types

    sessions = client.get("/api/v1/attack-sessions/").json()
    spray_sessions = [
        s for s in sessions if s["session_type"] == "password_spray"
    ]
    assert len(spray_sessions) == 1

    session = spray_sessions[0]
    assert ip in session["source_ips"]
    # The session must have accumulated the affected accounts.
    assert set(users).issubset(set(session["usernames"]))
    assert session["status"] == "active"


# ---------------------------------------------------------------------
# 5.19 Distributed brute force E2E
# ---------------------------------------------------------------------
def test_distributed_bruteforce_end_to_end(client):
    base = datetime.now()
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    # 12 failures against one account from three source IPs.
    for i in range(12):
        _post(
            client,
            (base + timedelta(seconds=i * 10)).isoformat() + "Z",
            source_ip=ips[i % len(ips)],
            username="administrator",
        )

    alert_types = {
        a["alert_type"] for a in client.get("/api/v1/alerts/").json()
    }
    assert "distributed_bruteforce" in alert_types

    # The single-account detector fires first (5 failures from one IP);
    # the distributed detector then joins the SAME session because both
    # share the `administrator`/`ssh` correlation dimensions.  What
    # matters is that ONE session represents the distributed attack and
    # accumulates ALL of its source IPs (Section 5.19).
    sessions = client.get("/api/v1/attack-sessions/").json()
    admin_sessions = [
        s for s in sessions
        if s["usernames"] and "administrator" in s["usernames"]
    ]
    assert len(admin_sessions) == 1

    session = admin_sessions[0]
    assert set(ips).issubset(set(session["source_ips"]))
    assert "distributed" in session["detection_types"]
    assert session["status"] == "active"


# ---------------------------------------------------------------------
# 5.21 Credential stuffing E2E
# ---------------------------------------------------------------------
def test_credential_stuffing_end_to_end(client):
    base = datetime.now()
    ip = "10.0.0.70"
    users = [f"user{i:02d}" for i in range(10)]

    # 20 failures against 10 distinct accounts from one source IP.
    for i in range(20):
        _post(
            client,
            (base + timedelta(seconds=i * 5)).isoformat() + "Z",
            source_ip=ip,
            username=users[i % len(users)],
        )

    alerts = client.get("/api/v1/alerts/").json()
    stuffing_alerts = [
        a for a in alerts if a["alert_type"] == "credential_stuffing"
    ]
    assert len(stuffing_alerts) == 1

    alert = stuffing_alerts[0]
    evidence = alert["evidence"]
    assert evidence["failure_count"] == 20
    assert evidence["distinct_users"] == 10
    assert "usernames" in evidence and len(evidence["usernames"]) == 10
    assert evidence["source_ip"] == ip
    assert evidence["services"] == ["ssh"]

    # Credential stuffing and password spraying share the correlation
    # key (source_ip, service) — both signals land in the SAME session.
    sessions = client.get("/api/v1/attack-sessions/").json()
    ip_sessions = [
        s for s in sessions if s["source_ips"] and ip in s["source_ips"]
    ]
    assert len(ip_sessions) == 1


# ---------------------------------------------------------------------
# 5.22 Low-and-slow E2E
# ---------------------------------------------------------------------
def test_low_and_slow_end_to_end(client):
    base = datetime.now() - timedelta(minutes=45)
    ip = "10.10.10.80"

    # 10 failures spread across the (1 hour) window, one every 5 minutes.
    for i in range(10):
        _post(
            client,
            (base + timedelta(minutes=5 * i)).isoformat() + "Z",
            source_ip=ip,
            username="slowuser",
        )

    alert_types = {
        a["alert_type"] for a in client.get("/api/v1/alerts/").json()
    }
    assert "low_and_slow" in alert_types

    low_slow_alerts = [
        a for a in client.get("/api/v1/alerts/").json()
        if a["alert_type"] == "low_and_slow"
    ]
    assert low_slow_alerts[0]["evidence"]["active_intervals"] >= 5

    # single-account cannot co-fire here: its 300 s window never contains
    # 5 failures when they are spaced 5 minutes apart.  The low-and-slow
    # signal alone owns the (ip + user + service) session.
    sessions = client.get("/api/v1/attack-sessions/").json()
    related = [
        s for s in sessions
        if s["source_ips"] and ip in s["source_ips"]
    ]
    assert len(related) == 1
    types = related[0]["detection_types"]
    assert "low_and_slow" in types