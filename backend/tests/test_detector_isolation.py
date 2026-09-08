"""
Detector-isolation tests (Phase 5, Section 5.28).

A failing detector must never prevent event ingestion.  The endpoint
wraps every detector in try/except specifically so that one broken
detector cannot take down event processing.
"""

from datetime import datetime, timedelta


def _post(client, timestamp, **overrides):
    payload = {
        "timestamp": timestamp,
        "source": "linux",
        "source_ip": "10.10.10.10",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    response = client.post("/api/v1/events/", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_broken_detector_does_not_block_ingestion(client, monkeypatch):
    """A detector that raises must not prevent the event being saved."""
    import app.services.detection_service as ds

    def explode(self, event, **kwargs):
        raise RuntimeError("simulated detector failure")

    monkeypatch.setattr(
        ds.DetectionService,
        "detect_low_and_slow",
        explode,
    )

    base = datetime.now()

    # Five failures — single-account detection must still fire normally.
    for i in range(5):
        _post(
            client,
            (base + timedelta(seconds=i * 5)).isoformat() + "Z",
        )

    events = client.get("/api/v1/events/").json()
    assert len(events) == 5

    # The healthy detectors still produced their alert and session.
    alerts = client.get("/api/v1/alerts/").json()
    assert [a["alert_type"] for a in alerts] == ["single_account_bruteforce"]

    sessions = client.get("/api/v1/attack-sessions/").json()
    assert len(sessions) == 1
    assert sessions[0]["session_type"] == "single_account"


def test_every_broken_detector_still_ingests(client, monkeypatch):
    """Even if EVERY detector fails, the event itself is still saved."""
    import app.services.detection_service as ds

    def explode(self, event, **kwargs):
        raise RuntimeError("simulated detector failure")

    for method in [
        "detect_single_account_bruteforce",
        "detect_password_spraying",
        "detect_distributed_bruteforce",
        "detect_failed_then_success",
        "detect_credential_stuffing",
        "detect_low_and_slow",
    ]:
        monkeypatch.setattr(ds.DetectionService, method, explode)

    _post(client, datetime.now().isoformat() + "Z")

    events = client.get("/api/v1/events/").json()
    assert len(events) == 1

    assert client.get("/api/v1/alerts/").json() == []
    assert client.get("/api/v1/attack-sessions/").json() == []