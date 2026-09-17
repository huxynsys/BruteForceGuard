"""Phase 8 Part 1/2/4 — cross-phase regression and API contract tests.

These pin behaviour that Phases 5, 6 and 7 established so Phase 7
intelligence can be proven to *enrich* detection rather than alter it.

They also pin the exact output contract of the dashboard summary (the
hottest endpoint used by the frontend) so it can be optimised safely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent
from app.models.threat_indicator import ThreatIndicator


def _event_payload(**overrides) -> dict:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "regression",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }
    payload.update(overrides)
    return payload


def _reset(bind) -> None:
    with Session(bind=bind) as db:
        for model in (Alert, AttackSession, AuthEvent, ThreatIndicator):
            db.execute(delete(model))
        db.commit()


# ---------------------------------------------------------------------------
# Dashboard summary output contract (pinned, golden values)
# ---------------------------------------------------------------------------


def test_dashboard_summary_contract_is_stable(client, test_engine):
    now = datetime.now(timezone.utc)
    _reset(test_engine)

    with Session(bind=test_engine) as db:
        db.execute(
            insert(AuthEvent),
            [
                {
                    "timestamp": now,
                    "source": "regression",
                    "source_ip": "10.0.0.1",
                    "username": "admin",
                    "result": "failure",
                    "service": "ssh",
                    "port": 22,
                },
                {
                    "timestamp": now,
                    "source": "regression",
                    "source_ip": "10.0.0.1",
                    "username": "admin",
                    "result": "failure",
                    "service": "ssh",
                    "port": 22,
                },
                {
                    "timestamp": now,
                    "source": "regression",
                    "source_ip": "10.0.0.2",
                    "username": "bob",
                    "result": "success",
                    "service": "rdp",
                    "port": 3389,
                },
            ],
        )
        db.execute(
            insert(Alert),
            [
                {
                    "alert_type": "single_account_bruteforce",
                    "severity": "high",
                    "confidence": 70,
                    "title": "a",
                    "description": "a",
                    "source_ip": "10.0.0.1",
                    "username": "admin",
                    "service": "ssh",
                    "status": "open",
                    "evidence": {"failure_count": 2},
                    "risk_score": 88,
                    "risk_level": "critical",
                },
                {
                    "alert_type": "password_spraying",
                    "severity": "low",
                    "confidence": 40,
                    "title": "b",
                    "description": "b",
                    "source_ip": "10.0.0.2",
                    "username": "bob",
                    "service": "rdp",
                    "status": "open",
                    "evidence": {"failure_count": 1},
                    "risk_score": 12,
                    "risk_level": "low",
                },
            ],
        )
        db.execute(
            insert(AttackSession),
            [
                {
                    "started_at": now,
                    "last_seen_at": now,
                    "session_type": "single_account",
                    "severity": "high",
                    "event_count": 5,
                    "source_ips": ["10.0.0.1"],
                    "usernames": ["admin"],
                    "services": ["ssh"],
                    "detection_types": ["single_account"],
                    "status": "active",
                    "risk_score": 80,
                    "risk_level": "high",
                },
                {
                    "started_at": now,
                    "last_seen_at": now,
                    "session_type": "password_spray",
                    "severity": "critical",
                    "event_count": 20,
                    "source_ips": ["10.0.0.2"],
                    "usernames": ["bob"],
                    "services": ["rdp"],
                    "detection_types": ["password_spray"],
                    "status": "closed",
                    "risk_score": 90,
                    "risk_level": "critical",
                },
            ],
        )
        db.commit()

    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    body = response.json()

    assert body["total_events"] == 3
    assert body["total_alerts"] == 2
    assert body["active_sessions"] == 1
    assert body["unique_source_ips"] == 2
    assert body["unique_usernames"] == 2

    assert body["severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
    }
    assert body["detections"] == {
        "single_account": 1,
        "password_spray": 1,
        "distributed": 0,
        "failed_success": 0,
        "credential_stuffing": 0,
        "low_and_slow": 0,
    }

    # Phase 7 intelligence KPIs
    assert body["critical_risk"] == 1
    assert body["high_risk_alerts"] == 1
    assert body["high_risk_sessions"] == 1
    assert body["known_malicious_indicators"] == 0
    assert body["threat_indicators"] == 0


# ---------------------------------------------------------------------------
# Helpers for pipeline regression
# ---------------------------------------------------------------------------

DETECTION_FIELDS = (
    "failure_count",
    "window_seconds",
    "distinct_users",
    "distinct_source_ips",
    "services",
    "source_ip",
    "username",
)


def _post_failures(client, *, ip="10.0.0.1", username="admin", count=5):
    """Post ``count`` failures one second apart (inside the 300s window)."""
    base = datetime.now(timezone.utc) - timedelta(seconds=count)
    for i in range(count):
        payload = _event_payload(
            source_ip=ip,
            username=username,
            result="failure",
            timestamp=(base + timedelta(seconds=i)).isoformat(),
        )
        response = client.post("/api/v1/events/", json=payload)
        assert response.status_code == 200


def _alerts(bind, alert_type=None):
    with Session(bind=bind) as db:
        rows = list(db.scalars(select(Alert)))
    if alert_type:
        rows = [a for a in rows if a.alert_type == alert_type]
    return rows


def _detection_view(alert) -> dict:
    """Only the detection-engine-derived evidence (not enrichment timestamps)."""
    return {key: alert.evidence.get(key) for key in DETECTION_FIELDS}


# ---------------------------------------------------------------------------
# Part 1/2 — Phase 5 pipeline regression
# ---------------------------------------------------------------------------


def test_phase5_single_account_pipeline_regression(client, test_engine):
    """event -> detection -> alert -> session still works end to end."""
    _reset(test_engine)
    _post_failures(client, count=5)

    alerts = _alerts(test_engine, "single_account_bruteforce")
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.severity == "high"
    assert alert.confidence == 50
    assert alert.mitre_technique == "T1110.001"
    assert alert.evidence["failure_count"] == 5
    assert alert.evidence["distinct_users"] == 1
    assert alert.source_ip == "10.0.0.1"
    assert alert.username == "admin"

    with Session(bind=test_engine) as db:
        sessions = list(db.scalars(select(AttackSession)))
    assert len(sessions) == 1
    assert sessions[0].session_type == "single_account"
    assert "single_account" in sessions[0].detection_types


def test_phase7_enrichment_does_not_alter_detection_evidence(
    client,
    test_engine,
):
    """Risk/intel must *enrich* detection, never replace or mutate it."""
    _reset(test_engine)

    # (a) No threat intelligence knows this source.
    _post_failures(client, ip="10.0.0.1", username="admin", count=5)
    baseline = _alerts(test_engine, "single_account_bruteforce")[0]
    baseline_view = _detection_view(baseline)
    baseline_risk = baseline.risk_score
    assert baseline.threat_intelligence is None or (
        baseline.threat_intelligence.get("known") is False
    )

    _reset(test_engine)

    # (b) Identical attack, but the source IP is a known-bad indicator.
    with Session(bind=test_engine) as db:
        db.add(
            ThreatIndicator(
                indicator="10.0.0.1",
                indicator_type="ipv4",
                confidence=95,
                threat_type="brute_force",
                source="test",
                tags=["brute_force"],
                active=True,
            )
        )
        db.commit()

    _post_failures(client, ip="10.0.0.1", username="admin", count=5)
    enriched = _alerts(test_engine, "single_account_bruteforce")[0]

    # Detection evidence is unchanged...
    assert _detection_view(enriched) == baseline_view
    # ...the enrichment is additive...
    assert enriched.threat_intelligence["known"] is True
    assert enriched.risk_score > baseline_risk
    assert enriched.risk_level is not None
    # ...and the detection classification itself is untouched.
    assert enriched.alert_type == baseline.alert_type
    assert enriched.severity == baseline.severity
    assert enriched.confidence == baseline.confidence


def test_phase5_failed_then_success_regression(client, test_engine):
    """Failures followed by a success must raise a critical alert."""
    _reset(test_engine)

    base = datetime.now(timezone.utc) - timedelta(seconds=60)
    for i in range(3):
        response = client.post(
            "/api/v1/events/",
            json=_event_payload(
                source_ip="10.0.0.9",
                username="root",
                timestamp=(base + timedelta(seconds=i)).isoformat(),
            ),
        )
        assert response.status_code == 200

    response = client.post(
        "/api/v1/events/",
        json=_event_payload(
            source_ip="10.0.0.9",
            username="root",
            result="success",
            timestamp=(base + timedelta(seconds=30)).isoformat(),
        ),
    )
    assert response.status_code == 200

    alerts = _alerts(test_engine, "failed_then_success")
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].evidence["failed_attempts"] == 3
    assert alerts[0].evidence["successful_login"] is True


# ---------------------------------------------------------------------------
# Part 1 — API contract status codes
# ---------------------------------------------------------------------------

OK_ENDPOINTS = [
    "/api/v1/events/",
    "/api/v1/alerts/",
    "/api/v1/attack-sessions/",
    "/api/v1/attack-sessions/stats/active",
    "/api/v1/dashboard/summary",
    "/api/v1/dashboard/analytics",
    "/api/v1/intelligence/indicators",
    "/api/v1/intelligence/mitre",
]


def test_api_returns_200_for_all_read_endpoints(client):
    for path in OK_ENDPOINTS:
        assert client.get(path).status_code == 200, path


def test_api_returns_404_for_missing_resources(client):
    assert client.get("/api/v1/events/999999").status_code == 404
    assert client.get("/api/v1/alerts/999999").status_code == 404
    assert client.get("/api/v1/attack-sessions/999999").status_code == 404
    assert client.get("/api/v1/intelligence/mitre/NOPE").status_code == 404


def test_api_returns_422_for_invalid_event_payloads(client):
    bad_ip = _event_payload(source_ip="not-an-ip")
    assert client.post("/api/v1/events/", json=bad_ip).status_code == 422

    bad_result = _event_payload(result="maybe")
    assert client.post("/api/v1/events/", json=bad_result).status_code == 422

    bad_port = _event_payload(port=70000)
    assert client.post("/api/v1/events/", json=bad_port).status_code == 422

    assert client.post("/api/v1/events/", json={"source": "x"}).status_code == 422


# ---------------------------------------------------------------------------
# Part 4 — threat-indicator input validation
# ---------------------------------------------------------------------------

INVALID_INDICATORS = [
    {"indicator": "hello", "indicator_type": "ipv4"},
    {"indicator": "999.999.999.999", "indicator_type": "ipv4"},
    {"indicator": "10.0.0.1", "indicator_type": "invalid"},
    {"indicator": "10.0.0.1", "indicator_type": "ipv4", "confidence": 0},
    {"indicator": "10.0.0.1", "indicator_type": "ipv4", "confidence": 101},
    {"indicator": "bad domain", "indicator_type": "domain"},
    {"indicator": "user name", "indicator_type": "username"},
    {"indicator": "", "indicator_type": "ipv4"},
    {"indicator": "2001:db8::1", "indicator_type": "ipv4"},
]


@pytest.mark.parametrize("payload", INVALID_INDICATORS)
def test_invalid_indicators_are_rejected(client, payload):
    response = client.post("/api/v1/intelligence/indicators", json=payload)
    assert response.status_code == 422, payload


VALID_INDICATORS = [
    {"indicator": "203.0.113.7", "indicator_type": "ipv4"},
    {"indicator": "2001:db8::1", "indicator_type": "ipv6"},
    {"indicator": "malicious.example.com", "indicator_type": "domain"},
    {"indicator": "root", "indicator_type": "username"},
]


@pytest.mark.parametrize("payload", VALID_INDICATORS)
def test_valid_indicators_are_accepted_and_discoverable(
    client,
    test_engine,
    payload,
):
    _reset(test_engine)

    response = client.post("/api/v1/intelligence/indicators", json=payload)
    assert response.status_code == 201

    body = response.json()
    assert body["indicator"] == payload["indicator"].lower()
    assert body["indicator_type"] == payload["indicator_type"]
    assert body["active"] is True

    listed = client.get(
        "/api/v1/intelligence/indicators",
        params={"indicator_type": payload["indicator_type"]},
    )
    assert listed.status_code == 200
    assert [row["indicator"] for row in listed.json()] == [
        payload["indicator"].lower()
    ]


def test_ip_lookup_finds_a_stored_indicator(client, test_engine):
    _reset(test_engine)

    created = client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": "203.0.113.7",
            "indicator_type": "ipv4",
            "confidence": 90,
            "threat_type": "brute_force",
        },
    )
    assert created.status_code == 201

    lookup = client.get("/api/v1/intelligence/ip/203.0.113.7")
    assert lookup.status_code == 200

    result = lookup.json()
    assert result["known"] is True
    assert result["confidence"] == 90
    assert result["threat_type"] == "brute_force"
    assert "brute_force" in result["categories"]


def test_ip_lookup_for_unknown_indicator_is_not_reported_as_safe(
    client,
    test_engine,
):
    _reset(test_engine)

    lookup = client.get("/api/v1/intelligence/ip/198.51.100.200")
    assert lookup.status_code == 200

    result = lookup.json()
    # An unknown indicator is *unknown*, never implicitly trustworthy.
    assert result["known"] is False
    assert result["confidence"] is None