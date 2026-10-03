"""Alert lifecycle: state machine, permissions, audit trail and auth.

Covers ``PATCH /api/v1/alerts/{id}`` and ``GET /api/v1/alerts/{id}/history``:

* authentication + role binding (``ALERT_TRIAGE_API_TOKENS``)
* valid transitions persisting snapshot fields (timestamp, actor, reason)
* invalid transitions rejected with 409 and *no* side effects
* analyst vs admin permissions (reopening a closed alert is admin-only)
* the append-only ``alert_status_history`` audit trail and the audit log line
"""

import logging

from app.core.config import settings
from app.models.alert import Alert, AlertStatusHistory


def _patch(client, alert_id, payload, headers):
    return client.patch(f"/api/v1/alerts/{alert_id}", json=payload, headers=headers)


# ---------------------------------------------------------------------------
# Authentication and role resolution
# ---------------------------------------------------------------------------


def test_triage_writes_fail_closed_when_unconfigured(
    client, alert_factory, analyst_headers, monkeypatch
):
    monkeypatch.setattr(settings, "alert_triage_api_tokens", "", raising=False)
    alert = alert_factory()

    response = _patch(client, alert.id, {"status": "acknowledged"}, analyst_headers)

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]
    assert client.get(f"/api/v1/alerts/{alert.id}").json()["status"] == "open"


def test_triage_writes_require_a_bearer_token(client, alert_factory):
    alert = alert_factory()

    response = _patch(
        client, alert.id, {"status": "acknowledged"}, {"X-User-Id": "analyst"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_an_unknown_bearer_token_is_forbidden(client, alert_factory):
    alert = alert_factory()

    response = _patch(
        client,
        alert.id,
        {"status": "acknowledged"},
        {"Authorization": "Bearer wrong-token", "X-User-Id": "analyst"},
    )

    assert response.status_code == 403


def test_an_identity_header_is_required(client, alert_factory):
    alert = alert_factory()

    response = _patch(
        client,
        alert.id,
        {"status": "acknowledged"},
        {"Authorization": "Bearer analyst-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "User identity required"


def test_the_role_is_bound_to_the_token_not_to_a_client_header(
    client, alert_factory, analyst_headers
):
    """An analyst token stays an analyst even if the client claims admin."""

    alert = alert_factory(status="resolved")

    response = _patch(
        client,
        alert.id,
        {"status": "investigating"},
        {**analyst_headers, "X-User-Role": "admin"},
    )

    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


def test_a_token_without_a_role_defaults_to_analyst(
    client, alert_factory, monkeypatch
):
    monkeypatch.setattr(
        settings, "alert_triage_api_tokens", "plain-token", raising=False
    )
    headers = {"Authorization": "Bearer plain-token", "X-User-Id": "casey"}

    alert = alert_factory(status="resolved")
    assert (
        _patch(client, alert.id, {"status": "investigating"}, headers).status_code
        == 403
    )

    fresh = alert_factory(status="open")
    assert (
        _patch(client, fresh.id, {"status": "acknowledged"}, headers).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# Valid transitions
# ---------------------------------------------------------------------------


def test_valid_transition_persists_the_snapshot_fields(
    client, db, alert_factory, analyst_headers
):
    alert = alert_factory(status="open")

    response = _patch(client, alert.id, {"status": "acknowledged"}, analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "acknowledged"
    assert body["status_updated_at"] is not None
    assert body["status_updated_by"] == "analyst"
    assert body["status_reason"] is None

    # Persisted, not just echoed back.
    db.expire_all()
    row = db.get(Alert, alert.id)
    assert row.status == "acknowledged"
    assert row.status_updated_by == "analyst"
    assert row.status_updated_at is not None


def test_an_analyst_can_reclassify_between_closed_states(
    client, alert_factory, analyst_headers
):
    """resolved <-> false_positive is a correction, not a reopen."""

    alert = alert_factory(status="false_positive")

    response = _patch(client, alert.id, {"status": "resolved"}, analyst_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_the_analyst_workflow_chain_is_accepted_end_to_end(
    client, alert_factory, analyst_headers
):
    alert = alert_factory(status="open")

    for status in ("acknowledged", "investigating", "resolved", "false_positive"):
        response = _patch(client, alert.id, {"status": status}, analyst_headers)
        assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# Invalid transitions
# ---------------------------------------------------------------------------


def test_a_self_transition_is_rejected_and_changes_nothing(
    client, db, alert_factory, analyst_headers
):
    alert = alert_factory(status="open")

    response = _patch(client, alert.id, {"status": "open"}, analyst_headers)

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert "Invalid alert status transition" in detail
    assert "open" in detail

    db.expire_all()
    row = db.get(Alert, alert.id)
    assert row.status == "open"
    assert row.status_updated_at is None
    assert row.status_updated_by is None

    # No audit rows for a rejected transition.
    assert db.query(AlertStatusHistory).count() == 0
    assert client.get(f"/api/v1/alerts/{alert.id}/history").json() == []


def test_a_closed_alert_cannot_close_itself_again(
    client, alert_factory, analyst_headers
):
    alert = alert_factory(status="resolved")

    response = _patch(client, alert.id, {"status": "resolved"}, analyst_headers)

    assert response.status_code == 409
    assert client.get(f"/api/v1/alerts/{alert.id}").json()["status"] == "resolved"


# ---------------------------------------------------------------------------
# Analyst / admin permissions
# ---------------------------------------------------------------------------


def test_an_analyst_cannot_reopen_a_closed_alert(
    client, db, alert_factory, analyst_headers
):
    alert = alert_factory(status="resolved")

    response = _patch(client, alert.id, {"status": "investigating"}, analyst_headers)

    assert response.status_code == 403
    assert "admin" in response.json()["detail"]

    db.expire_all()
    row = db.get(Alert, alert.id)
    assert row.status == "resolved"
    assert row.status_updated_at is None
    assert db.query(AlertStatusHistory).count() == 0


def test_an_admin_can_reopen_a_closed_alert(
    client, db, alert_factory, admin_headers
):
    alert = alert_factory(status="resolved")

    response = _patch(client, alert.id, {"status": "investigating"}, admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "investigating"
    assert body["status_updated_by"] == "admin"

    db.expire_all()
    entry = db.query(AlertStatusHistory).one()
    assert entry.from_status == "resolved"
    assert entry.to_status == "investigating"
    assert entry.changed_by == "admin"
    assert entry.changed_by_role == "admin"
    assert entry.changed_at is not None


# ---------------------------------------------------------------------------
# Optional resolution / false-positive reason
# ---------------------------------------------------------------------------


def test_a_closure_reason_is_recorded_on_the_alert_and_audit_row(
    client, db, alert_factory, analyst_headers
):
    alert = alert_factory(status="open")

    response = _patch(
        client,
        alert.id,
        {"status": "false_positive", "reason": "Known maintenance job"},
        analyst_headers,
    )

    assert response.status_code == 200
    assert response.json()["status_reason"] == "Known maintenance job"

    entry = db.query(AlertStatusHistory).one()
    assert entry.reason == "Known maintenance job"


def test_the_reason_clears_when_the_alert_reopens(
    client, db, alert_factory, analyst_headers, admin_headers
):
    alert = alert_factory(status="open")
    _patch(
        client,
        alert.id,
        {"status": "resolved", "reason": "Ticket SEC-1 closed"},
        analyst_headers,
    )

    reopened = _patch(client, alert.id, {"status": "open"}, admin_headers)

    assert reopened.status_code == 200
    assert reopened.json()["status_reason"] is None


def test_a_blank_reason_is_normalized_to_null(
    client, db, alert_factory, analyst_headers
):
    alert = alert_factory(status="open")

    response = _patch(
        client,
        alert.id,
        {"status": "resolved", "reason": "   "},
        analyst_headers,
    )

    assert response.status_code == 200
    assert response.json()["status_reason"] is None
    assert db.query(AlertStatusHistory).one().reason is None


def test_an_oversized_reason_is_rejected(client, alert_factory, analyst_headers):
    alert = alert_factory(status="open")

    response = _patch(
        client,
        alert.id,
        {"status": "resolved", "reason": "x" * 501},
        analyst_headers,
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Audit trail endpoint
# ---------------------------------------------------------------------------


def test_history_returns_every_transition_newest_first(
    client, alert_factory, analyst_headers, admin_headers
):
    alert = alert_factory(status="open")
    _patch(client, alert.id, {"status": "acknowledged"}, analyst_headers)
    _patch(client, alert.id, {"status": "resolved"}, analyst_headers)
    _patch(
        client,
        alert.id,
        {"status": "investigating", "reason": "Second wave detected"},
        admin_headers,
    )

    response = client.get(f"/api/v1/alerts/{alert.id}/history")

    assert response.status_code == 200
    history = response.json()
    assert [entry["to_status"] for entry in history] == [
        "investigating",
        "resolved",
        "acknowledged",
    ]

    latest = history[0]
    assert latest["from_status"] == "resolved"
    assert latest["changed_by"] == "admin"
    assert latest["changed_by_role"] == "admin"
    assert latest["reason"] == "Second wave detected"
    assert latest["changed_at"]

    first = history[-1]
    assert first["from_status"] == "open"
    assert first["changed_by"] == "analyst"
    assert first["changed_by_role"] == "analyst"
    assert first["reason"] is None


def test_history_of_an_untouched_alert_is_empty(client, alert_factory):
    alert = alert_factory()

    assert client.get(f"/api/v1/alerts/{alert.id}/history").json() == []


def test_history_of_an_unknown_alert_is_404(client):
    assert client.get("/api/v1/alerts/999999/history").status_code == 404


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def test_an_accepted_transition_emits_an_audit_log(
    client, alert_factory, analyst_headers, caplog
):
    alert = alert_factory(status="open")

    with caplog.at_level(logging.INFO, logger="app.services.alert_service"):
        _patch(
            client,
            alert.id,
            {"status": "resolved", "reason": "False alarm"},
            analyst_headers,
        )

    messages = [record.getMessage() for record in caplog.records]
    audit_lines = [m for m in messages if "alert_status_transition" in m]

    assert len(audit_lines) == 1
    line = audit_lines[0]
    assert f"alert_id={alert.id}" in line
    assert "open->resolved" in line
    assert "actor=analyst" in line
    assert "role=analyst" in line
    assert "reason=False alarm" in line


