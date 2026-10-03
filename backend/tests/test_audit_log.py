"""Immutable security audit log: append-only evidence + admin-only reads.

Covers ``security_audit_logs`` end to end:

* three enforcement layers - no write endpoints, ORM ``before_update`` /
  ``before_delete`` listeners, and database triggers (the trigger layer is
  exercised against a real migrated database in ``test_migrations.py``);
* secret redaction in the sanitizer, so a presented credential can never be
  persisted;
* the write hooks - alert triage transitions, IP blocklist/whitelist changes
  and rejected authentication attempts;
* ``GET /api/v1/audit/`` authentication (fail-closed 503, 401, 403) and the
  filter/pagination behaviour of the read API.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import Base
from app.models.audit_log import (
    AuditAction,
    AuditLogImmutableError,
    AuditResult,
    SecurityAuditLog,
)
from app.services.audit_service import (
    MAX_STRING_LENGTH,
    REDACTED,
    AuditService,
    client_ip,
    sanitize_detail,
)

AUDIT_URL = "/api/v1/audit/"
BLACKLIST_URL = "/api/v1/blacklist/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(client, headers, **params) -> dict:
    """Read one page of the audit log, asserting the request succeeded."""

    response = client.get(AUDIT_URL, headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _entries(client, headers, **params) -> list[dict]:
    return _read(client, headers, **params)["items"]


def _single(client, headers, **params) -> dict:
    """The one and only audit entry matching the filters."""

    items = _entries(client, headers, **params)
    assert len(items) == 1, items
    return items[0]


def _bearer(token: str, user: str) -> dict:
    return {"Authorization": f"Bearer {token}", "X-User-Id": user}


@pytest.fixture()
def ip_management_headers(monkeypatch) -> dict:
    """Valid credentials for an IP-management write (token + identity)."""

    monkeypatch.setattr(
        settings, "ip_management_api_tokens", "ip-token", raising=False
    )
    return {"Authorization": "Bearer ip-token", "X-User-Id": "netadmin"}


@pytest.fixture()
def source_ip_client(test_engine, monkeypatch):
    """A TestClient whose peer address is a *real* IP (``203.0.113.9``).

    The default ``client`` fixture reports the peer as ``testclient``, which
    is not an address and therefore resolves to ``None``; this fixture proves
    the ``source_ip`` column is actually populated from the request.
    """

    from fastapi.testclient import TestClient

    import app.main as main_module
    from app.db.database import get_db
    from app.main import app

    def _override_get_db():
        session = Session(bind=test_engine, autoflush=False, autocommit=False)
        try:
            yield session
        finally:
            session.close()

    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    app.dependency_overrides[get_db] = _override_get_db
    monkeypatch.setattr(main_module, "engine", test_engine)
    # The blacklist middleware resolves its session through ``app.main.get_db``
    # directly (dependency overrides do not apply there), so point it at the
    # SQLite test engine too - otherwise a real peer address sends the
    # middleware to the application database.
    monkeypatch.setattr(main_module, "get_db", _override_get_db, raising=False)

    try:
        with TestClient(app, client=("203.0.113.9", 50000)) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()



# ---------------------------------------------------------------------------
# Immutability layer 2: the ORM refuses to mutate a row
# ---------------------------------------------------------------------------


def test_audit_rows_cannot_be_updated_through_the_orm(db):
    AuditService(db).record(
        action=AuditAction.AUTH_FAILED, result=AuditResult.FAILURE, note="initial"
    )
    entry = db.query(SecurityAuditLog).one()

    entry.note = "tampered"
    with pytest.raises(AuditLogImmutableError):
        db.commit()
    db.rollback()

    assert db.query(SecurityAuditLog).one().note == "initial"


def test_audit_rows_cannot_be_deleted_through_the_orm(db):
    AuditService(db).record(
        action=AuditAction.AUTH_FAILED, result=AuditResult.FAILURE
    )
    entry = db.query(SecurityAuditLog).one()

    db.delete(entry)
    with pytest.raises(AuditLogImmutableError):
        db.commit()
    db.rollback()

    assert db.query(SecurityAuditLog).count() == 1


def test_recording_grouped_into_a_caller_transaction_commits_once(db):
    """``commit=False`` leaves the row pending for the caller's commit."""

    AuditService(db).record(
        action=AuditAction.ALERT_STATUS_CHANGE,
        result=AuditResult.SUCCESS,
        commit=False,
    )

    db.commit()
    assert db.query(SecurityAuditLog).count() == 1


# ---------------------------------------------------------------------------
# Sanitizer: secrets never reach the log
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["password", "Password", "api_key", "apikey", "authorization", "session_id"],
)
def test_sanitize_detail_redacts_secret_looking_keys(key):
    sanitized = sanitize_detail({key: "hunter2", "safe": "keep-me"})

    assert sanitized[key] == REDACTED
    assert sanitized["safe"] == "keep-me"


def test_sanitize_detail_redacts_nested_secrets_and_keeps_lists():
    sanitized = sanitize_detail(
        {
            "headers": {"Authorization": "Bearer abc", "X-User-Id": "analyst"},
            "attempts": ["one", "two"],
        }
    )

    assert sanitized["headers"]["Authorization"] == REDACTED
    assert sanitized["headers"]["X-User-Id"] == "analyst"
    assert sanitized["attempts"] == ["one", "two"]


def test_sanitize_detail_truncates_oversized_strings():
    sanitized = sanitize_detail({"reason": "x" * (MAX_STRING_LENGTH + 100)})

    assert sanitized["reason"].endswith("...[truncated]")
    assert len(sanitized["reason"]) == MAX_STRING_LENGTH + len("...[truncated]")


def test_sanitize_detail_stringifies_non_json_scalars_and_bounds_depth():
    from datetime import datetime, timezone

    moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    sanitized = sanitize_detail(
        {"at": moment, "nested": {"a": {"b": {"c": {"d": {"e": 1}}}}}}
    )

    assert sanitized["at"] == "2026-01-02 03:04:05+00:00"
    # Nesting past MAX_DEPTH is flattened to a placeholder, never recursed.
    assert sanitized["nested"]["a"]["b"]["c"]["d"] == {
        "e": "[truncated: max depth exceeded]"
    }


def test_client_ip_resolves_real_addresses_and_rejects_junk():
    class _Request:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})()

    assert client_ip(_Request("203.0.113.7")) == "203.0.113.7"
    assert client_ip(_Request("[2001:db8::1]")) == "2001:db8::1"
    assert client_ip(_Request("testclient")) is None
    assert client_ip(_Request("")) is None


# ---------------------------------------------------------------------------
# Read API authentication (admin role, bound to the token)
# ---------------------------------------------------------------------------


def test_audit_read_fails_closed_when_triage_tokens_are_unconfigured(
    client, monkeypatch
):
    monkeypatch.setattr(settings, "alert_triage_api_tokens", "", raising=False)

    response = client.get(AUDIT_URL, headers=_bearer("admin-token", "admin"))

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_audit_read_requires_a_bearer_token(client):
    response = client.get(AUDIT_URL)

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_an_unknown_token_cannot_read_the_audit_log(client):
    response = client.get(AUDIT_URL, headers=_bearer("wrong-token", "intruder"))

    assert response.status_code == 403


def test_an_analyst_token_cannot_read_the_audit_log(client, analyst_headers):
    response = client.get(AUDIT_URL, headers=analyst_headers)

    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


def test_audit_read_requires_an_identity_header(client):
    response = client.get(AUDIT_URL, headers={"Authorization": "Bearer admin-token"})

    assert response.status_code == 401
    assert response.json()["detail"] == "User identity required"


def test_audit_read_returns_an_empty_page_initially(client, admin_headers):
    assert _read(client, admin_headers) == {"items": [], "total": 0}


def test_the_audit_log_exposes_no_write_endpoints(client, admin_headers):
    """The table is append-only: the API deliberately offers reads only."""

    for method in (client.post, client.put, client.patch, client.delete):
        assert method(AUDIT_URL, headers=admin_headers).status_code == 405


# ---------------------------------------------------------------------------
# Write hook 1: alert triage transitions
# ---------------------------------------------------------------------------


def _transition(client, alert_id, status, headers, reason=None):
    payload = {"status": status}
    if reason is not None:
        payload["reason"] = reason
    return client.patch(f"/api/v1/alerts/{alert_id}", json=payload, headers=headers)


def test_an_accepted_triage_transition_is_recorded(
    client, alert_factory, analyst_headers, admin_headers
):
    alert = alert_factory(status="open")

    assert (
        _transition(
            client, alert.id, "resolved", analyst_headers, reason="False alarm"
        ).status_code
        == 200
    )

    entry = _single(client, admin_headers)
    assert entry["action"] == "alert.status_change"
    assert entry["result"] == "success"
    assert entry["actor"] == "analyst"
    assert entry["actor_role"] == "analyst"
    assert entry["target_type"] == "alert"
    assert entry["target_id"] == str(alert.id)
    assert entry["detail"] == {
        "from_status": "open",
        "to_status": "resolved",
        "reason": "False alarm",
    }
    assert entry["note"] is None
    assert entry["created_at"]


def test_a_denied_transition_is_recorded_as_denied(
    client, alert_factory, analyst_headers, admin_headers
):
    """An analyst reopening a closed alert is a privilege escalation attempt."""

    alert = alert_factory(status="resolved")

    response = _transition(client, alert.id, "investigating", analyst_headers)

    assert response.status_code == 403
    entry = _single(client, admin_headers)
    assert entry["action"] == "alert.status_change"
    assert entry["result"] == "denied"
    assert entry["actor"] == "analyst"
    assert entry["actor_role"] == "analyst"
    assert entry["detail"]["from_status"] == "resolved"
    assert entry["detail"]["to_status"] == "investigating"
    assert "admin" in entry["note"]


def test_an_invalid_transition_is_recorded_as_failure(
    client, alert_factory, analyst_headers, admin_headers
):
    alert = alert_factory(status="open")

    response = _transition(client, alert.id, "resolved", analyst_headers)
    assert response.status_code == 200

    # open -> resolved -> resolved is not a legal successor.
    response = _transition(client, alert.id, "resolved", analyst_headers)
    assert response.status_code == 409

    entry = _single(client, admin_headers, result="failure")
    assert entry["action"] == "alert.status_change"
    assert entry["detail"] == {
        "from_status": "resolved",
        "to_status": "resolved",
        "reason": None,
    }


def test_a_rejected_triage_authentication_is_recorded(
    client, alert_factory, admin_headers
):
    alert = alert_factory(status="open")

    response = _transition(client, alert.id, "acknowledged", _bearer("wrong-token", "nobody"))
    assert response.status_code == 403

    entry = _single(client, admin_headers)
    assert entry["action"] == "auth.failed"
    assert entry["result"] == "failure"
    assert entry["target_type"] == "endpoint"
    assert entry["target_id"] == f"/api/v1/alerts/{alert.id}"
    assert entry["detail"] == {
        "path": f"/api/v1/alerts/{alert.id}",
        "status": 403,
    }
    assert entry["note"] == "Triage write rejected: unknown token"



def test_the_presented_token_is_never_persisted(
    client, alert_factory, admin_headers
):
    """A rejected credential must not leak into the audit evidence."""

    alert = alert_factory(status="open")
    secret = "super-secret-token-value"

    assert _transition(client, alert.id, "acknowledged", _bearer(secret, "nobody")).status_code == 403

    response = client.get(AUDIT_URL, headers=admin_headers)
    assert response.status_code == 200
    assert secret not in response.text
    assert "REDACTED" not in response.text


# ---------------------------------------------------------------------------
# Write hook 2: IP blocklist / whitelist changes
# ---------------------------------------------------------------------------


def _ip_payload(list_type: str, ip_address: str, **extra) -> dict:
    return {
        "entry_type": "SINGLE",
        "list_type": list_type,
        "ip_address": ip_address,
        "description": f"{list_type} entry",
        "added_by": "netadmin",
        **extra,
    }


def test_blocklist_and_whitelist_changes_are_recorded(
    client, admin_headers, ip_management_headers
):
    created = client.post(
        BLACKLIST_URL,
        json=_ip_payload("BLOCKLIST", "203.0.113.20"),
        headers=ip_management_headers,
    )
    assert created.status_code == 201
    entry_id = created.json()["id"]

    whitelisted = client.post(
        BLACKLIST_URL,
        json=_ip_payload("WHITELIST", "198.51.100.9"),
        headers=ip_management_headers,
    )
    assert whitelisted.status_code == 201
    whitelist_id = whitelisted.json()["id"]

    removed = client.delete(
        f"{BLACKLIST_URL}{entry_id}", headers=ip_management_headers
    )
    assert removed.status_code == 200
    whitelist_removed = client.delete(
        f"{BLACKLIST_URL}{whitelist_id}", headers=ip_management_headers
    )
    assert whitelist_removed.status_code == 200

    actions = [item["action"] for item in _entries(client, admin_headers, limit=50)]
    assert actions == [
        "ip.whitelist.remove",
        "ip.blocklist.remove",
        "ip.whitelist.add",
        "ip.blocklist.add",
    ]

    added = _single(client, admin_headers, action="ip.blocklist.add")
    assert added["result"] == "success"
    assert added["actor"] == "netadmin"
    assert added["actor_role"] is None
    assert added["target_type"] == "blacklist_entry"
    assert added["target_id"] == str(entry_id)
    assert added["detail"]["list_type"] == "BLOCKLIST"
    assert added["detail"]["value"] == "203.0.113.20"
    assert added["detail"]["entry_type"] == "SINGLE"

    removed_entry = _single(client, admin_headers, action="ip.whitelist.remove")
    assert removed_entry["target_id"] == str(whitelist_id)
    assert removed_entry["detail"]["list_type"] == "WHITELIST"
    assert removed_entry["detail"]["value"] == "198.51.100.9"


def test_an_unknown_blacklist_entry_is_not_audited(
    client, admin_headers, ip_management_headers
):
    assert (
        client.delete(f"{BLACKLIST_URL}999999", headers=ip_management_headers).status_code
        == 404
    )

    assert _read(client, admin_headers) == {"items": [], "total": 0}


def test_a_rejected_ip_management_authentication_is_recorded(
    client, admin_headers, monkeypatch
):
    monkeypatch.setattr(
        settings, "ip_management_api_tokens", "ip-token", raising=False
    )

    response = client.post(
        BLACKLIST_URL, json=_ip_payload("BLOCKLIST", "203.0.113.30")
    )
    assert response.status_code == 401

    entry = _single(client, admin_headers)
    assert entry["action"] == "auth.failed"
    assert entry["result"] == "failure"
    assert entry["target_id"] == "/api/v1/blacklist/"
    assert entry["note"] == "IP management write rejected: bearer token missing"
    assert entry["detail"] == {"path": "/api/v1/blacklist/", "status": 401}
    assert entry["source_ip"] is None


def test_an_unconfigured_ip_management_api_is_not_audited(
    client, admin_headers, monkeypatch
):
    """A missing deployment configuration is a 503, not an auth attempt."""

    monkeypatch.setattr(settings, "ip_management_api_tokens", "", raising=False)

    response = client.post(
        BLACKLIST_URL, json=_ip_payload("BLOCKLIST", "203.0.113.40")
    )
    assert response.status_code == 503

    assert _read(client, admin_headers) == {"items": [], "total": 0}


def test_the_resolved_peer_address_is_stored(
    source_ip_client, admin_headers, ip_management_headers
):
    assert (
        source_ip_client.post(
            BLACKLIST_URL,
            json=_ip_payload("BLOCKLIST", "203.0.113.50"),
            headers=ip_management_headers,
        ).status_code
        == 201
    )

    entry = _single(source_ip_client, admin_headers, action="ip.blocklist.add")


# ---------------------------------------------------------------------------
# Filtering, ordering and pagination of the read API
# ---------------------------------------------------------------------------


def _seed_mixed_entries(client, alert_factory, analyst_headers):
    """Create three audit rows: two accepted transitions and one rejection.

    ``open -> acknowledged -> resolved`` are legal analyst transitions while
    the final ``resolved -> resolved`` is a no-op the state machine rejects
    (409), so the log holds two ``success`` rows and one ``failure`` row.
    """

    alert = alert_factory(status="open")
    assert (
        _transition(client, alert.id, "acknowledged", analyst_headers).status_code
        == 200
    )
    assert (
        _transition(
            client, alert.id, "resolved", analyst_headers, reason="Handled"
        ).status_code
        == 200
    )
    assert (
        _transition(client, alert.id, "resolved", analyst_headers).status_code == 409
    )
    return alert


def test_audit_read_filters_by_action_user_and_result(
    client, alert_factory, analyst_headers, admin_headers
):
    _seed_mixed_entries(client, alert_factory, analyst_headers)

    assert _read(client, admin_headers)["total"] == 3
    assert _read(client, admin_headers, action="alert.status_change")["total"] == 3
    assert _read(client, admin_headers, action="auth.failed")["total"] == 0

    assert _read(client, admin_headers, user="analyst")["total"] == 3
    assert _read(client, admin_headers, user="someone-else")["total"] == 0

    assert _read(client, admin_headers, result="success")["total"] == 2
    assert _read(client, admin_headers, result="failure")["total"] == 1
    assert _read(client, admin_headers, result="denied")["total"] == 0


def test_audit_read_combines_filters_with_and(
    client, alert_factory, analyst_headers, admin_headers
):
    _seed_mixed_entries(client, alert_factory, analyst_headers)

    assert _read(
        client, admin_headers, action="alert.status_change", result="success"
    )["total"] == 2
    assert _read(
        client, admin_headers, action="alert.status_change", result="denied"
    )["total"] == 0


def test_audit_read_filters_by_time_window(
    client, alert_factory, analyst_headers, admin_headers
):
    _seed_mixed_entries(client, alert_factory, analyst_headers)

    assert _read(client, admin_headers, since="2000-01-01T00:00:00")["total"] == 3
    assert _read(client, admin_headers, until="2000-01-01T00:00:00")["total"] == 0
    assert _read(
        client,
        admin_headers,
        since="2000-01-01T00:00:00",
        until="2100-01-01T00:00:00",
    )["total"] == 3
    assert _read(client, admin_headers, since="2100-01-01T00:00:00")["total"] == 0


def test_an_invalid_result_filter_is_rejected(client, admin_headers):
    response = client.get(AUDIT_URL, headers=admin_headers, params={"result": "maybe"})

    assert response.status_code == 422
    assert "result must be one of" in response.json()["detail"]


def test_audit_read_paginates_newest_first(
    client, alert_factory, analyst_headers, admin_headers
):
    _seed_mixed_entries(client, alert_factory, analyst_headers)

    page = _read(client, admin_headers, limit=1)
    assert page["total"] == 3
    assert len(page["items"]) == 1

    first = _read(client, admin_headers, limit=2)["items"]
    assert [item["id"] for item in first] == sorted(
        (item["id"] for item in first), reverse=True
    )
    assert first[0]["detail"]["to_status"] == "resolved"
    assert first[0]["result"] == "failure"
    assert first[1]["detail"]["to_status"] == "resolved"
    assert first[1]["result"] == "success"

    second = _read(client, admin_headers, limit=2, skip=2)["items"]
    assert len(second) == 1
    assert second[0]["detail"]["to_status"] == "acknowledged"

    assert _read(client, admin_headers, skip=3)["items"] == []


def test_audit_read_limit_and_skip_are_bounded(client, admin_headers):
    assert (
        client.get(AUDIT_URL, headers=admin_headers, params={"limit": 0}).status_code
        == 422
    )
    assert (
        client.get(AUDIT_URL, headers=admin_headers, params={"limit": 501}).status_code
        == 422
    )
    assert (
        client.get(AUDIT_URL, headers=admin_headers, params={"skip": -1}).status_code
        == 422
    )


def test_every_listed_entry_has_the_documented_shape(
    client, alert_factory, analyst_headers, admin_headers
):
    _seed_mixed_entries(client, alert_factory, analyst_headers)

    entry = _entries(client, admin_headers, limit=1)[0]

    assert set(entry) == {
        "id",
        "created_at",
        "action",
        "actor",
        "actor_role",
        "target_type",
        "target_id",
        "result",
        "source_ip",
        "detail",
        "note",
    }
    assert entry["id"] > 0
    assert entry["actor"] == "analyst"
    assert entry["actor_role"] == "analyst"

