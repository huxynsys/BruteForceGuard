"""Alert API contract: filtering, pagination, facets and triage persistence.

Covers ``GET /api/v1/alerts/`` (server-side filters + paging),
``GET /api/v1/alerts/stats`` (matching total and facet counts) and
``PATCH /api/v1/alerts/{id}`` (analyst transitions persisted to the database).
"""

from fastapi.testclient import TestClient

from app.models.alert import Alert


def _alerts(client: TestClient, query: str = "") -> list:
    response = client.get(f"/api/v1/alerts/{query}")
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Listing, ordering and pagination
# ---------------------------------------------------------------------------


def test_default_request_still_returns_a_plain_list(client, alert_factory):
    """Backward compatibility: no parameters == newest 100 as a bare list."""
    alert_factory()

    body = _alerts(client)

    assert isinstance(body, list)
    assert len(body) == 1


def test_alerts_are_newest_first_and_paginated(client, alert_factory):
    oldest = alert_factory(source_ip="10.0.0.1", username="aaa")
    middle = alert_factory(source_ip="10.0.0.2", username="bbb")
    newest = alert_factory(source_ip="10.0.0.3", username="ccc")

    first_page = _alerts(client, "?limit=2")
    assert [alert["id"] for alert in first_page] == [newest.id, middle.id]

    second_page = _alerts(client, "?skip=2&limit=2")
    assert [alert["id"] for alert in second_page] == [oldest.id]


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_severity_filter(client, alert_factory):
    alert_factory(severity="critical")
    alert_factory(severity="low")

    body = _alerts(client, "?severity=critical")

    assert [alert["severity"] for alert in body] == ["critical"]


def test_status_filter_covers_every_triage_state(client, alert_factory):
    alert_factory(status="open")
    alert_factory(status="false_positive")

    assert len(_alerts(client, "?status=open")) == 1
    assert len(_alerts(client, "?status=false_positive")) == 1
    assert _alerts(client, "?status=resolved") == []
    assert _alerts(client, "?status=acknowledged") == []
    assert _alerts(client, "?status=investigating") == []


def test_alert_type_filter(client, alert_factory):
    alert_factory(alert_type="password_spraying")
    alert_factory(alert_type="low_and_slow")

    body = _alerts(client, "?alert_type=low_and_slow")

    assert [alert["alert_type"] for alert in body] == ["low_and_slow"]


def test_search_matches_source_ip_or_username(client, alert_factory):
    alert_factory(source_ip="192.168.1.44", username="admin")
    alert_factory(source_ip="10.1.2.3", username="guest")

    by_ip = _alerts(client, "?search=192.168.1")
    assert [alert["source_ip"] for alert in by_ip] == ["192.168.1.44"]

    by_username = _alerts(client, "?search=ADM")
    assert [alert["username"] for alert in by_username] == ["admin"]

    # A single search box must not require a username that looks like an IP.
    assert len(_alerts(client, "?search=10.1.2.3")) == 1


def test_filters_combine(client, alert_factory):
    alert_factory(
        severity="critical",
        status="open",
        alert_type="password_spraying",
        source_ip="10.0.0.9",
        username="admin",
    )
    alert_factory(
        severity="critical",
        status="resolved",
        alert_type="password_spraying",
        source_ip="10.0.0.9",
        username="admin",
    )

    body = _alerts(
        client,
        "?severity=critical&status=open&alert_type=password_spraying&search=10.0.0",
    )

    assert len(body) == 1
    assert body[0]["status"] == "open"


def test_invalid_filter_values_are_rejected(client):
    assert client.get("/api/v1/alerts/?severity=urgent").status_code == 422
    assert client.get("/api/v1/alerts/?status=archived").status_code == 422
    assert client.get("/api/v1/alerts/?limit=0").status_code == 422
    assert client.get("/api/v1/alerts/?skip=-1").status_code == 422


# ---------------------------------------------------------------------------
# Facets (pagination total + filter options)
# ---------------------------------------------------------------------------


def test_stats_reports_total_and_facets(client, alert_factory):
    alert_factory(
        severity="critical", status="open", alert_type="password_spraying"
    )
    alert_factory(severity="high", status="open", alert_type="password_spraying")
    alert_factory(severity="high", status="resolved", alert_type="low_and_slow")

    response = client.get("/api/v1/alerts/stats")

    assert response.status_code == 200
    body = response.json()

    assert body["total"] == 3
    assert body["by_status"] == {"open": 2, "resolved": 1}
    assert body["by_severity"] == {"critical": 1, "high": 2}
    assert body["by_alert_type"] == {
        "password_spraying": 2,
        "low_and_slow": 1,
    }


def test_stats_respects_the_same_filters(client, alert_factory):
    alert_factory(severity="critical", status="open")
    alert_factory(severity="low", status="resolved")

    body = client.get("/api/v1/alerts/stats?status=open").json()

    assert body["total"] == 1
    assert body["by_severity"] == {"critical": 1}


# ---------------------------------------------------------------------------
# Triage transitions
# ---------------------------------------------------------------------------


def test_patching_status_is_persisted(client, db, alert_factory):
    alert = alert_factory(status="open")

    response = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "acknowledged"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    # Persisted, not just echoed back.
    detail = client.get(f"/api/v1/alerts/{alert.id}").json()
    assert detail["status"] == "acknowledged"

    db.expire_all()
    assert db.get(Alert, alert.id).status == "acknowledged"

    # The work-queue filters see the new state.
    assert len(_alerts(client, "?status=acknowledged")) == 1
    assert _alerts(client, "?status=open") == []


def test_full_triage_lifecycle(client, alert_factory):
    alert = alert_factory(status="open")

    for status in (
        "acknowledged",
        "investigating",
        "resolved",
        "false_positive",
    ):
        response = client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": status},
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == status


def test_patching_an_unknown_alert_is_404(client):
    response = client.patch(
        "/api/v1/alerts/999999",
        json={"status": "resolved"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"


def test_patching_an_invalid_status_is_422_and_changes_nothing(
    client, alert_factory
):
    alert = alert_factory(status="open")

    response = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "closed"},
    )

    assert response.status_code == 422
    assert client.get(f"/api/v1/alerts/{alert.id}").json()["status"] == "open"


def test_patching_rejects_unknown_fields(client, alert_factory):
    alert = alert_factory()

    response = client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "resolved", "severity": "low"},
    )

    assert response.status_code == 422
