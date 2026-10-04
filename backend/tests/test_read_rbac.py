"""Read-path RBAC: security-data reads require an authenticated principal.

The unified authentication/RBAC change moved the previously-open read
endpoints behind ``require_reader``.  These tests pin the new contract across
every resource type so a regression cannot silently re-open them.

Contract (``app/api/deps.py``:``require_reader``):

* ``401`` without a bearer token (``WWW-Authenticate: Bearer``);
* ``401`` for an unknown / expired credential;
* ``200`` for any valid static token (analyst or admin) — reads never require
  an ``X-User-Id`` header because they perform no audited action.
"""

import pytest

PROTECTED_READS = [
    "/api/v1/events/",
    "/api/v1/events/groups",
    "/api/v1/alerts/",
    "/api/v1/alerts/stats",
    "/api/v1/attack-sessions/",
    "/api/v1/attack-sessions/stats/active",
    "/api/v1/dashboard/summary",
    "/api/v1/dashboard/analytics",
    "/api/v1/intelligence/indicators",
    "/api/v1/intelligence/mitre",
    "/api/v1/intelligence/mitre/T1110.001",
    "/api/v1/intelligence/ip/203.0.113.1",
    "/api/v1/intelligence/reputation/203.0.113.1",
]


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_protected_reads_require_authentication(client, path):
    """No credential presented -> 401 with a Bearer challenge."""

    response = client.get(path)

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_protected_reads_reject_unknown_tokens(client, path):
    """An unknown / expired credential is indistinguishable from anonymous."""

    response = client.get(
        path, headers={"Authorization": "Bearer not-a-real-token"}
    )

    assert response.status_code == 401


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_analyst_token_can_read(client, path, reader_headers):
    """An analyst static token satisfies ``require_reader``."""

    assert client.get(path, headers=reader_headers).status_code == 200


@pytest.mark.parametrize("path", PROTECTED_READS)
def test_admin_token_can_read_without_identity_header(client, path, admin_headers):
    """Reads never require ``X-User-Id``; the role is bound to the token."""

    headers = {"Authorization": admin_headers["Authorization"]}

    assert client.get(path, headers=headers).status_code == 200
