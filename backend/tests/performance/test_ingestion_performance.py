"""Phase 8 Parts 12, 14, 15 and 16 — ingestion, API latency, pagination.

Ingestion is measured end-to-end through the HTTP layer (validation +
detection + intelligence + alert + session).  API latency is measured
against seeded datasets of 10 / 100 / 1000 records to expose endpoints
that degrade with volume.

Ceilings are generous guard rails; measured values are recorded in
``docs/performance/phase-8-benchmark-results.md``.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, insert, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent

MAX_INGEST_MS_PER_EVENT = 150.0
MAX_API_MS = 1000.0


def _payload(i: int) -> dict:
    return {
        "timestamp": (
            datetime.now(timezone.utc) + timedelta(milliseconds=i * 20)
        ).isoformat(),
        "source": "loadgen",
        "source_ip": f"203.0.113.{i % 250 + 1}",
        "username": f"user{i % 40}",
        "result": "failure",
        "service": "ssh",
        "port": 22,
    }


def _seed(bind, records: int) -> None:
    """Bulk-seed events, alerts and attack sessions."""
    base = datetime.now(timezone.utc) - timedelta(hours=1)

    with Session(bind=bind) as db:
        db.execute(delete(Alert))
        db.execute(delete(AttackSession))
        db.execute(delete(AuthEvent))
        db.commit()

        db.execute(
            insert(AuthEvent),
            [
                {
                    "timestamp": base + timedelta(seconds=i),
                    "source": "seed",
                    "source_ip": f"198.51.100.{i % 250 + 1}",
                    "username": f"user{i % 40}",
                    "result": "failure",
                    "service": "ssh",
                    "port": 22,
                }
                for i in range(records)
            ],
        )
        db.execute(
            insert(Alert),
            [
                {
                    "alert_type": "single_account_bruteforce",
                    "severity": "high",
                    "confidence": 70,
                    "title": f"Seeded alert {i}",
                    "description": "seed",
                    "source_ip": f"198.51.100.{i % 250 + 1}",
                    "username": f"user{i % 40}",
                    "service": "ssh",
                    "status": "open",
                    "evidence": {"failure_count": 5},
                }
                for i in range(records)
            ],
        )
        db.execute(
            insert(AttackSession),
            [
                {
                    "started_at": base + timedelta(seconds=i),
                    "last_seen_at": base + timedelta(seconds=i + 5),
                    "session_type": "single_account",
                    "severity": "high",
                    "event_count": 5,
                    "source_ips": [f"198.51.100.{i % 250 + 1}"],
                    "usernames": [f"user{i % 40}"],
                    "services": ["ssh"],
                    "detection_types": ["single_account"],
                    "status": "active",
                }
                for i in range(records)
            ],
        )
        db.commit()


# ---------------------------------------------------------------------------
# Part 12/14 — end-to-end ingestion throughput
# ---------------------------------------------------------------------------


def test_full_pipeline_ingestion_throughput(
    client,
    test_engine,
    record_property,
):
    count = 150

    start = time.perf_counter()
    for i in range(count):
        response = client.post("/api/v1/events/", json=_payload(i))
        assert response.status_code == 200
    elapsed = time.perf_counter() - start

    per_event_ms = (elapsed / count) * 1000
    throughput = count / elapsed

    record_property("events", count)
    record_property("seconds", round(elapsed, 4))
    record_property("ms_per_event", round(per_event_ms, 3))
    record_property("events_per_second", round(throughput, 2))

    print(
        f"\nBENCH ingestion events={count} "
        f"total_s={elapsed:.3f} "
        f"ms_per_event={per_event_ms:.2f} "
        f"events_per_sec={throughput:.1f}"
    )

    with Session(bind=test_engine) as db:
        assert db.scalar(select(func.count()).select_from(AuthEvent)) == count

    assert per_event_ms < MAX_INGEST_MS_PER_EVENT


# ---------------------------------------------------------------------------
# Part 15 — API latency against growing datasets
# ---------------------------------------------------------------------------

ENDPOINTS = [
    "/api/v1/events/",
    "/api/v1/alerts/",
    "/api/v1/attack-sessions/",
    "/api/v1/dashboard/summary",
    "/api/v1/attack-sessions/stats/active",
    "/api/v1/intelligence/indicators",
]


@pytest.mark.parametrize("records", [10, 100, 1000])
def test_api_latency_by_dataset_size(
    client,
    test_engine,
    records,
    record_property,
):
    _seed(test_engine, records)

    for endpoint in ENDPOINTS:
        start = time.perf_counter()
        response = client.get(endpoint)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert response.status_code == 200, endpoint

        print(
            f"\nBENCH api endpoint={endpoint} records={records} "
            f"ms={elapsed_ms:.2f}"
        )
        record_property(f"{endpoint}|{records}", round(elapsed_ms, 2))

        assert elapsed_ms < MAX_API_MS, f"{endpoint} took {elapsed_ms:.1f}ms"
