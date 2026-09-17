"""Phase 8 Part 11 — detection throughput.

Measures the cost of running every detector over a stored event set,
separating seeding (database) time from detection time.

Ceilings are deliberately generous (10x+ expected values) so the suite
stays green on slow machines; the *recorded* numbers live in
``docs/performance/phase-8-benchmark-results.md``.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import insert, select

from app.core.detection_config import get_service_thresholds
from app.models.auth_event import AuthEvent
from app.services.detection_service import DetectionService

# Generous guard rails: fail only on catastrophic regressions.
MAX_MS_PER_EVENT = 25.0


def _seed(db, count: int) -> None:
    """Bulk-insert ``count`` failed ssh events across many sources."""
    base = datetime.now(timezone.utc) - timedelta(hours=2)
    rows = []
    for i in range(count):
        rows.append(
            {
                "timestamp": base + timedelta(milliseconds=i * 10),
                "source": "bench",
                "source_ip": f"10.{i % 250}.{(i // 250) % 250}.{i % 200}",
                "username": f"user{i % 50}",
                "result": "failure",
                "service": "ssh",
                "port": 22,
            }
        )
    db.execute(insert(AuthEvent), rows)
    db.commit()


def _run_all_detectors(db, events) -> float:
    service = DetectionService(db)
    thresholds = get_service_thresholds("ssh")

    start = time.perf_counter()

    for event in events:
        service.detect_single_account_bruteforce(
            event,
            threshold=thresholds["failure_threshold"],
            window_seconds=thresholds["window_seconds"],
        )
        service.detect_password_spraying(
            event,
            minimum_users=thresholds["password_spray_users"],
            minimum_failures=thresholds["failure_threshold"] * 2,
            window_seconds=thresholds["window_seconds"],
        )
        service.detect_distributed_bruteforce(
            event,
            minimum_source_ips=thresholds["distributed_ips"],
            minimum_failures=thresholds["failure_threshold"] * 2,
            window_seconds=thresholds["window_seconds"],
        )
        service.detect_failed_then_success(
            event,
            minimum_failures=3,
            window_seconds=300,
        )
        service.detect_credential_stuffing(
            event,
            minimum_users=thresholds["credential_stuffing_users"],
            minimum_failures=thresholds["credential_stuffing_failures"],
            window_seconds=600,
        )
        service.detect_low_and_slow(
            event,
            minimum_failures=10,
            window_seconds=3600,
            minimum_active_intervals=5,
        )

    return time.perf_counter() - start


@pytest.mark.parametrize("count", [1000, 5000])
def test_detection_throughput(db, count, record_property):
    seed_start = time.perf_counter()
    _seed(db, count)
    seed_elapsed = time.perf_counter() - seed_start

    events = list(db.scalars(select(AuthEvent)))
    assert len(events) == count

    detection_elapsed = _run_all_detectors(db, events)

    per_event_ms = (detection_elapsed / count) * 1000
    throughput = count / detection_elapsed

    record_property("events", count)
    record_property("seed_seconds", round(seed_elapsed, 4))
    record_property("detection_seconds", round(detection_elapsed, 4))
    record_property("ms_per_event", round(per_event_ms, 4))
    record_property("detections_per_second", round(throughput, 2))

    print(
        f"\nBENCH detection events={count} "
        f"seed_s={seed_elapsed:.3f} "
        f"detect_s={detection_elapsed:.3f} "
        f"ms_per_event={per_event_ms:.3f} "
        f"events_per_sec={throughput:.1f}"
    )

    assert per_event_ms < MAX_MS_PER_EVENT