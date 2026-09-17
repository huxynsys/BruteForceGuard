"""Phase 8 Parts 12 and 13 — intelligence overhead and duplicate lookups.

Part 13 explicitly asks whether the intelligence layer performs redundant
work (for example re-querying the same source IP).  The counting provider
below turns that question into an assertion rather than an opinion.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import insert

from app.intelligence.local_provider import LocalThreatIntelProvider
from app.intelligence.provider import ThreatIntelProvider, UnavailableProvider
from app.intelligence.schemas import ThreatIntelLookup
from app.intelligence.service import IntelligenceService
from app.models.auth_event import AuthEvent
from app.models.threat_indicator import ThreatIndicator


class CountingProvider(ThreatIntelProvider):
    """Wraps another provider and counts every lookup it performs."""

    source = "counting"

    def __init__(self, inner: ThreatIntelProvider):
        self.inner = inner
        self.ip_calls = 0
        self.indicator_calls = 0
        self.domain_calls = 0
        self.availability_checks = 0

    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        self.ip_calls += 1
        return self.inner.lookup_ip(ip)

    def lookup_domain(self, domain: str) -> ThreatIntelLookup:
        self.domain_calls += 1
        return self.inner.lookup_domain(domain)

    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelLookup:
        self.indicator_calls += 1
        return self.inner.lookup_indicator(indicator, indicator_type)

    def is_available(self) -> bool:
        self.availability_checks += 1
        return self.inner.is_available()


# ---------------------------------------------------------------------------
# Part 13 — no duplicate intelligence lookups
# ---------------------------------------------------------------------------


def test_enrich_alert_performs_exactly_one_ip_lookup(db, alert_factory):
    """Phase 7 Part 4: the IP is resolved once and reused for risk/MITRE."""
    provider = CountingProvider(LocalThreatIntelProvider(db))
    service = IntelligenceService(db, provider=provider)

    alert = alert_factory(
        source_ip="203.0.113.5",
        username="admin",
        evidence={"failure_count": 6},
    )

    service.enrich_alert(alert)

    assert provider.ip_calls == 1
    assert provider.availability_checks >= 1


def test_enrich_alert_reuses_one_lookup_for_username_too(db, alert_factory):
    provider = CountingProvider(LocalThreatIntelProvider(db))
    service = IntelligenceService(db, provider=provider)

    alert = alert_factory(
        source_ip="203.0.113.6",
        username="admin",
        evidence={"failure_count": 6},
    )

    service.enrich_alert(alert)

    # One IP lookup + at most one username lookup; never one-per-call-site.
    assert provider.ip_calls == 1
    assert provider.indicator_calls <= 1


def test_ip_lookup_is_shared_across_risk_and_enrichment(db, alert_factory):
    """Scoring an alert directly must not double the provider traffic."""
    provider = CountingProvider(LocalThreatIntelProvider(db))
    service = IntelligenceService(db, provider=provider)

    alert = alert_factory(source_ip="203.0.113.7")

    ip_result = service.lookup_ip("203.0.113.7")
    service.score_alert(alert, ti=ip_result)

    assert provider.ip_calls == 1


def test_session_enrichment_does_not_repeat_ip_lookups(db, session_factory):
    """A session with repeated source IPs must look each one up once."""
    provider = CountingProvider(LocalThreatIntelProvider(db))
    service = IntelligenceService(db, provider=provider)

    session = session_factory(
        event_count=10,
        source_ips=["203.0.113.1", "203.0.113.2", "203.0.113.1"],
        usernames=["admin", "root"],
        services=["ssh"],
        detection_types=["single_account"],
    )

    service.enrich_session(session)

    # Reputation is derived from stored history, so the provider is not
    # consulted per IP during session aggregation (only risk scoring runs).
    assert provider.ip_calls == 0
    assert session.behavioral_profile["unique_source_ips"] == 3
    assert session.behavioral_profile["unique_usernames"] == 2


# ---------------------------------------------------------------------------
# Part 12 — measured intelligence overhead
# ---------------------------------------------------------------------------

ALERTS_PER_RUN = 60


def test_intelligence_overhead_per_alert(db, alert_factory, record_property):
    """Compare enrichment with no provider against the local provider."""
    baseline_alerts = [
        alert_factory(evidence={"failure_count": 6})
        for _ in range(ALERTS_PER_RUN)
    ]
    enriched_alerts = [
        alert_factory(evidence={"failure_count": 6})
        for _ in range(ALERTS_PER_RUN)
    ]

    # (a) provider unavailable -> enrichment still runs, no TI signal
    cheap = IntelligenceService(db, provider=UnavailableProvider())
    start = time.perf_counter()
    for alert in baseline_alerts:
        cheap.enrich_alert(alert)
    baseline_ms = (time.perf_counter() - start) / ALERTS_PER_RUN * 1000

    # (b) a real local indicator so the TI path does genuine work
    db.add(
        ThreatIndicator(
            indicator="10.0.0.1",
            indicator_type="ipv4",
            confidence=90,
            threat_type="brute_force",
            source="perf",
            tags=["brute_force"],
            active=True,
        )
    )
    db.commit()

    full = IntelligenceService(db, provider=LocalThreatIntelProvider(db))
    start = time.perf_counter()
    for alert in enriched_alerts:
        full.enrich_alert(alert)
    enriched_ms = (time.perf_counter() - start) / ALERTS_PER_RUN * 1000

    overhead_ms = enriched_ms - baseline_ms

    record_property("alerts", ALERTS_PER_RUN)
    record_property("baseline_ms_per_alert", round(baseline_ms, 3))
    record_property("enriched_ms_per_alert", round(enriched_ms, 3))
    record_property("overhead_ms_per_alert", round(overhead_ms, 3))

    print(
        f"\nBENCH intelligence_overhead alerts={ALERTS_PER_RUN} "
        f"baseline_ms={baseline_ms:.2f} "
        f"enriched_ms={enriched_ms:.2f} "
        f"overhead_ms={overhead_ms:.2f}"
    )

    assert enriched_ms < 100.0
    # The TI signal must actually have been applied.
    assert any(a.threat_intelligence for a in enriched_alerts)


def _seed_history(db, source_ip: str, count: int) -> None:
    base = datetime.now(timezone.utc)
    db.execute(
        insert(AuthEvent),
        [
            {
                "timestamp": base,
                "source": "perf",
                "source_ip": source_ip,
                "username": f"user{i % 5}",
                "result": "failure",
                "service": "ssh",
                "port": 22,
            }
            for i in range(count)
        ],
    )
    db.commit()


@pytest.mark.parametrize("history", [10, 500])
def test_reputation_lookup_cost_by_history(db, history, record_property):
    _seed_history(db, "203.0.113.99", history)

    start = time.perf_counter()
    result = IntelligenceService(db).get_reputation("203.0.113.99")
    elapsed_ms = (time.perf_counter() - start) * 1000

    record_property("history_events", history)
    record_property("reputation_ms", round(elapsed_ms, 3))

    print(f"\nBENCH reputation history={history} ms={elapsed_ms:.2f}")

    assert result is not None
    assert result.internal_reputation_score >= 0
    assert elapsed_ms < 500.0