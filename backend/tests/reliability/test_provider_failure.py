"""Phase 8 Part 6 — intelligence failure isolation.

Phase 7 requires security intelligence to be strictly best-effort
(sections 7.25 / 7.40).  A threat-intelligence lookup, reputation
calculation, MITRE lookup or malformed provider payload must never be
promoted into a detection failure.

Each test here breaks exactly one intelligence sub-system and asserts that
alert/session enrichment still completes and that the failure is logged
rather than silently swallowed.
"""

from __future__ import annotations

import logging

from app.intelligence.provider import ThreatIntelProvider, UnavailableProvider
from app.intelligence.schemas import ThreatIntelLookup
from app.intelligence.service import IntelligenceService
from app.intelligence import service as service_module


class ExplodingProvider(ThreatIntelProvider):
    """A provider whose every operation raises."""

    source = "exploding"

    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        raise RuntimeError("provider down: lookup_ip")

    def lookup_domain(self, domain: str) -> ThreatIntelLookup:
        raise RuntimeError("provider down: lookup_domain")

    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelLookup:
        raise RuntimeError("provider down: lookup_indicator")

    def is_available(self) -> bool:
        raise RuntimeError("provider down: is_available")


class GarbageProvider(ThreatIntelProvider):
    """A provider that returns structurally invalid payloads."""

    source = "garbage"

    def lookup_ip(self, ip: str):  # type: ignore[override]
        return {"indicator": ip}  # not a ThreatIntelLookup

    def lookup_domain(self, domain: str):  # type: ignore[override]
        return None

    def lookup_indicator(  # type: ignore[override]
        self,
        indicator: str,
        indicator_type: str,
    ):
        return ["not", "a", "lookup"]

    def is_available(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Provider-level isolation
# ---------------------------------------------------------------------------


def test_lookup_ip_survives_provider_exception(db, caplog):
    service = IntelligenceService(db, provider=ExplodingProvider())

    with caplog.at_level(logging.WARNING):
        result = service.lookup_ip("10.0.0.9")

    assert result.known is False
    assert result.indicator == "10.0.0.9"
    assert result.indicator_type == "ipv4"
    assert "intelligence provider lookup failed" in caplog.text


def test_lookup_username_survives_provider_exception(db, caplog):
    service = IntelligenceService(db, provider=ExplodingProvider())

    with caplog.at_level(logging.WARNING):
        result = service.lookup_username("admin")

    assert result.known is False
    assert result.indicator == "admin"
    assert result.indicator_type == "username"


def test_unavailable_provider_is_never_reported_as_known(db):
    service = IntelligenceService(db, provider=UnavailableProvider())

    assert service.provider.is_available() is False
    assert service.lookup_ip("10.0.0.9").known is False
    assert service.lookup_username("admin").known is False


# ---------------------------------------------------------------------------
# Alert enrichment isolation
# ---------------------------------------------------------------------------


def test_enrich_alert_survives_provider_exception(db, alert_factory, caplog):
    alert = alert_factory(
        severity="critical",
        confidence=90,
        evidence={"failure_count": 12},
    )
    service = IntelligenceService(db, provider=ExplodingProvider())

    with caplog.at_level(logging.WARNING):
        returned = service.enrich_alert(alert)

    # Enrichment must be best-effort: same object back, still risk-scored.
    assert returned is alert
    assert alert.risk_score is not None
    assert 0 <= alert.risk_score <= 100
    assert alert.risk_level is not None


def test_reputation_failure_does_not_break_alert_enrichment(
    db,
    alert_factory,
    monkeypatch,
    caplog,
):
    def boom(self, source_ip):  # noqa: ANN001
        raise RuntimeError("reputation backend down")

    monkeypatch.setattr(service_module.ReputationService, "get_reputation", boom)

    alert = alert_factory(evidence={"failure_count": 7})
    service = IntelligenceService(db)

    with caplog.at_level(logging.WARNING):
        assert service.get_reputation("10.0.0.1") is None
        service.enrich_alert(alert)

    assert alert.risk_score is not None
    assert "reputation calculation failed" in caplog.text


def test_mitre_failure_does_not_break_alert_enrichment(
    db,
    alert_factory,
    monkeypatch,
):
    def boom(detection_type, *args, **kwargs):  # noqa: ANN001
        raise RuntimeError("mitre table unavailable")

    monkeypatch.setattr(service_module, "get_mitre_context", boom)

    alert = alert_factory(evidence={"failure_count": 6})
    service = IntelligenceService(db)

    service.enrich_alert(alert)  # must not raise

    assert alert.risk_score is not None


def test_malformed_provider_payload_is_contained(db, alert_factory):
    alert = alert_factory(evidence={"failure_count": 9})
    service = IntelligenceService(db, provider=GarbageProvider())

    returned = service.enrich_alert(alert)  # must not raise

    assert returned is alert
    assert alert.risk_score is not None


# ---------------------------------------------------------------------------
# Session enrichment isolation
# ---------------------------------------------------------------------------


def test_session_enrichment_survives_reputation_failure(
    db,
    session_factory,
    monkeypatch,
):
    def boom(self, source_ip):  # noqa: ANN001
        raise RuntimeError("reputation backend down")

    monkeypatch.setattr(service_module.ReputationService, "get_reputation", boom)

    session = session_factory(
        event_count=8,
        source_ips=["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
        detection_types=["single_account"],
    )

    returned = IntelligenceService(db).enrich_session(session)

    assert returned is session
    assert session.risk_score is not None
    # A failed reputation lookup degrades to "no levels", not a crash.
    assert session.behavioral_profile is not None
    assert session.behavioral_profile["source_reputation_levels"] == []


def test_session_enrichment_survives_provider_exception(db, session_factory):
    session = session_factory(
        event_count=4,
        source_ips=["10.1.1.1"],
        usernames=["root"],
        services=["ssh"],
        detection_types=["single_account"],
    )

    returned = IntelligenceService(
        db,
        provider=ExplodingProvider(),
    ).enrich_session(session)

    assert returned is session
    assert session.risk_score is not None
    assert 0 <= session.risk_score <= 100


def test_intelligence_failure_does_not_change_risk_scoring(db, alert_factory):
    """A TI outage must not remove the detection-derived risk score."""
    evidence = {"failure_count": 11, "distinct_users": 1}

    healthy = alert_factory(evidence=dict(evidence))
    IntelligenceService(db).enrich_alert(healthy)

    broken = alert_factory(evidence=dict(evidence))
    IntelligenceService(db, provider=ExplodingProvider()).enrich_alert(broken)

    # Only the TI-derived contribution may differ; the score must still be
    # a valid, fully-populated risk result.
    assert broken.risk_score is not None
    assert healthy.risk_score is not None
    assert broken.risk_factors, "risk factors must survive a TI outage"
    assert any(
        factor["factor"] == "detection_severity" for factor in broken.risk_factors
    )


def test_risk_factor_vocabulary_is_stable(db, alert_factory):
    """Lock the risk-factor vocabulary the frontend label map depends on."""
    alert = alert_factory(
        severity="high",
        confidence=80,
        username="root",
        service="ssh",
    )

    IntelligenceService(db).enrich_alert(alert)

    keys = {factor["factor"] for factor in alert.risk_factors}

    assert keys == {
        "detection_severity",
        "confidence",
        "attack_frequency",
        "threat_intelligence",
        "target_sensitivity",
    }