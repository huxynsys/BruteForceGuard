"""Phase 7 - IntelligenceService enrichment integration tests.

Covers:
7.12  Alert enrichment (risk score, MITRE context, threat-intel, reputation)
7.13  Attack-session enrichment (aggregated risk + behavioral profile)
7.25  Best-effort: provider / reputation failures never break enrichment
"""

import pytest
from unittest.mock import MagicMock

from app.intelligence.provider import ThreatIntelLookup
from app.intelligence.schemas import ReputationResult
from app.intelligence.service import IntelligenceService


class StubProvider:
    """Deterministic stand-in for ThreatIntelProvider."""

    def __init__(self) -> None:
        self.available = True
        self.fail_lookup = False
        self.lookup_ip_result = ThreatIntelLookup(
            indicator="10.0.0.1",
            indicator_type="ipv4",
            known=False,
        )
        self.lookup_indicator_result = ThreatIntelLookup(
            indicator="admin",
            indicator_type="username",
            known=False,
        )

    def is_available(self) -> bool:
        return self.available

    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        if self.fail_lookup:
            raise RuntimeError("provider boom")
        self.lookup_ip_result.indicator = ip
        return self.lookup_ip_result

    def lookup_indicator(self, value: str, indicator_type: str) -> ThreatIntelLookup:
        if self.fail_lookup:
            raise RuntimeError("provider boom")
        self.lookup_indicator_result.indicator = value
        self.lookup_indicator_result.indicator_type = indicator_type
        return self.lookup_indicator_result


@pytest.fixture
def stub_provider() -> StubProvider:
    return StubProvider()


@pytest.fixture
def intelligence_service(db, stub_provider) -> IntelligenceService:
    return IntelligenceService(db=db, provider=stub_provider)


# ---------------------------------------------------------------------------
# 7.12 Alert enrichment
# ---------------------------------------------------------------------------

def test_enrich_alert_with_threat_intel_and_mitre(
    intelligence_service: IntelligenceService,
    stub_provider: StubProvider,
    alert_factory,
):
    stub_provider.lookup_ip_result = ThreatIntelLookup(
        indicator="10.0.0.1",
        indicator_type="ipv4",
        known=True,
        confidence=80,
        threat_type="malicious",
        source="external_ti",
    )

    alert = alert_factory(
        alert_type="single_account_bruteforce",
        severity="high",
        source_ip="10.0.0.1",
        username="root",
        service="ssh",
    )

    enriched = intelligence_service.enrich_alert(alert)

    assert enriched.risk_score > 0
    assert enriched.risk_level in {"informational", "low", "medium", "high", "critical"}
    assert enriched.mitre_context is not None
    assert enriched.mitre_context["is_mapped"] is True
    assert enriched.mitre_context["technique_id"] == "T1110.001"
    assert enriched.threat_intelligence is not None
    assert enriched.threat_intelligence["known"] is True
    assert enriched.threat_intelligence["confidence"] == 80
    assert enriched.source_reputation is not None
    assert "internal_reputation_score" in enriched.source_reputation

    reasons = " ".join(f["reason"] for f in enriched.risk_factors)
    assert "Privileged account targeted" in reasons
    assert "high-sensitivity service" in reasons
    assert "Known indicator from local (confidence 80%)" in reasons


def test_enrich_alert_unknown_source_still_maps_mitre_and_risk(
    intelligence_service: IntelligenceService,
    alert_factory,
):
    alert = alert_factory(
        alert_type="low_and_slow",
        severity="medium",
        source_ip="198.51.100.1",
        username="bob",
        service="ftp",
    )

    enriched = intelligence_service.enrich_alert(alert)

    # No TI match, but MITRE and risk context are still persisted.
    assert enriched.threat_intelligence is not None
    assert enriched.threat_intelligence["known"] is False
    assert enriched.mitre_context is not None
    assert enriched.mitre_context["is_mapped"] is True
    assert enriched.mitre_context["technique_id"] == "T1110"
    assert enriched.risk_score > 0
    # 20 (severity) + 14 (confidence) + 4 (ftp sensitivity) = 38 -> low
    assert enriched.risk_score == 38
    assert enriched.risk_level == "low"
    assert any(f["factor"] == "threat_intelligence" and f["value"] == 0
               for f in enriched.risk_factors)


def test_enrich_alert_ti_lookup_failure_is_best_effort(
    intelligence_service: IntelligenceService,
    stub_provider: StubProvider,
    alert_factory,
):
    stub_provider.fail_lookup = True

    alert = alert_factory(
        alert_type="single_account_bruteforce",
        severity="low",
        source_ip="10.0.0.1",
        username="alice",
        service="web",
    )

    # Provider raising must not break alert enrichment (7.25).
    enriched = intelligence_service.enrich_alert(alert)

    assert enriched is alert
    assert enriched.threat_intelligence is not None
    assert enriched.threat_intelligence["known"] is False
    assert enriched.mitre_context["is_mapped"] is True
    assert enriched.risk_score > 0


def test_enrich_alert_unknown_detection_type_fails_safely(
    intelligence_service: IntelligenceService,
    alert_factory,
):
    alert = alert_factory(
        alert_type="totally_unknown_detection",
        severity="informational",
        source_ip="10.0.0.1",
        username="alice",
        service="web",
    )

    enriched = intelligence_service.enrich_alert(alert)

    assert enriched.mitre_context is not None
    assert enriched.mitre_context["is_mapped"] is False
    assert enriched.risk_level == "informational"


# ---------------------------------------------------------------------------
# 7.13 Attack-session enrichment
# ---------------------------------------------------------------------------

def test_enrich_session_aggregates_reputation_and_risk(
    intelligence_service: IntelligenceService,
    session_factory,
):
    intelligence_service.reputation_service.get_reputation = MagicMock(
        return_value=ReputationResult(
            source_ip="10.0.0.1",
            internal_reputation_score=50,
            internal_reputation_level="suspicious",
        )
    )

    session = session_factory(
        session_type="password_spray",
        severity="high",
        event_count=8,
        source_ips=["10.0.0.1"],
        usernames=["user1"],
        services=["ssh"],
        detection_types=["password_spraying"],
    )

    enriched = intelligence_service.enrich_session(session)

    assert enriched.risk_score > 0
    assert enriched.risk_level in {"low", "medium", "high", "critical"}
    assert enriched.behavioral_profile is not None
    assert enriched.behavioral_profile["unique_source_ips"] == 1
    assert enriched.behavioral_profile["unique_usernames"] == 1
    assert enriched.behavioral_profile["unique_services"] == 1
    assert enriched.behavioral_profile["source_reputation_levels"] == ["suspicious"]
    assert enriched.behavioral_profile["detection_types"] == ["password_spraying"]
    assert enriched.risk_factors  # non-empty
    assert sum(f["value"] for f in enriched.risk_factors) == enriched.risk_score


def test_enrich_session_privileged_user_and_sensitive_service(
    intelligence_service: IntelligenceService,
    session_factory,
):
    session = session_factory(
        session_type="single_account",
        severity="critical",
        event_count=10,
        source_ips=["10.0.0.1"],
        usernames=["root"],
        services=["vpn"],
        detection_types=["single_account_bruteforce"],
    )

    enriched = intelligence_service.enrich_session(session)

    reasons = " ".join(f["reason"] for f in enriched.risk_factors)
    assert "Privileged account targeted" in reasons
    assert "high-sensitivity service" in reasons
    # 40 (critical) + 16 (conf 80%) + 4 (behaviour) + 0 (TI) + 10 (sens) = 70
    assert enriched.risk_score == 70
    assert enriched.risk_level == "high"


def test_enrich_session_reputation_failure_is_best_effort(
    intelligence_service: IntelligenceService,
    session_factory,
):
    # Reputation service raising must not break session enrichment (7.25).
    intelligence_service.reputation_service.get_reputation = MagicMock(
        side_effect=Exception("reputation boom")
    )

    session = session_factory(
        session_type="distributed",
        severity="medium",
        event_count=12,
        source_ips=["10.0.0.1", "10.0.0.2"],
        usernames=["alice", "bob"],
        services=["web"],
        detection_types=["distributed_bruteforce"],
    )

    enriched = intelligence_service.enrich_session(session)

    assert enriched is session
    assert enriched.behavioral_profile is not None
    assert enriched.behavioral_profile["source_reputation_levels"] == []
    assert enriched.risk_factors  # other factors still computed
    assert enriched.risk_score > 0


# ---------------------------------------------------------------------------
# Session confidence helper (feed for 7.13 scoring)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "event_count,expected",
    [
        (0, 60),
        (1, 60),
        (3, 60),
        (4, 60),
        (5, 70),
        (8, 70),
        (10, 80),
        (19, 80),
        (20, 90),
        (25, 90),
        (None, 60),
    ],
)
def test_session_confidence_calculation(event_count, expected):
    session = MagicMock()
    session.event_count = event_count
    assert IntelligenceService._session_confidence(session) == expected