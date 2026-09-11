"""Phase 7 - threat-intelligence provider, repository and local provider.

Covers criteria 7.1-7.6:
7.1  Security-intelligence module exists.
7.2  Threat-intelligence provider abstraction exists.
7.3  Local provider works without Internet access.
7.4  Indicators can be stored and retrieved.
7.5  Indicator types are validated.
7.6  Intelligence lookup failure does not break detection.
"""

import pytest
from sqlalchemy.orm import Session

from app.intelligence.local_provider import LocalThreatIntelProvider
from app.intelligence.provider import ThreatIntelProvider, UnavailableProvider
from app.intelligence.repository import ThreatIndicatorRepository
from app.intelligence.schemas import ThreatIndicatorCreate, ThreatIntelLookup
from app.models.threat_indicator import ThreatIndicator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def repository(db: Session) -> ThreatIndicatorRepository:
    return ThreatIndicatorRepository(db)


@pytest.fixture()
def provider(db: Session) -> LocalThreatIntelProvider:
    return LocalThreatIntelProvider(db)


@pytest.fixture()
def sample_indicator(repository: ThreatIndicatorRepository) -> ThreatIndicator:
    return repository.create(
        ThreatIndicatorCreate(
            indicator="203.0.113.50",
            indicator_type="ipv4",
            confidence=90,
            threat_type="brute_force",
            source="test",
            tags=["scanner", "attacker"],
            active=True,
        )
    )


# ---------------------------------------------------------------------------
# 7.2 Provider abstraction exists
# ---------------------------------------------------------------------------
def test_threat_intel_provider_is_abstract():
    assert hasattr(ThreatIntelProvider, "lookup_ip")
    assert hasattr(ThreatIntelProvider, "lookup_domain")
    assert hasattr(ThreatIntelProvider, "lookup_indicator")
    assert hasattr(ThreatIntelProvider, "is_available")


def test_unavailable_provider_returns_not_known():
    prov = UnavailableProvider()
    result = prov.lookup_ip("1.2.3.4")
    assert result.known is False
    assert result.indicator == "1.2.3.4"


def test_unavailable_provider_is_available_returns_false():
    assert UnavailableProvider().is_available() is False


# ---------------------------------------------------------------------------
# 7.3 Local provider works without Internet access
# ---------------------------------------------------------------------------
def test_local_provider_is_available_with_db(provider: LocalThreatIntelProvider):
    assert provider.is_available() is True


def test_local_provider_source_is_local(provider: LocalThreatIntelProvider):
    assert provider.source == "local"


def test_local_provider_unknown_ip_returns_not_known(
    provider: LocalThreatIntelProvider,
):
    result = provider.lookup_ip("198.51.100.1")
    assert result.known is False
    assert result.indicator == "198.51.100.1"
    assert result.indicator_type == "ipv4"


def test_local_provider_known_ip_returns_match(
    provider: LocalThreatIntelProvider,
    sample_indicator: ThreatIndicator,
):
    result = provider.lookup_ip("203.0.113.50")
    assert result.known is True
    assert result.confidence == 90
    assert result.source == "test"
    assert "brute_force" in result.categories

def test_local_provider_lookup_username(
    repository: ThreatIndicatorRepository,
):
    repository.create(
        ThreatIndicatorCreate(
            indicator="attacker_user",
            indicator_type="username",
            confidence=80,
            threat_type="compromised",
        )
    )
    prov = LocalThreatIntelProvider(repository.db)
    result = prov.lookup_username("attacker_user")
    assert result.known is True
    assert result.indicator_type == "username"
    assert result.confidence == 80


def test_local_provider_lookup_domain(
    repository: ThreatIndicatorRepository,
):
    repository.create(
        ThreatIndicatorCreate(
            indicator="evil.example.com",
            indicator_type="domain",
            confidence=70,
            threat_type="c2",
        )
    )
    prov = LocalThreatIntelProvider(repository.db)
    result = prov.lookup_domain("evil.example.com")
    assert result.known is True
    assert result.indicator_type == "domain"


def test_local_provider_inactive_indicator_not_matched(
    repository: ThreatIndicatorRepository,
):
    repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.5",
            indicator_type="ipv4",
            confidence=50,
            active=False,
        )
    )
    prov = LocalThreatIntelProvider(repository.db)
    result = prov.lookup_ip("10.0.0.5")
    assert result.known is False


def test_local_provider_case_insensitive_match(
    repository: ThreatIndicatorRepository,
):
    repository.create(
        ThreatIndicatorCreate(
            indicator="mixedcase.example.com",
            indicator_type="domain",
            confidence=60,
        )
    )
    prov = LocalThreatIntelProvider(repository.db)
    result = prov.lookup_domain("MixedCase.Example.Com")
    assert result.known is True

# ---------------------------------------------------------------------------
# 7.4 Indicators can be stored and retrieved
# ---------------------------------------------------------------------------
def test_create_indicator_persists(repository: ThreatIndicatorRepository):
    created = repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.1",
            indicator_type="ipv4",
            confidence=75,
            threat_type="scanner",
            source="manual",
            tags=["auto"],
        )
    )
    assert created.id is not None
    assert created.indicator == "10.0.0.1"
    assert created.active is True


def test_get_indicator_by_id(
    repository: ThreatIndicatorRepository,
    sample_indicator: ThreatIndicator,
):
    fetched = repository.get(sample_indicator.id)
    assert fetched is not None
    assert fetched.indicator == "203.0.113.50"


def test_list_indicators(
    repository: ThreatIndicatorRepository,
    sample_indicator: ThreatIndicator,
):
    repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.2",
            indicator_type="ipv4",
            confidence=50,
        )
    )
    results = repository.list_indicators()
    assert len(results) == 2


def test_list_indicators_filter_by_type(repository: ThreatIndicatorRepository):
    repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.3",
            indicator_type="ipv4",
            confidence=50,
        )
    )
    repository.create(
        ThreatIndicatorCreate(
            indicator="user1",
            indicator_type="username",
            confidence=50,
        )
    )
    results = repository.list_indicators(indicator_type="ipv4")
    assert len(results) == 1
    assert results[0].indicator_type == "ipv4"


def test_list_indicators_active_only(repository: ThreatIndicatorRepository):
    repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.4",
            indicator_type="ipv4",
            confidence=50,
            active=True,
        )
    )
    repository.create(
        ThreatIndicatorCreate(
            indicator="10.0.0.5",
            indicator_type="ipv4",
            confidence=50,
            active=False,
        )
    )
    results = repository.list_indicators(active_only=True)
    assert len(results) == 1
    assert results[0].indicator == "10.0.0.4"


def test_delete_indicator(
    repository: ThreatIndicatorRepository,
    sample_indicator: ThreatIndicator,
):
    deleted = repository.delete(sample_indicator.id)
    assert deleted is True
    assert repository.get(sample_indicator.id) is None


def test_delete_nonexistent_indicator(repository: ThreatIndicatorRepository):
    assert repository.delete(9999) is False


def test_record_observation_updates_last_seen(
    repository: ThreatIndicatorRepository,
    sample_indicator: ThreatIndicator,
):
    assert sample_indicator.last_seen is None
    repository.record_observation(sample_indicator.id)
    refreshed = repository.get(sample_indicator.id)
    assert refreshed is not None
    assert refreshed.last_seen is not None

# ---------------------------------------------------------------------------
# 7.5 Indicator types are validated
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "indicator_type",
    ["ipv4", "ipv6", "domain", "username"],
)
def test_valid_indicator_types(repository: ThreatIndicatorRepository, indicator_type: str):
    created = repository.create(
        ThreatIndicatorCreate(
            indicator="test-value",
            indicator_type=indicator_type,
            confidence=50,
        )
    )
    assert created.indicator_type == indicator_type


def test_invalid_indicator_type_rejected(repository: ThreatIndicatorRepository):
    with pytest.raises(Exception):
        repository.create(
            ThreatIndicatorCreate(
                indicator="test",
                indicator_type="invalid_type",
                confidence=50,
            )
        )


# ---------------------------------------------------------------------------
# 7.6 Intelligence lookup failure does not break detection
# ---------------------------------------------------------------------------
def test_provider_without_db_returns_not_known():
    prov = LocalThreatIntelProvider(None)
    result = prov.lookup_ip("1.2.3.4")
    assert result.known is False


def test_provider_is_available_without_db():
    prov = LocalThreatIntelProvider(None)
    assert prov.is_available() is False


def test_lookup_indicator_generic(
    provider: LocalThreatIntelProvider,
    sample_indicator: ThreatIndicator,
):
    result = provider.lookup_indicator("203.0.113.50", "ipv4")
    assert result.known is True
    assert result.confidence == 90
