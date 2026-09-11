"""Threat-intelligence provider abstraction (Phase 7, section 7.5).

The core detection engine never depends on an external vendor.  Providers
are pluggable behind this interface so an external provider can be added
later while the system remains deterministic and testable with the local
provider.
"""

from abc import ABC, abstractmethod
from typing import Optional

from app.intelligence.schemas import ThreatIntelLookup


class ThreatIntelProvider(ABC):
    """Interface every intelligence provider must implement."""

    source: str = "unknown"

    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        ...

    @abstractmethod
    def lookup_domain(self, domain: str) -> ThreatIntelLookup:
        ...

    @abstractmethod
    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelLookup:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...


class UnavailableProvider(ThreatIntelProvider):
    """Fallback used when no provider can be reached.

    Returns a never-known result so InteligenceService can fail soft.
    """

    source = "unavailable"

    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(
            indicator=ip, indicator_type="ipv4", known=False,
        )

    def lookup_domain(self, domain: str) -> ThreatIntelLookup:
        return ThreatIntelLookup(
            indicator=domain, indicator_type="domain", known=False,
        )

    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelLookup:
        return ThreatIntelLookup(
            indicator=indicator,
            indicator_type=indicator_type,
            known=False,
        )

    def is_available(self) -> bool:
        return False