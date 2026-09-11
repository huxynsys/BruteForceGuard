"""Local threat-intelligence provider (Phase 7, section 7.5 / 7.6).

Fully deterministic and works without Internet access.  ``lookup_ip``
and ``lookup_username`` match against the local ``ThreatIndicator`` store.
"""

import ipaddress
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.intelligence.provider import ThreatIntelProvider
from app.intelligence.repository import ThreatIndicatorRepository
from app.intelligence.schemas import ThreatIntelLookup

logger = logging.getLogger(__name__)


class LocalThreatIntelProvider(ThreatIntelProvider):

    source = "local"

    def __init__(self, db: Session | None = None):
        self.db = db
        self.repository: ThreatIndicatorRepository | None = (
            ThreatIndicatorRepository(db) if db is not None else None
        )

    def is_available(self) -> bool:
        return self.repository is not None

    @staticmethod
    def _indicator_type(value: str) -> str:
        try:
            ip = ipaddress.ip_address(value)
            return "ipv6" if ip.version == 6 else "ipv4"
        except ValueError:
            if "." in value and ":" in value:
                return "domain"
            if " " not in value and all(
                c.isalnum() or c in "-._" for c in value
            ):
                return "domain"
            return "username"

    def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str,
    ) -> ThreatIntelLookup:
        if self.repository is None:
            return ThreatIntelLookup(
                indicator=indicator,
                indicator_type=indicator_type,
                known=False,
            )

        result = self.repository.find_active(indicator, indicator_type)

        if result is None:
            return ThreatIntelLookup(
                indicator=indicator,
                indicator_type=indicator_type,
                known=False,
            )

        categories = list(result.tags or [])

        if result.threat_type:
            categories.append(result.threat_type)

        self.repository.record_observation(result.id)

        return ThreatIntelLookup(
            indicator=indicator,
            indicator_type=indicator_type,
            known=True,
            confidence=result.confidence,
            categories=categories,
            threat_type=result.threat_type,
            source=result.source,
        )

    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        indicator_type = self._indicator_type(ip)
        if indicator_type not in ("ipv4", "ipv6"):
            return ThreatIntelLookup(
                indicator=ip, indicator_type="ipv4", known=False,
            )
        return self.lookup_indicator(ip, indicator_type)

    def lookup_domain(self, domain: str) -> ThreatIntelLookup:
        return self.lookup_indicator(domain, "domain")

    def lookup_username(self, username: str) -> ThreatIntelLookup:
        return self.lookup_indicator(username, "username")