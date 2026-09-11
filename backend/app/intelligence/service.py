"""Security-intelligence orchestration (Phase 7).

Wires together the local threat-intelligence provider, behavioral
reputation, MITRE mapping and deterministic risk scoring into a single
best-effort enrich-and-score service used by the event pipeline.

All enrichment is best-effort: a provider failure or an unexpected error
must never break detection, alert creation, session processing or event
ingestion (sections 7.25 / 7.40).
"""

import logging

from sqlalchemy.orm import Session

from app.intelligence.config import (
    is_privileged_user,
    service_sensitivity,
)
from app.intelligence.local_provider import LocalThreatIntelProvider
from app.intelligence.mitre import get_mitre_context
from app.intelligence.provider import ThreatIntelProvider
from app.intelligence.reputation import ReputationService
from app.intelligence.risk import RiskScorer
from app.intelligence.schemas import (
    MitreContext,
    ReputationResult,
    RiskResultSchema,
    ThreatIntelLookup,
)
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent

logger = logging.getLogger(__name__)


class IntelligenceService:
    """Best-effort enrichment and explainable risk scoring."""

    def __init__(
        self,
        db: Session,
        provider: ThreatIntelProvider | None = None,
    ):
        self.db = db
        # Fall back to a local provider when none is supplied.  A provider
        # is never allowed to break detection (7.25).
        self.provider: ThreatIntelProvider = provider or LocalThreatIntelProvider(db)
        self.reputation_service = ReputationService(db)
        self.risk_scorer = RiskScorer()

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------
    def lookup_ip(self, ip: str) -> ThreatIntelLookup:
        try:
            if not self.provider.is_available():
                return ThreatIntelLookup(
                    indicator=ip, indicator_type="ipv4", known=False,
                )
            return self.provider.lookup_ip(ip)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("intelligence provider lookup failed: %s", exc)
            return ThreatIntelLookup(
                indicator=ip, indicator_type="ipv4", known=False,
            )

    def lookup_username(self, username: str) -> ThreatIntelLookup:
        try:
            if not self.provider.is_available():
                return ThreatIntelLookup(
                    indicator=username,
                    indicator_type="username",
                    known=False,
                )
            return self.provider.lookup_indicator(username, "username")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("intelligence provider lookup failed: %s", exc)
            return ThreatIntelLookup(
                indicator=username, indicator_type="username", known=False,
            )

    def get_reputation(self, source_ip: str | None) -> ReputationResult | None:
        if not source_ip:
            return None
        try:
            return self.reputation_service.get_reputation(source_ip)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("reputation calculation failed: %s", exc)
            return None

    def get_mitre(self, detection_type: str | None) -> MitreContext:
        return get_mitre_context(detection_type)
# ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def score_alert(
        self,
        alert: Alert,
        *,
        reputation_level: str | None = None,
    ) -> RiskResultSchema:
        evidence = alert.evidence or {}

        failure_count = evidence.get("failure_count") or 0
        if isinstance(failure_count, str):
            try:
                failure_count = int(failure_count)
            except ValueError:  # pragma: no cover - defensive
                failure_count = 0

        distinct_users = evidence.get("distinct_users") or 0
        if isinstance(distinct_users, str):
            try:
                distinct_users = int(distinct_users)
            except ValueError:  # pragma: no cover - defensive
                distinct_users = 0

        distinct_services = len(evidence.get("services") or [])
        if evidence.get("distinct_services"):
            distinct_services = int(evidence["distinct_services"])

        ti = self.lookup_ip(str(alert.source_ip)) if alert.source_ip else None

        username_ti = (
            self.lookup_username(alert.username) if alert.username else None
        )
        ti_known = bool(ti and ti.known) or bool(username_ti and username_ti.known)
        ti_confidence = (
            ti.confidence
            if ti and ti.known
            else username_ti.confidence
            if username_ti and username_ti.known
            else None
        )

        return self.risk_scorer.score(
            severity=alert.severity,
            confidence=alert.confidence,
            failure_count=failure_count,
            distinct_users=distinct_users,
            distinct_services=distinct_services,
            source_reputation_level=reputation_level,
            ti_known=ti_known,
            ti_confidence=ti_confidence,
            ti_source="local" if ti_known else None,
            privileged_user=is_privileged_user(alert.username),
            service_sensitivity=service_sensitivity(alert.service),
        )

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------
    def enrich_alert(
        self,
        alert: Alert,
        event: AuthEvent | None = None,
    ) -> Alert:
        """Compute and persist intelligence context on an alert (7.12)."""
        try:
            reputation = self.get_reputation(str(alert.source_ip))
            risk = self.score_alert(
                alert,
                reputation_level=(
                    reputation.internal_reputation_level
                    if reputation else None
                ),
            )
            mitre = self.get_mitre(alert.alert_type)

            ti = self.lookup_ip(str(alert.source_ip)) if alert.source_ip else None

            alert.risk_score = risk.risk_score
            alert.risk_level = risk.risk_level
            alert.risk_factors = [
                factor.model_dump() for factor in risk.risk_factors
            ]

            if ti is not None:
                alert.threat_intelligence = {
                    "known": ti.known,
                    "confidence": ti.confidence,
                    "categories": ti.categories,
                    "threat_type": ti.threat_type,
                    "source": ti.source,
                }

            if reputation is not None:
                alert.source_reputation = {
                    "internal_reputation_score": (
                        reputation.internal_reputation_score
                    ),
                    "internal_reputation_level": (
                        reputation.internal_reputation_level
                    ),
                    "failure_rate": reputation.failure_rate,
                    "unique_usernames": reputation.unique_usernames,
                    "unique_services": reputation.unique_services,
                    "attack_sessions": reputation.attack_sessions,
                    "alert_count": reputation.alert_count,
                }

            alert.mitre_context = {
                "technique_id": mitre.technique_id,
                "technique_name": mitre.technique_name,
                "tactic": mitre.tactic,
                "description": mitre.description,
                "is_mapped": mitre.is_mapped,
            }

            self.db.commit()
            self.db.refresh(alert)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "alert enrichment failed (alert %s): %s",
                getattr(alert, "id", "?"),
                exc,
            )

        return alert

    def enrich_session(
        self,
        session: AttackSession,
    ) -> AttackSession:
        """Compute and persist aggregated session risk (section 7.13)."""
        try:
            severity = session.severity
            confidence = self._session_confidence(session)

            reputation_levels = []
            for source_ip in session.source_ips or []:
                reputation = self.get_reputation(str(source_ip))
                if reputation:
                    reputation_levels.append(
                        reputation.internal_reputation_level,
                    )

            risk = self.risk_scorer.score(
                severity=severity,
                confidence=confidence,
                failure_count=session.event_count or 0,
                distinct_users=len(session.usernames or []),
                distinct_services=len(session.services or []),
                source_reputation_level=(
                    max(reputation_levels) if reputation_levels else None
                ),
                ti_known=False,
                privileged_user=any(
                    is_privileged_user(u) for u in (session.usernames or [])
                ),
                service_sensitivity=(
                    service_sensitivity(session.services[0])
                    if session.services else "unknown"
                ),
            )

            session.risk_score = risk.risk_score
            session.risk_level = risk.risk_level
            session.risk_factors = [
                factor.model_dump() for factor in risk.risk_factors
            ]

            session.behavioral_profile = {
                "unique_source_ips": len(session.source_ips or []),
                "unique_usernames": len(session.usernames or []),
                "unique_services": len(session.services or []),
                "detection_types": session.detection_types or [],
                "source_reputation_levels": reputation_levels,
            }

            self.db.commit()
            self.db.refresh(session)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "session enrichment failed (session %s): %s",
                getattr(session, "id", "?"),
                exc,
            )

        return session

    @staticmethod
    def _session_confidence(session: AttackSession) -> int:
        """Aggregate a deterministic confidence for a session."""
        events = session.event_count or 0
        if events >= 20:
            return 90
        if events >= 10:
            return 80
        if events >= 5:
            return 70
        return 60

