"""Explainable, deterministic risk scoring (Phase 7, sections 7.2-7.4).

The score is a weighted sum of explicit, individually-justified factors:

    base_detection        0-40
    confidence            0-20
    behavior              0-15
    threat_intelligence   0-15
    target_sensitivity    0-10
                         -------
    total                0-100

No opaque machine-learning model is involved; every contribution carries
a human-readable ``reason`` so an analyst (or examiner) can ask *why* a
score is what it is and receive a programmatic answer.
"""

from app.intelligence.config import (
    RISK_BEHAVIOR_WEIGHT,
    RISK_CONFIDENCE_WEIGHT,
    RISK_LEVELS,
    RISK_SENSITIVITY_WEIGHT,
    RISK_TI_WEIGHT,
    SEVERITY_RISK_BASE,
    risk_level_for_score,
)
from app.intelligence.schemas import RiskFactorSchema, RiskResultSchema


class RiskScorer:
    """Deterministic, explainable risk scorer."""

    def __init__(self) -> None:
        self._max_score = 100

    def base_detection_factor(self, severity: str) -> RiskFactorSchema:
        value = SEVERITY_RISK_BASE.get(
            (severity or "informational").lower(), 5
        )
        return RiskFactorSchema(
            factor="detection_severity",
            value=value,
            reason=f"{severity} severity detection".capitalize(),
        )

    def confidence_factor(self, confidence: int) -> RiskFactorSchema:
        value = round((max(0, min(100, confidence)) / 100) * RISK_CONFIDENCE_WEIGHT)
        return RiskFactorSchema(
            factor="confidence",
            value=value,
            reason=f"Detection confidence {confidence}%",
        )

    def behavior_factor(
        self,
        *,
        failure_count: int = 0,
        distinct_users: int = 0,
        distinct_services: int = 0,
        source_reputation_level: str | None = None,
    ) -> RiskFactorSchema:
        score = 0
        reasons: list[str] = []

        if failure_count >= 5:
            score += 4
            reasons.append(f"{failure_count} failed attempts")
        elif failure_count > 0:
            score += 2
        if distinct_users >= 5:
            score += 3
            reasons.append(f"{distinct_users} targeted accounts")
        elif distinct_users >= 2:
            score += 1
        if distinct_services >= 2:
            score += 2
            reasons.append(f"{distinct_services} targeted services")
        if source_reputation_level in ("high", "hostile"):
            score += 4
            reasons.append(f"source reputation {source_reputation_level}")

        score = min(score, RISK_BEHAVIOR_WEIGHT)
        reason = "; ".join(reasons) if reasons else "Limited behavioral context"

        return RiskFactorSchema(
            factor="attack_frequency",
            value=score,
            reason=reason,
        )

    def threat_intel_factor(
        self,
        *,
        known: bool = False,
        confidence: int | None = None,
        source: str | None = None,
    ) -> RiskFactorSchema:
        if not known:
            return RiskFactorSchema(
                factor="threat_intelligence",
                value=0,
                reason="No threat-intelligence match",
            )

        effective_confidence = 50 if confidence is None else confidence
        value = round((max(0, min(100, effective_confidence)) / 100) * RISK_TI_WEIGHT)
        return RiskFactorSchema(
            factor="threat_intelligence",
            value=value,
            reason=(
                f"Known indicator from {source or 'local'} "
                f"(confidence {effective_confidence}%)"
            ),
        )

    def sensitivity_factor(
        self,
        *,
        privileged_user: bool = False,
        service_sensitivity: str = "low",
    ) -> RiskFactorSchema:
        value = 0
        reasons: list[str] = []

        if privileged_user:
            value += 6
            reasons.append("Privileged account targeted")
        if service_sensitivity in ("high", "medium"):
            value += 4
            reasons.append(f"{service_sensitivity}-sensitivity service")

        value = min(value, RISK_SENSITIVITY_WEIGHT)
        reason = "; ".join(reasons) if reasons else "No target sensitivity signal"

        return RiskFactorSchema(
            factor="target_sensitivity",
            value=value,
            reason=reason,
        )

    def score(
        self,
        *,
        severity: str,
        confidence: int,
        failure_count: int = 0,
        distinct_users: int = 0,
        distinct_services: int = 0,
        source_reputation_level: str | None = None,
        ti_known: bool = False,
        ti_confidence: int | None = None,
        ti_source: str | None = None,
        privileged_user: bool = False,
        service_sensitivity: str = "low",
    ) -> RiskResultSchema:
        factors = [
            self.base_detection_factor(severity),
            self.confidence_factor(confidence),
            self.behavior_factor(
                failure_count=failure_count,
                distinct_users=distinct_users,
                distinct_services=distinct_services,
                source_reputation_level=source_reputation_level,
            ),
            self.threat_intel_factor(
                known=ti_known,
                confidence=ti_confidence,
                source=ti_source,
            ),
            self.sensitivity_factor(
                privileged_user=privileged_user,
                service_sensitivity=service_sensitivity,
            ),
        ]

        total = sum(factor.value for factor in factors)
        total = max(0, min(self._max_score, total))

        return RiskResultSchema(
            risk_score=total,
            risk_level=risk_level_for_score(total),
            risk_factors=factors,
        )


