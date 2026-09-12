"""Pydantic schemas for the Phase 7 intelligence module."""

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.intelligence.validation import validate_indicator

IndicatorType = Literal["ipv4", "ipv6", "domain", "username"]


class RiskFactorSchema(BaseModel):
    factor: str
    value: int
    reason: str


class RiskResultSchema(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    risk_factors: list[RiskFactorSchema]


class ThreatIntelLookup(BaseModel):
    indicator: str
    indicator_type: str
    known: bool
    confidence: int | None = None
    categories: list[str] = Field(default_factory=list)
    threat_type: str | None = None
    source: str | None = None


class ReputationResult(BaseModel):
    source_ip: str
    internal_reputation_score: int = Field(ge=0, le=100)
    internal_reputation_level: str
    failure_rate: float | None = None
    unique_usernames: int = 0
    unique_services: int = 0
    attack_sessions: int = 0
    alert_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class MitreContext(BaseModel):
    detection_type: str
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    is_mapped: bool = True


class ThreatIndicatorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1, max_length=255)
    indicator_type: IndicatorType
    confidence: int = Field(default=50, ge=1, le=100)
    threat_type: str | None = Field(default=None, max_length=100)
    source: str = Field(default="manual", max_length=100)
    tags: list[str] = Field(default_factory=list)
    active: bool = True

    @model_validator(mode="after")
    def _check_indicator_format(self) -> Self:
        """Reject indicator values that do not match their claimed type.

        e.g. {"indicator": "hello", "indicator_type": "ipv4"} -> 422.
        """
        if not validate_indicator(self.indicator, self.indicator_type):
            raise ValueError(
                f"indicator {self.indicator!r} is not a valid "
                f"{self.indicator_type} value"
            )
        return self


class ThreatIndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator: str
    indicator_type: str
    confidence: int
    threat_type: str | None
    source: str
    tags: list | None
    active: bool
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime
    updated_at: datetime
