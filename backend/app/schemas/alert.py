from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, IPvAnyAddress


class AlertSeverity(str, Enum):
    """Canonical severities emitted by the detection engine."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, Enum):
    """Analyst triage lifecycle persisted in ``alerts.status``."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertDetectionRule(BaseModel):
    """Detection-rule parameters behind an alert (``alerts.alert_type``).

    The values are derived from the same configuration the detectors run with
    (``app.core.detection_config``), so the investigation UI shows the threshold
    the engine actually required instead of a browser-side copy that could
    drift.  ``None`` is returned for alert types the engine no longer knows.
    """

    alert_type: str
    label: str
    threshold_label: str
    threshold: int
    secondary_label: str | None = None
    secondary_threshold: int | None = None
    window_seconds: int
    requirement: str


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime

    alert_type: str
    severity: str

    title: str
    description: str

    source_ip: IPvAnyAddress | None
    username: str | None
    service: str | None

    mitre_technique: str | None
    confidence: int

    evidence: dict | None
    status: str
    session_id: int | None

    # The detection rule that produced this alert (never analyst-supplied).
    detection_rule: AlertDetectionRule | None = None

    # Phase 7 intelligence
    risk_score: int = 0
    risk_level: str = "informational"
    risk_factors: list[dict] | None = None
    threat_intelligence: dict | None = None
    source_reputation: dict | None = None
    mitre_context: dict | None = None


class AlertStatusUpdate(BaseModel):
    """Body of a triage transition (``PATCH /api/v1/alerts/{id}``)."""

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus


class AlertStats(BaseModel):
    """Matching total plus facet counts for the current filter set."""

    total: int
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_alert_type: dict[str, int] = {}