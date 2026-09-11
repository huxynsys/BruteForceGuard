from datetime import datetime

from pydantic import BaseModel, ConfigDict, IPvAnyAddress


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

    # Phase 7 intelligence
    risk_score: int = 0
    risk_level: str = "informational"
    risk_factors: list[dict] | None = None
    threat_intelligence: dict | None = None
    source_reputation: dict | None = None
    mitre_context: dict | None = None