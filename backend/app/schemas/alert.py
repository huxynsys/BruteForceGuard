from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime

    alert_type: str
    severity: str

    title: str
    description: str

    source_ip: str | None
    username: str | None
    service: str | None

    mitre_technique: str | None
    confidence: int

    evidence: dict | None
    status: str
    session_id: int | None