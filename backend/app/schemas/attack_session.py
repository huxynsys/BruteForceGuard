from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AttackSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    started_at: datetime
    last_seen_at: datetime
    session_type: str
    severity: str
    event_count: int
    source_ips: list[str] | None
    usernames: list[str] | None
    services: list[str] | None
    detection_types: list[str] | None
    status: str
    created_at: datetime

    # Phase 7 intelligence
    risk_score: int = 0
    risk_level: str = "informational"
    risk_factors: list[dict] | None = None
    behavioral_profile: dict | None = None