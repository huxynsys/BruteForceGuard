"""Phase 7 intelligence API.

Endpoints for threat indicators, IP lookups, reputation, and MITRE context.
Reads require an authenticated principal (analyst or admin); the indicator
create/delete endpoints require the **admin** role because they change the
security configuration (IOC store).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_admin, require_reader
from app.db.database import get_db
from app.intelligence.local_provider import LocalThreatIntelProvider
from app.intelligence.mitre import get_mitre_context, is_valid_technique
from app.intelligence.repository import ThreatIndicatorRepository
from app.intelligence.reputation import ReputationService
from app.intelligence.schemas import (
    MitreContext,
    ReputationResult,
    ThreatIndicatorCreate,
    ThreatIndicatorResponse,
    ThreatIntelLookup,
)
from app.models.threat_indicator import ThreatIndicator

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/intelligence",
    tags=["intelligence"],
)


def _provider(db: Session) -> LocalThreatIntelProvider:
    return LocalThreatIntelProvider(db)


def _repository(db: Session) -> ThreatIndicatorRepository:
    return ThreatIndicatorRepository(db)


@router.get("/ip/{ip}", response_model=ThreatIntelLookup)
def lookup_ip(
    ip: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_reader),
):
    """Look up threat-intelligence data for an IP address."""
    return _provider(db).lookup_ip(ip)


@router.get("/reputation/{ip}", response_model=ReputationResult)
def get_reputation(
    ip: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_reader),
):
    """Return the internal behavioral reputation for a source IP."""
    return ReputationService(db).get_reputation(ip)


@router.get("/mitre/{technique_id}", response_model=MitreContext)
def get_mitre(
    technique_id: str,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_reader),
):
    """Return MITRE ATT&CK context for a technique id."""
    if not is_valid_technique(technique_id):
        # Try interpreting as a detection-type alias then fall back safe.
        context = get_mitre_context(technique_id)
        if not context.is_mapped:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown technique id or detection type: {technique_id}",
            )
        return context

    # technique_id matched directly - find the first mapping.
    from app.intelligence.mitre import MITRE_MAPPING

    for detection_type, entry in MITRE_MAPPING.items():
        if entry["technique_id"] == technique_id:
            return MitreContext(
                detection_type=detection_type,
                technique_id=technique_id,
                technique_name=entry["technique_name"],
                tactic=entry["tactic"],
                description=entry["description"],
                is_mapped=True,
            )
    raise HTTPException(status_code=404, detail="Technique not found")


@router.get("/indicators", response_model=list[ThreatIndicatorResponse])
def list_indicators(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_reader),
    indicator_type: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
):
    """List stored threat indicators (local IOC store)."""
    return _repository(db).list_indicators(
        indicator_type=indicator_type,
        active_only=active_only,
        limit=limit,
    )


@router.get(
    "/mitre", response_model=list[dict])
def list_mitre(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_reader),
):
    """List all supported MITRE mappings."""
    from app.intelligence.mitre import MITRE_MAPPING

    return [
        {
            "detection_type": detection_type,
            **entry,
        }
        for detection_type, entry in MITRE_MAPPING.items()
    ]


@router.post(
    "/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=201,
    summary="Create threat indicator (admin only)",
)
def create_indicator(
    data: ThreatIndicatorCreate,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_admin),
):
    """Create a new local threat indicator (admin role required).

    Writing to the IOC store changes detection context, so it is governed by
    the same admin gate as other security configuration.
    """
    return _repository(db).create(data)


@router.delete(
    "/indicators/{indicator_id}",
    status_code=204)
def delete_indicator(
    indicator_id: int,
    db: Session = Depends(get_db),
    actor: Principal = Depends(require_admin),
):
    """Delete a threat indicator (admin role required)."""
    deleted = _repository(db).delete(indicator_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return None