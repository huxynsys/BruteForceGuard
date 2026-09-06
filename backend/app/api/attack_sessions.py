from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.attack_session import AttackSession
from app.schemas.attack_session import AttackSessionResponse
from app.services.session_service import SessionService


router = APIRouter(
    prefix="/api/v1/attack-sessions",
    tags=["attack-sessions"],
)


@router.get("/", response_model=list[AttackSessionResponse])
def list_sessions(
    db: Session = Depends(get_db),
    limit: int = 100,
    status: str | None = None,
):
    """List attack sessions with optional status filter."""
    statement = select(AttackSession).order_by(
        AttackSession.last_seen_at.desc()
    ).limit(limit)

    if status:
        statement = statement.where(AttackSession.status == status)

    return list(db.scalars(statement))


@router.get("/{session_id}", response_model=AttackSessionResponse)
def get_session(
    session_id: int,
    db: Session = Depends(get_db),
):
    """Get a specific attack session by ID."""
    session = db.get(AttackSession, session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.post("/{session_id}/close", response_model=AttackSessionResponse)
def close_session(
    session_id: int,
    db: Session = Depends(get_db),
):
    """Manually close an attack session."""
    session_service = SessionService(db)
    session = db.get(AttackSession, session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session_service.close_session(session)


@router.get("/stats/active")
def get_active_stats(
    db: Session = Depends(get_db),
):
    """Get statistics about active sessions."""
    statement = select(AttackSession).where(AttackSession.status == "active")
    active_sessions = list(db.scalars(statement))

    total_events = sum(s.event_count for s in active_sessions)
    unique_ips = set()
    unique_users = set()

    for session in active_sessions:
        if session.source_ips:
            unique_ips.update(session.source_ips)
        if session.usernames:
            unique_users.update(session.usernames)

    return {
        "active_sessions": len(active_sessions),
        "total_events": total_events,
        "unique_source_ips": len(unique_ips),
        "unique_usernames": len(unique_users),
    }