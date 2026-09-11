"""Phase 7 - internal behavioral reputation (7.8-7.9, 7.15-7.18).

7.15  Source-IP behavioral reputation exists.
7.16  Reputation considers historical behavior.
7.17  Reputation is deterministic.
7.18  Reputation is exposed through the API.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from app.intelligence.reputation import ReputationService
from app.intelligence.schemas import ReputationResult
from app.models.alert import Alert
from app.models.attack_session import AttackSession
from app.models.auth_event import AuthEvent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def reputation_service(db: Session) -> ReputationService:
    return ReputationService(db)


def _make_event(
    db: Session,
    *,
    source_ip: str = "10.0.0.1",
    username: str = "admin",
    result: str = "failure",
    service: str = "ssh",
    timestamp: datetime | None = None,
) -> AuthEvent:
    event = AuthEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source="test",
        source_ip=source_ip,
        username=username,
        result=result,
        service=service,
        port=22,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _make_alert(
    db: Session,
    *,
    source_ip: str = "10.0.0.1",
    alert_type: str = "single_account_bruteforce",
    severity: str = "high",
) -> Alert:
    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        confidence=80,
        title="Test",
        description="Test",
        source_ip=source_ip,
        username="admin",
        service="ssh",
        status="open",
        evidence={},
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def _make_session(
    db: Session,
    *,
    source_ips: list[str] | None = None,
    status: str = "active",
) -> AttackSession:
    session = AttackSession(
        started_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        session_type="single_account",
        severity="high",
        event_count=10,
        source_ips=source_ips or ["10.0.0.1"],
        usernames=["admin"],
        services=["ssh"],
        detection_types=["single_account"],
        status=status,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session

# ---------------------------------------------------------------------------
# 7.15 / 7.16 Source-IP behavioral reputation exists and considers history
# ---------------------------------------------------------------------------
def test_new_ip_has_unknown_reputation(
    reputation_service: ReputationService,
):
    result = reputation_service.get_reputation("192.168.1.1")
    assert result.internal_reputation_score == 0
    assert result.internal_reputation_level == "unknown"
    assert result.unique_usernames == 0


def test_reputation_increases_with_failures(
    db: Session,
    reputation_service: ReputationService,
):
    for _ in range(10):
        _make_event(db, result="failure")
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.internal_reputation_score > 0
    assert result.failure_rate == 1.0
    assert result.unique_usernames == 1


def test_reputation_with_mixed_results(
    db: Session,
    reputation_service: ReputationService,
):
    for _ in range(8):
        _make_event(db, result="failure")
    _make_event(db, result="success")
    _make_event(db, result="success")
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.failure_rate == 0.8
    assert result.internal_reputation_score > 0


def test_reputation_considers_multiple_usernames(
    db: Session,
    reputation_service: ReputationService,
):
    _make_event(db, username="admin")
    _make_event(db, username="root")
    _make_event(db, username="user1")
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.unique_usernames == 3


def test_reputation_considers_multiple_services(
    db: Session,
    reputation_service: ReputationService,
):
    _make_event(db, service="ssh")
    _make_event(db, service="rdp")
    _make_event(db, service="web")
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.unique_services == 3


def test_reputation_considers_alerts(
    db: Session,
    reputation_service: ReputationService,
):
    _make_alert(db)
    _make_alert(db)
    _make_alert(db)
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.alert_count == 3
    assert result.internal_reputation_score > 0


def test_reputation_considers_attack_sessions(
    db: Session,
    reputation_service: ReputationService,
):
    _make_session(db)
    _make_session(db)
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.attack_sessions == 2


def test_reputation_first_seen_last_seen(
    db: Session,
    reputation_service: ReputationService,
):
    now = datetime.now(timezone.utc)
    earlier = now - timedelta(hours=2)
    _make_event(db, timestamp=earlier)
    _make_event(db, timestamp=now)
    result = reputation_service.get_reputation("10.0.0.1")
    assert result.first_seen is not None
    assert result.last_seen is not None
    assert result.last_seen >= result.first_seen


# ---------------------------------------------------------------------------
# 7.17 Reputation is deterministic
# ---------------------------------------------------------------------------
def test_reputation_is_deterministic(
    db: Session,
    reputation_service: ReputationService,
):
    for _ in range(5):
        _make_event(db, result="failure")
    _make_alert(db)
    result1 = reputation_service.get_reputation("10.0.0.1")
    result2 = reputation_service.get_reputation("10.0.0.1")
    assert result1.internal_reputation_score == result2.internal_reputation_score
    assert result1.internal_reputation_level == result2.internal_reputation_level


def test_reputation_score_bounded(
    db: Session,
    reputation_service: ReputationService,
):
    for _ in range(100):
        _make_event(db, result="failure")
    for _ in range(50):
        _make_alert(db)
    result = reputation_service.get_reputation("10.0.0.1")
    assert 0 <= result.internal_reputation_score <= 100


def test_reputation_level_mapping(
    reputation_service: ReputationService,
):
    assert reputation_service.get_reputation("1.1.1.1").internal_reputation_level == "unknown"
