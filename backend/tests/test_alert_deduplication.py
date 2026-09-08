from datetime import datetime, timezone

from sqlalchemy import select

from app.models.alert import Alert
from app.models.auth_event import AuthEvent
from app.services.detection_service import create_alert_if_new


def test_duplicate_alert_is_not_created(db):
    event = AuthEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
    )

    db.add(event)
    db.commit()

    alert_data = {
        "alert_type": "single_account_bruteforce",
        "severity": "high",
        "confidence": 50,
        "title": "Possible Single-Account Brute Force",
        "description": "5 failed authentication attempts.",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "service": "ssh",
        "mitre_technique": "T1110.001",
        "evidence": {
            "failure_count": 5,
        },
    }

    # First call creates the alert...
    first_alert = create_alert_if_new(db, alert_data)

    # Second call for the same open attack is deduplicated...
    second_alert = create_alert_if_new(db, alert_data)

    # ...and only one row exists in the database.
    alerts = list(db.scalars(select(Alert)))

    assert first_alert is not None
    assert second_alert is None
    assert len(alerts) == 1


def test_different_attack_creates_a_different_alert(db):
    event = AuthEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        source_ip="10.0.0.1",
        username="admin",
        result="failure",
        service="ssh",
        port=22,
    )

    db.add(event)
    db.commit()

    single_account_data = {
        "alert_type": "single_account_bruteforce",
        "severity": "high",
        "confidence": 50,
        "title": "Possible Single-Account Brute Force",
        "description": "5 failed authentication attempts.",
        "source_ip": "10.0.0.1",
        "username": "admin",
        "service": "ssh",
        "mitre_technique": "T1110.001",
        "evidence": {},
    }

    failed_success_data = dict(single_account_data)
    failed_success_data.update(
        {
            "alert_type": "failed_then_success",
            "severity": "critical",
            "mitre_technique": "T1110",
        }
    )

    single_account_alert = create_alert_if_new(db, single_account_data)
    failed_success_alert = create_alert_if_new(db, failed_success_data)

    assert single_account_alert is not None
    assert failed_success_alert is not None
    assert single_account_alert.id != failed_success_alert.id