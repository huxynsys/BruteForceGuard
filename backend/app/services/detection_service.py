from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.alert import Alert
from app.core.detection_config import get_service_thresholds
from app.core.trusted_sources import is_trusted_ip


class DetectionService:

    def __init__(self, db: Session):
        self.db = db

    def get_recent_failures(
        self,
        timestamp: datetime,
        seconds: int,
    ):
        """Helper: get all failures within a time window."""
        start_time = timestamp - timedelta(seconds=seconds)

        statement = (
            select(AuthEvent)
            .where(
                AuthEvent.result == "failure",
                AuthEvent.timestamp >= start_time,
                AuthEvent.timestamp <= timestamp,
            )
            .order_by(AuthEvent.timestamp)
        )

        return list(self.db.scalars(statement))

    # ===================== SINGLE ACCOUNT =====================
    def detect_single_account_bruteforce(
        self,
        event: AuthEvent,
        threshold: int = 5,
        window_seconds: int = 300,
    ):
        if event.result != "failure":
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.source_ip == event.source_ip,
            AuthEvent.username == event.username,
        )

        events = list(self.db.scalars(statement))
        count = len(events)

        if count < threshold:
            return None

        confidence = 50
        if count >= 10:
            confidence = 65
        if count >= 20:
            confidence = 80

        alert_data = {
            "alert_type": "single_account_bruteforce",
            "severity": "high",
            "confidence": confidence,
            "title": "Possible Single-Account Brute Force",
            "description": (
                f"{count} failed authentication attempts "
                f"against account {event.username} "
                f"from {event.source_ip}."
            ),
            "source_ip": str(event.source_ip),
            "username": event.username,
            "service": event.service,
            "mitre_technique": "T1110.001",
            "evidence": {
                "failure_count": count,
                "window_seconds": window_seconds,
                "distinct_users": 1,
                "distinct_source_ips": 1,
                "services": [event.service] if event.service else [],
                "first_seen": events[0].timestamp.isoformat() if events else None,
                "last_seen": events[-1].timestamp.isoformat() if events else None,
                "source_ip": str(event.source_ip),
                "username": event.username,
            },
        }

        return create_alert_if_new(self.db, alert_data)

    # ===================== PASSWORD SPRAY =====================
    def detect_password_spraying(
        self,
        event: AuthEvent,
        minimum_users: int = 5,
        minimum_failures: int = 10,
        window_seconds: int = 600,
    ):
        if event.result != "failure":
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.source_ip == event.source_ip,
        )

        events = list(self.db.scalars(statement))

        usernames = {e.username for e in events if e.username}

        if len(events) < minimum_failures or len(usernames) < minimum_users:
            return None

        confidence = 50
        if len(events) >= 20:
            confidence = 65
        if len(usernames) >= 10:
            confidence = 75
        if len(events) >= 50 and len(usernames) >= 20:
            confidence = 85

        alert_data = {
            "alert_type": "password_spraying",
            "severity": "high",
            "confidence": confidence,
            "title": "Possible Password Spraying",
            "description": (
                f"Source {event.source_ip} generated "
                f"{len(events)} failures against "
                f"{len(usernames)} accounts."
            ),
            "source_ip": str(event.source_ip),
            "username": None,
            "service": event.service,
            "mitre_technique": "T1110.003",
            "evidence": {
                "failure_count": len(events),
                "distinct_users": len(usernames),
                "usernames": sorted(usernames)[:20],
                "distinct_source_ips": 1,
                "services": [event.service] if event.service else [],
                "window_seconds": window_seconds,
                "first_seen": events[0].timestamp.isoformat() if events else None,
                "last_seen": events[-1].timestamp.isoformat() if events else None,
                "source_ip": str(event.source_ip),
            },
        }

        return create_alert_if_new(self.db, alert_data)

    # ===================== DISTRIBUTED BRUTE FORCE =====================
    def detect_distributed_bruteforce(
        self,
        event: AuthEvent,
        minimum_source_ips: int = 3,
        minimum_failures: int = 10,
        window_seconds: int = 600,
    ):
        if event.result != "failure":
            return None

        if not event.username:
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.username == event.username,
        )

        events = list(self.db.scalars(statement))

        source_ips = {str(e.source_ip) for e in events}

        if len(events) < minimum_failures or len(source_ips) < minimum_source_ips:
            return None

        confidence = 50
        if len(source_ips) >= 5:
            confidence = 65
        if len(events) >= 20:
            confidence = 75
        if len(source_ips) >= 10 and len(events) >= 30:
            confidence = 85

        alert_data = {
            "alert_type": "distributed_bruteforce",
            "severity": "high",
            "confidence": confidence,
            "title": "Possible Distributed Brute Force",
            "description": (
                f"Account {event.username} received "
                f"{len(events)} failed authentication attempts "
                f"from {len(source_ips)} source IPs."
            ),
            "source_ip": None,
            "username": event.username,
            "service": event.service,
            "mitre_technique": "T1110",
            "evidence": {
                "failure_count": len(events),
                "distinct_source_ips": len(source_ips),
                "source_ips": sorted(source_ips),
                "distinct_users": 1,
                "services": [event.service] if event.service else [],
                "window_seconds": window_seconds,
                "first_seen": events[0].timestamp.isoformat() if events else None,
                "last_seen": events[-1].timestamp.isoformat() if events else None,
                "username": event.username,
            },
        }

        return create_alert_if_new(self.db, alert_data)

    # ===================== FAILED → SUCCESS =====================
    def detect_failed_then_success(
        self,
        event: AuthEvent,
        minimum_failures: int = 3,
        window_seconds: int = 300,
    ):
        if event.result != "success":
            return None

        if not event.username:
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp < event.timestamp,
            AuthEvent.username == event.username,
            AuthEvent.source_ip == event.source_ip,
        )

        failures = list(self.db.scalars(statement))
        failure_count = len(failures)

        if failure_count < minimum_failures:
            return None

        confidence = 70
        if failure_count >= 5:
            confidence = 80
        if failure_count >= 10:
            confidence = 90

        alert_data = {
            "alert_type": "failed_then_success",
            "severity": "critical",
            "confidence": confidence,
            "title": "Multiple Failed Logins Followed By Success",
            "description": (
                f"{failure_count} failed authentication attempts "
                f"were followed by a successful login for "
                f"{event.username}."
            ),
            "source_ip": str(event.source_ip),
            "username": event.username,
            "service": event.service,
            "mitre_technique": "T1110",
            "evidence": {
                "failed_attempts": failure_count,
                "successful_login": True,
                "window_seconds": window_seconds,
                "source_ip": str(event.source_ip),
                "username": event.username,
                "services": [event.service] if event.service else [],
                "first_seen": failures[0].timestamp.isoformat() if failures else None,
                "last_seen": event.timestamp.isoformat(),
                "failure_timestamps": [
                    f.timestamp.isoformat() for f in failures[-10:]
                ],
            },
        }

        return create_alert_if_new(self.db, alert_data)

    # ===================== CREDENTIAL STUFFING =====================
    def detect_credential_stuffing(
        self,
        event: AuthEvent,
        minimum_users: int = 10,
        minimum_failures: int = 20,
        window_seconds: int = 600,
    ):
        if event.result != "failure":
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.source_ip == event.source_ip,
        )

        events = list(self.db.scalars(statement))

        usernames = {e.username for e in events if e.username}

        if len(events) < minimum_failures or len(usernames) < minimum_users:
            return None

        confidence = 50
        if len(events) > 50:
            confidence = 65
        if len(events) > 100:
            confidence = 75
        if len(usernames) > 20:
            confidence = 80

        alert_data = {
            "alert_type": "credential_stuffing",
            "severity": "high",
            "confidence": confidence,
            "title": "Possible Credential Stuffing",
            "description": (
                f"Source {event.source_ip} generated "
                f"{len(events)} failed authentication attempts "
                f"against {len(usernames)} accounts."
            ),
            "source_ip": str(event.source_ip),
            "username": None,
            "service": event.service,
            "mitre_technique": "T1110.004",
            "evidence": {
                "failure_count": len(events),
                "distinct_users": len(usernames),
                "usernames": sorted(usernames)[:20],
                "distinct_source_ips": 1,
                "services": [event.service] if event.service else [],
                "window_seconds": window_seconds,
                "first_seen": events[0].timestamp.isoformat() if events else None,
                "last_seen": events[-1].timestamp.isoformat() if events else None,
                "source_ip": str(event.source_ip),
            },
        }

        return create_alert_if_new(self.db, alert_data)

    # ===================== LOW AND SLOW =====================
    def detect_low_and_slow(
        self,
        event: AuthEvent,
        minimum_failures: int = 10,
        window_seconds: int = 3600,
        minimum_active_intervals: int = 5,
    ):
        if event.result != "failure":
            return None

        if not event.username:
            return None

        start_time = event.timestamp - timedelta(seconds=window_seconds)

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.username == event.username,
            AuthEvent.source_ip == event.source_ip,
        )

        events = list(self.db.scalars(statement))

        if len(events) < minimum_failures:
            return None

        interval_seconds = window_seconds // minimum_active_intervals
        active_intervals = set()

        for e in events:
            interval_index = int(
                (e.timestamp - start_time).total_seconds() // interval_seconds
            )
            active_intervals.add(interval_index)

        if len(active_intervals) < minimum_active_intervals:
            return None

        confidence = 50
        if len(events) > 15:
            confidence = 60
        if len(active_intervals) > 7:
            confidence = 70
        if len(events) > 20 and len(active_intervals) > 10:
            confidence = 80

        alert_data = {
            "alert_type": "low_and_slow",
            "severity": "medium",
            "confidence": confidence,
            "title": "Low-and-Slow Authentication Attack",
            "description": (
                f"Account {event.username} received "
                f"{len(events)} failed authentication attempts "
                f"spread across {len(active_intervals)} time intervals "
                f"from {event.source_ip}."
            ),
            "source_ip": str(event.source_ip),
            "username": event.username,
            "service": event.service,
            "mitre_technique": "T1110",
            "evidence": {
                "failure_count": len(events),
                "active_intervals": len(active_intervals),
                "window_seconds": window_seconds,
                "distinct_users": 1,
                "distinct_source_ips": 1,
                "services": [event.service] if event.service else [],
                "first_seen": events[0].timestamp.isoformat() if events else None,
                "last_seen": events[-1].timestamp.isoformat() if events else None,
                "source_ip": str(event.source_ip),
                "username": event.username,
                "intervals": sorted(active_intervals)[:20],
            },
        }

        return create_alert_if_new(self.db, alert_data)


# ===================== ALERT DEDUPLICATION =====================
def create_alert_if_new(db: Session, alert_data: dict) -> Alert | None:
    """Create an alert only if no open alert with the same key exists."""
    # Base query
    statement = select(Alert).where(
        Alert.alert_type == alert_data["alert_type"],
        Alert.status == "open",
    )

    # Add filters conditionally
    if alert_data.get("source_ip") is not None:
        statement = statement.where(Alert.source_ip == alert_data["source_ip"])

    if alert_data.get("username") is not None:
        statement = statement.where(Alert.username == alert_data["username"])

    if alert_data.get("service") is not None:
        statement = statement.where(Alert.service == alert_data["service"])

    existing = db.scalar(statement)

    if existing:
        return None

    # Create new alert
    alert = Alert(
        alert_type=alert_data["alert_type"],
        severity=alert_data["severity"],
        confidence=alert_data.get("confidence", 50),
        title=alert_data["title"],
        description=alert_data["description"],
        source_ip=alert_data.get("source_ip"),
        username=alert_data.get("username"),
        service=alert_data.get("service"),
        mitre_technique=alert_data.get("mitre_technique"),
        evidence=alert_data.get("evidence"),
        status="open",
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert