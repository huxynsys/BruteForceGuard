from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent
from app.models.alert import Alert



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

    # ===================== SECTION 16 =====================
    def detect_single_account_bruteforce(
        self,
        event: AuthEvent,
        threshold: int = 5,
        window_seconds: int = 300,
    ):
        if event.result != "failure":
            return None

        start_time = event.timestamp - timedelta(
            seconds=window_seconds
        )

        statement = select(func.count(AuthEvent.id)).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.source_ip == event.source_ip,
            AuthEvent.username == event.username,
        )

        count = self.db.scalar(statement) or 0

        if count < threshold:
            return None

        return {
            "alert_type": "single_account_bruteforce",
            "severity": "high",
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
            },
        }

    # ===================== SECTION 17 =====================
    def detect_password_spraying(
        self,
        event: AuthEvent,
        minimum_users: int = 5,
        minimum_failures: int = 10,
        window_seconds: int = 600,
    ):
        if event.result != "failure":
            return None

        start_time = event.timestamp - timedelta(
            seconds=window_seconds
        )

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.source_ip == event.source_ip,
        )

        events = list(self.db.scalars(statement))

        usernames = {
            e.username
            for e in events
            if e.username
        }

        if (
            len(events) < minimum_failures
            or len(usernames) < minimum_users
        ):
            return None

        return {
            "alert_type": "password_spraying",
            "severity": "high",
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
                "usernames": sorted(usernames),
                "window_seconds": window_seconds,
            },
        }

    # ===================== SECTION 18 =====================
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

        start_time = event.timestamp - timedelta(
            seconds=window_seconds
        )

        statement = select(AuthEvent).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp <= event.timestamp,
            AuthEvent.username == event.username,
        )

        events = list(self.db.scalars(statement))

        source_ips = {
            str(e.source_ip)
            for e in events
        }

        if (
            len(events) < minimum_failures
            or len(source_ips) < minimum_source_ips
        ):
            return None

        return {
            "alert_type": "distributed_bruteforce",
            "severity": "high",
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
                "window_seconds": window_seconds,
            },
        }

    # ===================== SECTION 19 =====================
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

        start_time = event.timestamp - timedelta(
            seconds=window_seconds
        )

        statement = select(func.count(AuthEvent.id)).where(
            AuthEvent.result == "failure",
            AuthEvent.timestamp >= start_time,
            AuthEvent.timestamp < event.timestamp,
            AuthEvent.username == event.username,
            AuthEvent.source_ip == event.source_ip,
        )

        failures = self.db.scalar(statement) or 0

        if failures < minimum_failures:
            return None

        return {
            "alert_type": "failed_then_success",
            "severity": "critical",
            "title": "Multiple Failed Logins Followed By Success",
            "description": (
                f"{failures} failed authentication attempts "
                f"were followed by a successful login for "
                f"{event.username}."
            ),
            "source_ip": str(event.source_ip),
            "username": event.username,
            "service": event.service,
            "mitre_technique": "T1110",
            "evidence": {
                "failed_attempts": failures,
                "successful_login": True,
                "window_seconds": window_seconds,
            },
        }





def create_alert_if_new(
    db: Session,
    alert_data: dict,
) -> Alert | None:

    statement = select(Alert).where(
        Alert.alert_type == alert_data["alert_type"],
        Alert.source_ip == alert_data.get("source_ip"),
        Alert.username == alert_data.get("username"),
        Alert.service == alert_data.get("service"),
        Alert.status == "open",
    )

    existing_alert = db.scalar(statement)

    if existing_alert:
        return None

    alert = Alert(
        alert_type=alert_data["alert_type"],
        severity=alert_data["severity"],
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