from datetime import datetime, timedelta, timezone

from sqlalchemy import select
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
#: Only an *open* alert absorbs further detections of the same attack.  Once an
#: analyst resolves an alert (or marks it a false positive) the next detection
#: must raise a fresh alert instead of disappearing into a closed case.
DEDUPLICATED_STATUS = "open"

#: The deduplication key: a detection joins an existing alert only when every
#: dimension it populates matches.  Dimensions a detector leaves ``None`` (for
#: example the username of a password spray) are compared as "not applicable".
DEDUPLICATION_KEY_FIELDS = ("alert_type", "source_ip", "username", "service")

#: Window-scoped evidence counters.  A merge keeps the largest observed value,
#: so folding in a later detection can never shrink recorded evidence.
EVIDENCE_COUNT_KEYS = (
    "failure_count",
    "failed_attempts",
    "distinct_users",
    "distinct_source_ips",
    "active_intervals",
)

#: Evidence keys holding raw identifiers/timestamps.  A merge unions them and
#: caps the result, so a long-running attack cannot grow an alert row without
#: bound.
EVIDENCE_LIST_LIMITS = {
    "usernames": 20,
    "source_ips": 20,
    "services": 5,
    "intervals": 20,
    "failure_timestamps": 10,
}

#: Every detection folded into an alert leaves a trace in its evidence:
#: ``occurrence_count`` counts them and ``occurrences`` keeps the newest
#: ``MAX_RECORDED_OCCURRENCES`` raw scopes, so a suppressed duplicate is never
#: silently discarded.
OCCURRENCES_EVIDENCE_KEY = "occurrences"
OCCURRENCE_COUNT_EVIDENCE_KEY = "occurrence_count"
MAX_RECORDED_OCCURRENCES = 10

#: Severity never downgrades when detections are merged (attack sessions follow
#: the same escalation-only rule).
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def create_alert_if_new(db: Session, alert_data: dict) -> Alert | None:
    """Create an alert, or fold a repeated detection into the open one.

    Deduplication is keyed on ``alert_type + source_ip + username + service``
    (``DEDUPLICATION_KEY_FIELDS``) while the covering alert is still ``open``.

    Returns the new :class:`Alert` when a row was created, and ``None`` when an
    open alert already covers the attack.  A suppressed duplicate is *not*
    dropped: the existing alert is refreshed in place with the new detection's
    scope - evidence counters, identifier lists, ``first_seen`` / ``last_seen``
    and the per-detection ``occurrences`` history - and is never downgraded in
    severity or confidence.  ``title`` and ``description`` keep the narrative of
    the detection that first raised the alert; the aggregated numbers live in
    ``evidence``.

    The merge path deliberately only *flushes* (rather than committing): a
    burst of repeated detections - the overwhelmingly common case during an
    active attack - is persisted as one transaction batch by the caller's
    commit.  The creation path keeps its own commit because callers consume
    the new alert immediately (enrichment, session linkage), and an
    uncommitted row cannot safely feed those follow-ups.
    """

    # Base query
    statement = select(Alert).where(
        Alert.alert_type == alert_data["alert_type"],
        Alert.status == DEDUPLICATED_STATUS,
    )

    # Add filters conditionally
    if alert_data.get("source_ip") is not None:
        statement = statement.where(Alert.source_ip == alert_data["source_ip"])

    if alert_data.get("username") is not None:
        statement = statement.where(Alert.username == alert_data["username"])

    if alert_data.get("service") is not None:
        statement = statement.where(Alert.service == alert_data["service"])

    existing = db.scalar(statement)

    if existing is not None:
        # A repeated detection of the same attack: refresh the alert it belongs
        # to instead of discarding the new evidence.
        existing = db.get(Alert, existing.id, populate_existing=True)

        if existing is None:
            # The open alert vanished between the lookup and the merge (another
            # request resolved it).  Drop this merge rather than resurrect it.
            db.rollback()
            return None

        existing.evidence = merge_alert_evidence(
            existing.evidence,
            alert_data.get("evidence"),
        )

        existing.severity = _higher_severity(
            existing.severity,
            alert_data.get("severity"),
        )

        existing.confidence = max(
            _as_int(existing.confidence) or 0,
            _as_int(alert_data.get("confidence")) or 0,
        )

        if not existing.mitre_technique and alert_data.get("mitre_technique"):
            existing.mitre_technique = alert_data["mitre_technique"]

        # Flush only: committing here would expire the session on every repeated
        # detection and serialize + fsync on every row.  Seen-but-uncommitted
        # merges stay in this transaction and are durable once the caller's
        # commit lands.  ``db.get`` above re-reads rather than trusting the
        # first SELECT, so concurrent readers always fold into fresh state.
        db.flush()
        db.refresh(existing)

        # No new alert was created.  The merged detection is fully represented
        # by the refreshed row, so callers must not treat this as an alert.
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
        evidence=build_alert_evidence(alert_data.get("evidence")),
        status=DEDUPLICATED_STATUS,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


# --------------------------- deduplication helpers ---------------------------
def _as_int(value: object) -> int | None:
    """Read an evidence counter that may have been serialized as a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _as_utc(value: object) -> datetime | None:
    """Parse an ISO evidence timestamp for comparison only (never re-stored)."""
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        # SQLite hands back naive timestamps; detectors serialize exactly what
        # the database gave them, so both sides of a comparison agree.
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _earliest(first: object, second: object) -> object:
    """Keep the earlier of two ISO timestamps in its original stored form."""
    first_key = _as_utc(first)
    second_key = _as_utc(second)

    if first_key is None:
        return second if second_key is not None else first
    if second_key is None:
        return first

    return first if first_key <= second_key else second


def _latest(first: object, second: object) -> object:
    """Keep the later of two ISO timestamps in its original stored form."""
    first_key = _as_utc(first)
    second_key = _as_utc(second)

    if first_key is None:
        return second if second_key is not None else first
    if second_key is None:
        return first

    return first if first_key >= second_key else second


def _merged_unique_list(
    existing: object,
    incoming: object,
    limit: int,
) -> list | None:
    """Union two evidence lists: order-preserving, de-duplicated and capped."""
    merged: list = []

    for source in (existing, incoming):
        if not isinstance(source, list):
            continue

        for item in source:
            if item not in merged:
                merged.append(item)

    if not merged:
        return None

    return merged[:limit]


def _occurrence_snapshot(evidence: dict) -> dict:
    """Freeze the raw window scope of one detection for ``occurrences``."""
    snapshot: dict = {}

    for key in (
        "first_seen",
        "last_seen",
        "failure_count",
        "failed_attempts",
        "distinct_users",
        "distinct_source_ips",
        "active_intervals",
        "window_seconds",
    ):
        value = evidence.get(key)

        if value is None or isinstance(value, (dict, list)):
            continue

        snapshot[key] = value

    return snapshot


def _record_occurrence(evidence: dict, snapshot: dict) -> dict:
    """Count one detection and keep its snapshot (newest last, bounded)."""
    occurrences = [
        item
        for item in (evidence.get(OCCURRENCES_EVIDENCE_KEY) or [])
        if isinstance(item, dict)
    ]

    if snapshot:
        occurrences.append(snapshot)

    if occurrences:
        evidence[OCCURRENCES_EVIDENCE_KEY] = occurrences[
            -MAX_RECORDED_OCCURRENCES:
        ]

    evidence[OCCURRENCE_COUNT_EVIDENCE_KEY] = (
        _as_int(evidence.get(OCCURRENCE_COUNT_EVIDENCE_KEY)) or 0
    ) + 1

    return evidence


def build_alert_evidence(evidence: dict | None) -> dict:
    """Evidence recorded when an alert is created: its first occurrence."""
    recorded = dict(evidence or {})

    return _record_occurrence(recorded, _occurrence_snapshot(recorded))


def merge_alert_evidence(
    existing: dict | None,
    incoming: dict | None,
) -> dict:
    """Fold a repeated detection into the evidence of an open alert.

    * counters keep the largest window-scoped value (never shrink),
    * identifier/timestamp lists are unioned and bounded,
    * ``first_seen`` keeps the earliest and ``last_seen`` the latest timestamp,
    * every detection is preserved as one entry in ``occurrences``.

    A successful login is a fact, so ``successful_login`` never reverts to
    false.  The result is always a new dict: the JSONB column is assigned, never
    mutated in place.
    """
    merged = dict(existing or {})
    incoming = incoming or {}

    for key in EVIDENCE_COUNT_KEYS:
        new_value = _as_int(incoming.get(key))

        if new_value is None:
            continue

        merged[key] = max(_as_int(merged.get(key)) or 0, new_value)

    for key, limit in EVIDENCE_LIST_LIMITS.items():
        union = _merged_unique_list(merged.get(key), incoming.get(key), limit)

        if union is not None:
            merged[key] = union

    if incoming.get("successful_login"):
        merged["successful_login"] = True

    if incoming.get("window_seconds") is not None:
        merged["window_seconds"] = incoming["window_seconds"]

    for key in ("source_ip", "username"):
        if not merged.get(key) and incoming.get(key):
            merged[key] = incoming[key]

    first_seen = _earliest(merged.get("first_seen"), incoming.get("first_seen"))
    if first_seen is not None:
        merged["first_seen"] = first_seen

    last_seen = _latest(merged.get("last_seen"), incoming.get("last_seen"))
    if last_seen is not None:
        merged["last_seen"] = last_seen

    return _record_occurrence(merged, _occurrence_snapshot(incoming))


def _higher_severity(
    existing: str | None,
    incoming: str | None,
) -> str | None:
    """Never downgrade: keep whichever of two severities ranks higher."""
    if SEVERITY_RANK.get(incoming or "", 0) > SEVERITY_RANK.get(existing or "", 0):
        return incoming

    return existing