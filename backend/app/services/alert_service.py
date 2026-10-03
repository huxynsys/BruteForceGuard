"""Alert querying and the analyst triage lifecycle.

The alerts page is the authoritative detailed view of detections, so the
list query needs real server-side filtering/pagination and triage status
changes must be persisted.  All alert database access lives here, mirroring
``EventService`` and ``SessionService``.

Lifecycle transitions are validated against the state machine in
``app.services.alert_lifecycle`` and every accepted change appends one
``AlertStatusHistory`` row (timestamp, actor, role, optional reason) plus a
structured audit log line - the database row is the queryable audit trail,
the log line is the operational one.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatusHistory
from app.services.alert_lifecycle import validate_transition

logger = logging.getLogger(__name__)


class AlertService:
    """Filter, paginate, count and update alerts."""

    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def _conditions(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        alert_type: str | None = None,
        search: str | None = None,
    ) -> list:
        """Build the shared WHERE clauses (used by list, count and facets)."""

        conditions = []

        if severity:
            conditions.append(Alert.severity == severity)

        if status:
            conditions.append(Alert.status == status)

        if alert_type:
            conditions.append(Alert.alert_type == alert_type)

        if search and search.strip():
            pattern = f"%{search.strip()}%"
            # The analyst searches by source IP *or* username from one box.
            conditions.append(
                or_(
                    cast(Alert.source_ip, String).ilike(pattern),
                    Alert.username.ilike(pattern),
                )
            )

        return conditions

    def list_alerts(
        self,
        *,
        skip: int = 0,
        limit: int = 100,
        severity: str | None = None,
        status: str | None = None,
        alert_type: str | None = None,
        search: str | None = None,
    ) -> list[Alert]:
        """Newest-first page of alerts matching every supplied filter."""

        statement = (
            select(Alert)
            .where(
                *self._conditions(
                    severity=severity,
                    status=status,
                    alert_type=alert_type,
                    search=search,
                )
            )
            .order_by(Alert.created_at.desc(), Alert.id.desc())
            .offset(skip)
            .limit(limit)
        )

        return list(self.db.scalars(statement))

    def count_alerts(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        alert_type: str | None = None,
        search: str | None = None,
    ) -> int:
        """Number of alerts matching the filters (drives pagination)."""

        statement = select(func.count(Alert.id)).where(
            *self._conditions(
                severity=severity,
                status=status,
                alert_type=alert_type,
                search=search,
            )
        )

        return int(self.db.scalar(statement) or 0)

    def _facet_counts(
        self,
        column,
        *,
        severity: str | None = None,
        status: str | None = None,
        alert_type: str | None = None,
        search: str | None = None,
    ) -> dict[str, int]:
        statement = (
            select(column, func.count(Alert.id))
            .where(
                *self._conditions(
                    severity=severity,
                    status=status,
                    alert_type=alert_type,
                    search=search,
                )
            )
            .group_by(column)
        )

        return {
            str(value): count
            for value, count in self.db.execute(statement).all()
            if value is not None
        }

    def stats(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        alert_type: str | None = None,
        search: str | None = None,
    ) -> dict:
        """Total plus per-status/severity/type counts for the current filters."""

        filters = {
            "severity": severity,
            "status": status,
            "alert_type": alert_type,
            "search": search,
        }

        return {
            "total": self.count_alerts(**filters),
            "by_status": self._facet_counts(Alert.status, **filters),
            "by_severity": self._facet_counts(Alert.severity, **filters),
            "by_alert_type": self._facet_counts(Alert.alert_type, **filters),
        }

    def get_alert(self, alert_id: int) -> Alert | None:
        return self.db.get(Alert, alert_id)

    # ------------------------------------------------------------------
    # Triage lifecycle
    # ------------------------------------------------------------------
    def update_status(
        self,
        alert: Alert,
        *,
        target_status: str,
        actor: str,
        role: str,
        reason: str | None = None,
    ) -> Alert:
        """Validate and persist one lifecycle transition.

        Raises ``InvalidTransitionError`` (API maps it to 409) when the
        requested status is not a legal successor of the current one, and
        ``TransitionPermissionError`` (403) when the role may not perform an
        otherwise-valid transition.  On success the alert's denormalized
        snapshot (``status_updated_at/by``, ``status_reason``), one
        ``AlertStatusHistory`` audit row and one structured log line are
        written in the same transaction.
        """

        from_status = alert.status
        validate_transition(from_status, target_status, role)

        changed_at = datetime.now(timezone.utc)
        reason = reason.strip() if reason and reason.strip() else None

        alert.status = target_status
        alert.status_updated_at = changed_at
        alert.status_updated_by = actor
        alert.status_reason = reason

        self.db.add(
            AlertStatusHistory(
                alert_id=alert.id,
                from_status=from_status,
                to_status=target_status,
                changed_at=changed_at,
                changed_by=actor,
                changed_by_role=role,
                reason=reason,
            )
        )

        self.db.commit()
        self.db.refresh(alert)

        logger.info(
            "alert_status_transition alert_id=%s %s->%s actor=%s role=%s reason=%s",
            alert.id,
            from_status,
            target_status,
            actor,
            role,
            reason or "-",
        )

        return alert

    def list_status_history(self, alert_id: int) -> list[AlertStatusHistory]:
        """Newest-first audit trail of every transition of ``alert_id``."""

        statement = (
            select(AlertStatusHistory)
            .where(AlertStatusHistory.alert_id == alert_id)
            .order_by(
                AlertStatusHistory.changed_at.desc(),
                AlertStatusHistory.id.desc(),
            )
        )

        return list(self.db.scalars(statement))
