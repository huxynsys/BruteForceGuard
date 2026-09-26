"""Alert querying and the analyst triage lifecycle.

The alerts page is the authoritative detailed view of detections, so the
list query needs real server-side filtering/pagination and triage status
changes must be persisted.  All alert database access lives here, mirroring
``EventService`` and ``SessionService``.
"""

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert


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
    def update_status(self, alert: Alert, status: str) -> Alert:
        """Persist a triage transition (open -> acknowledged -> resolved...)."""

        alert.status = status

        self.db.commit()
        self.db.refresh(alert)

        return alert
