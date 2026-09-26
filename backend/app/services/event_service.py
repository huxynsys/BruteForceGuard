from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.auth_event import AuthEvent
from app.schemas.auth_event import AuthEventCreate


class EventService:

    def __init__(self, db: Session):
        self.db = db

    def create_event(
        self,
        event_data: AuthEventCreate,
    ) -> AuthEvent:

        event = AuthEvent(
            timestamp=event_data.timestamp,
            source=event_data.source,
            source_ip=str(event_data.source_ip),
            destination_ip=(
                str(event_data.destination_ip)
                if event_data.destination_ip
                else None
            ),
            username=event_data.username,
            result=event_data.result.value,
            service=event_data.service,
            port=event_data.port,
            hostname=event_data.hostname,
            user_agent=event_data.user_agent,
            event_id=event_data.event_id,
            raw_event=event_data.raw_event,
        )

        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event

    def get_events(
        self,
        limit: int = 100,
        skip: int = 0,
    ) -> list[AuthEvent]:

        statement = (
            select(AuthEvent)
            .order_by(AuthEvent.timestamp.desc())
            .offset(skip)
            .limit(limit)
        )

        return list(self.db.scalars(statement))

    def get_event(
        self,
        event_id: int,
    ) -> AuthEvent | None:

        statement = select(AuthEvent).where(
            AuthEvent.id == event_id
        )

        return self.db.scalar(statement)

    def get_event_groups(
        self,
        *,
        search: str | None = None,
        result: str | None = None,
        sort: str = "recent",
        skip: int = 0,
        limit: int = 20,
        events_limit: int = 20,
    ) -> tuple[list[dict], int]:
        """Group events by ``source_ip`` with server-side pagination.

        ``source_ip`` is NOT NULL and indexed on every event, so it is the
        strongest correlation identifier that exists on ``AuthEvent`` (there
        is no session/event linkage in the schema).  Attack context
        (``alert_types``, ``session_ids``) is derived from alerts sharing the
        group's source IP — real data only, never synthesized.

        Returns ``(items, total_groups)`` where each item is a plain dict
        validated by ``EventGroupResponse``.
        """
        limit = max(1, min(limit, 100))
        events_limit = max(1, min(events_limit, 100))
        skip = max(0, skip)

        # Shared WHERE clause: the aggregate, the per-group event query and
        # the total count all see the same filtered event set, so counts and
        # listings stay consistent while filters are combined.
        conditions = []
        if search:
            needle = f"%{search.strip()}%"
            conditions.append(
                AuthEvent.source_ip.ilike(needle)
                | AuthEvent.username.ilike(needle)
            )
        if result in ("success", "failure"):
            conditions.append(AuthEvent.result == result)

        success_sum = func.sum(
            case((AuthEvent.result == "success", 1), else_=0)
        )

        aggregate = (
            select(
                AuthEvent.source_ip.label("group_key"),
                func.count().label("event_count"),
                success_sum.label("success_count"),
                func.min(AuthEvent.timestamp).label("first_seen"),
                func.max(AuthEvent.timestamp).label("last_seen"),
            )
            .group_by(AuthEvent.source_ip)
        )
        for condition in conditions:
            aggregate = aggregate.where(condition)

        if sort == "events":
            aggregate = aggregate.order_by(
                func.count().desc(), func.max(AuthEvent.timestamp).desc()
            )
        elif sort == "ip":
            aggregate = aggregate.order_by(AuthEvent.source_ip.asc())
        else:  # "recent" (default)
            aggregate = aggregate.order_by(
                func.max(AuthEvent.timestamp).desc()
            )

        # Total number of groups for pagination (same filters, no paging).
        total = self.db.scalar(
            select(func.count()).select_from(aggregate.subquery())
        )

        rows = self.db.execute(
            aggregate.offset(skip).limit(limit)
        ).mappings().all()

        if not rows:
            return [], int(total or 0)

        return self._build_group_items(rows, conditions, events_limit), int(
            total or 0
        )

    def _build_group_items(
        self,
        rows,
        conditions: list,
        events_limit: int,
    ) -> list[dict]:
        group_keys = [row["group_key"] for row in rows]

        def _filtered(query):
            for condition in conditions:
                query = query.where(condition)
            return query

        # Most recent events for the page's groups (bounded per group).
        # The same filters as the aggregate apply, so the expanded rows
        # always agree with the collapsed counts.
        event_rows = list(
            self.db.scalars(
                _filtered(
                    select(AuthEvent)
                    .where(AuthEvent.source_ip.in_(group_keys))
                    .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
                )
            )
        )
        events_by_group: dict[str, list[AuthEvent]] = {
            key: [] for key in group_keys
        }
        for event in event_rows:
            bucket = events_by_group.setdefault(event.source_ip, [])
            if len(bucket) < events_limit:
                bucket.append(event)

        # usernames/services must cover ALL events in the page's groups, not
        # just the capped per-group event list, so they stay complete when a
        # group exceeds ``events_limit``.  Sorted for stable output.
        context_rows = self.db.execute(
            _filtered(
                select(
                    AuthEvent.source_ip,
                    AuthEvent.username,
                    AuthEvent.service,
                ).where(AuthEvent.source_ip.in_(group_keys))
            )
        ).all()

        usernames_by_group: dict[str, set[str]] = {
            key: set() for key in group_keys
        }
        services_by_group: dict[str, set[str]] = {
            key: set() for key in group_keys
        }
        for source_ip, username, service in context_rows:
            if username:
                usernames_by_group.setdefault(source_ip, set()).add(username)
            if service:
                services_by_group.setdefault(source_ip, set()).add(service)

        # Real attack context: alerts sharing the group's source IP.
        alert_rows = self.db.execute(
            select(Alert.source_ip, Alert.alert_type, Alert.session_id)
            .where(Alert.source_ip.in_(group_keys))
            .where(Alert.source_ip.is_not(None))
        ).all()

        alert_types_by_group: dict[str, list[str]] = {
            key: [] for key in group_keys
        }
        session_ids_by_group: dict[str, set[int]] = {
            key: set() for key in group_keys
        }
        for alert_ip, alert_type, session_id in alert_rows:
            if alert_ip in alert_types_by_group and alert_type:
                if alert_type not in alert_types_by_group[alert_ip]:
                    alert_types_by_group[alert_ip].append(alert_type)
            if alert_ip in session_ids_by_group and session_id is not None:
                session_ids_by_group[alert_ip].add(session_id)

        items = []
        for row in rows:
            key = row["group_key"]
            group_events = events_by_group.get(key, [])

            items.append(
                {
                    "group_key": key,
                    "group_field": "source_ip",
                    "event_count": int(row["event_count"]),
                    "success_count": int(row["success_count"] or 0),
                    "failure_count": int(row["event_count"])
                    - int(row["success_count"] or 0),
                    "usernames": sorted(usernames_by_group.get(key, set())),
                    "services": sorted(services_by_group.get(key, set())),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "alert_types": sorted(alert_types_by_group.get(key, [])),
                    "session_ids": sorted(
                        session_ids_by_group.get(key, set())
                    ),
                    "events": group_events,
                }
            )

        return items