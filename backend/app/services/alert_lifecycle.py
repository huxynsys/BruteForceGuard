"""Alert triage lifecycle state machine.

The five canonical states live in ``app.schemas.alert.AlertStatus``; this
module defines *how* an alert may move between them and enforces the rules
so neither the API nor the browser can invent arbitrary state changes.

Rules (mirrored by ``frontend/src/lib/alerts.ts`` - keep both in sync):

* Every status may transition to every other status except itself
  (a no-op "transition" is rejected instead of silently recorded).
* Moving a **closed** alert (``resolved`` / ``false_positive``) back into an
  **active** state (``open`` / ``acknowledged`` / ``investigating``) is a
  reopen and therefore requires the ``admin`` role.
* Reclassifying between the two closed states (resolved <-> false_positive)
  is an analyst-level correction, allowed to both roles.

Nothing here touches the database; :class:`AlertService.update_status` calls
:func:`validate_transition` before persisting a change plus its audit record.
"""

from app.schemas.alert import AlertStatus

#: Active (still needs analyst attention) statuses.
ACTIVE_STATUSES: frozenset[str] = frozenset(
    {AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value, AlertStatus.INVESTIGATING.value}
)

#: Closed (terminal, but reclassifiable) statuses.
CLOSED_STATUSES: frozenset[str] = frozenset(
    {AlertStatus.RESOLVED.value, AlertStatus.FALSE_POSITIVE.value}
)

ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
TRIAGE_ROLES: frozenset[str] = frozenset({ROLE_ANALYST, ROLE_ADMIN})

#: Allowed targets for each status (the current status itself is never listed).
VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    AlertStatus.OPEN.value: frozenset(
        {
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.INVESTIGATING.value,
            AlertStatus.RESOLVED.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.ACKNOWLEDGED.value: frozenset(
        {
            AlertStatus.OPEN.value,
            AlertStatus.INVESTIGATING.value,
            AlertStatus.RESOLVED.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.INVESTIGATING.value: frozenset(
        {
            AlertStatus.OPEN.value,
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.RESOLVED.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.RESOLVED.value: frozenset(
        {
            AlertStatus.OPEN.value,
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.INVESTIGATING.value,
            AlertStatus.FALSE_POSITIVE.value,
        }
    ),
    AlertStatus.FALSE_POSITIVE.value: frozenset(
        {
            AlertStatus.OPEN.value,
            AlertStatus.ACKNOWLEDGED.value,
            AlertStatus.INVESTIGATING.value,
            AlertStatus.RESOLVED.value,
        }
    ),
}


class InvalidTransitionError(ValueError):
    """Raised when the requested status change is not a valid transition."""


class TransitionPermissionError(PermissionError):
    """Raised when the transition is valid but the role may not perform it."""


def available_transitions(from_status: str) -> frozenset[str]:
    """All statuses ``from_status`` may move to (empty for unknown statuses)."""

    return VALID_TRANSITIONS.get(from_status, frozenset())


def requires_admin(from_status: str, to_status: str) -> bool:
    """True when reopening a closed alert back into an active state."""

    return from_status in CLOSED_STATUSES and to_status in ACTIVE_STATUSES


def validate_transition(from_status: str, to_status: str, role: str) -> None:
    """Validate a lifecycle transition for ``role``.

    Raises ``InvalidTransitionError`` for an unknown status pair or a no-op
    self-transition, and ``TransitionPermissionError`` when an analyst tries
    to reopen a closed alert.  Returns ``None`` when the transition is
    allowed.
    """

    if role not in TRIAGE_ROLES:
        raise TransitionPermissionError(
            f"Unknown triage role {role!r}; expected one of {sorted(TRIAGE_ROLES)}"
        )

    allowed = available_transitions(from_status)
    if to_status not in allowed:
        if not allowed:
            raise InvalidTransitionError(
                f"Alert status {from_status!r} is not a known lifecycle state"
            )
        raise InvalidTransitionError(
            f"Invalid alert status transition {from_status!r} -> {to_status!r}; "
            f"allowed from {from_status!r}: {sorted(allowed)}"
        )

    if requires_admin(from_status, to_status) and role != ROLE_ADMIN:
        raise TransitionPermissionError(
            f"Reopening a {from_status!r} alert requires the admin role"
        )