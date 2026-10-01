"""Structured alert explainability.

Every alert must be self-explanatory for an analyst: which rule fired, with
what threshold, against which target, over which window, and what counts were
actually observed.  :func:`build_alert_explanation` assembles that context from
data the detection engine already recorded - the alert columns, the rule
configuration (``app.core.detection_config``) and an allow-list of scalar
evidence keys - and composes a human-readable sentence from those fields.

Design rules:

* The sentence is *generated* from the structured fields, never hard-coded per
  alert type, so any change to the counts, target, window or threshold is
  reflected in the wording automatically.
* Only allow-listed scalar evidence values are read.  The raw evidence blob,
  collector payloads, credentials, tokens and exception text never enter the
  explanation.
* Unknown alert types (``get_detection_rule`` returned ``None``) still get an
  explanation built from the recorded evidence, with ``rule_name``/``threshold``
  reported as ``None`` instead of a fabricated value.
"""

from app.models.alert import Alert
from app.schemas.alert import AlertExplanation

#: The only ``alerts.evidence`` keys that may feed the failure count.  Detectors
#: historically used both names (``failed_then_success`` writes ``failed_attempts``).
FAILURE_COUNT_KEYS = ("failure_count", "failed_attempts")


def _as_int(value) -> int | None:
    """Coerce an evidence value to ``int``; anything else becomes ``None``."""

    if isinstance(value, bool) or value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_window(seconds: int) -> str:
    """Humanize a window: ``300`` -> ``"5 minutes"``, ``3600`` -> ``"1 hour"``."""

    if seconds <= 0:
        return f"{seconds} seconds"
    if seconds % 3600 == 0:
        amount, unit = seconds // 3600, "hour"
    elif seconds % 60 == 0:
        amount, unit = seconds // 60, "minute"
    else:
        amount, unit = seconds, "second"

    return f"{amount} {unit}{'' if amount == 1 else 's'}"


def _compose_text(
    *,
    failure_count: int | None,
    success_count: int,
    detection_type: str,
    rule_name: str | None,
    service: str | None,
    source_ip: str | None,
    username: str | None,
    distinct_users: int,
    distinct_source_ips: int,
    window_seconds: int | None,
    threshold: int | None,
) -> str:
    """Compose the analyst-facing sentence from the structured fields.

    Clauses are only added when the corresponding field exists, so a
    distributed attack (no single source IP) or a spray (no single target
    user) still produces a grammatical, accurate sentence.
    """

    if failure_count is not None:
        service_prefix = f"{service.upper()} " if service else ""
        attempts = "attempt" if failure_count == 1 else "attempts"
        subject = f"{failure_count} failed {service_prefix}authentication {attempts}"
    else:
        subject = f"A {rule_name or detection_type} detection"

    clauses: list[str] = []

    if source_ip:
        clauses.append(f"from {source_ip}")
    if username:
        clauses.append(f"against user {username}")
    elif distinct_users > 1:
        clauses.append(f"across {distinct_users} distinct accounts")
    if success_count > 0:
        clauses.append("followed by a successful login")
    if distinct_source_ips > 1:
        clauses.append(f"from {distinct_source_ips} distinct source IPs")
    if window_seconds is not None and window_seconds > 0:
        clauses.append(f"within {_format_window(window_seconds)}")

    body = " ".join([subject, *clauses])

    if threshold is None:
        # Unknown rule: still explain what was observed, without fabricating
        # a threshold.  Subject is singular when no failure count exists.
        if failure_count is None:
            tail = "was recorded by the detection engine."
        else:
            verb = "was" if failure_count == 1 else "were"
            tail = f"{verb} recorded by the detection engine."
    elif failure_count is None:
        tail = f"was recorded against a configured threshold of {threshold}."
    elif failure_count > threshold:
        tail = f"exceeded the configured threshold of {threshold}."
    elif failure_count == threshold:
        tail = f"reached the configured threshold of {threshold}."
    else:
        tail = f"remained below the configured threshold of {threshold}."

    return f"{body} {tail}"


def _compose_reason(
    *,
    failure_count: int | None,
    threshold: int | None,
    rule_name: str | None,
) -> str:
    """Short machine-readable reason derived from the threshold comparison."""

    if threshold is None:
        if rule_name:
            return f"{rule_name} matched without a known threshold."
        return "Rule parameters unavailable; recorded evidence only."
    if failure_count is None:
        return f"Configured threshold {threshold}; observed count unavailable."
    if failure_count > threshold:
        return f"{failure_count} failures exceeded the threshold of {threshold}."
    if failure_count == threshold:
        return f"{failure_count} failures reached the threshold of {threshold}."

    return f"{failure_count} failures remained below the threshold of {threshold}."


def build_alert_explanation(alert: Alert, rule: dict | None) -> AlertExplanation:
    """Build the structured explanation for one alert.

    ``rule`` is the output of ``get_detection_rule`` (or ``None`` for alert
    types the engine no longer knows).  All values come from the alert record,
    its evidence allow-list and the rule configuration - nothing else.
    """

    evidence = alert.evidence if isinstance(alert.evidence, dict) else {}

    failure_count: int | None = None
    for key in FAILURE_COUNT_KEYS:
        failure_count = _as_int(evidence.get(key))
        if failure_count is not None:
            break

    success_count = _as_int(evidence.get("success_count"))
    if success_count is None:
        success_count = 1 if evidence.get("successful_login") else 0

    distinct_users = _as_int(evidence.get("distinct_users")) or 0
    distinct_source_ips = _as_int(evidence.get("distinct_source_ips")) or 0

    rule_name = rule.get("label") if rule else None
    threshold = _as_int(rule.get("threshold")) if rule else None
    threshold_label = rule.get("threshold_label") if rule else None

    # The window the detector actually used always wins over the current
    # configuration (the rule values are re-read at response time).
    window_seconds = _as_int(evidence.get("window_seconds"))
    if window_seconds is None and rule:
        window_seconds = _as_int(rule.get("window_seconds"))

    source_ip = str(alert.source_ip) if alert.source_ip else None

    return AlertExplanation(
        detection_type=alert.alert_type,
        rule_name=rule_name,
        threshold=threshold,
        threshold_label=threshold_label,
        observed_value=failure_count,
        window_seconds=window_seconds,
        failure_count=failure_count,
        success_count=success_count,
        source_ip=source_ip,
        username=alert.username,
        service=alert.service,
        reason=_compose_reason(
            failure_count=failure_count,
            threshold=threshold,
            rule_name=rule_name,
        ),
        detected_at=alert.created_at,
        text=_compose_text(
            failure_count=failure_count,
            success_count=success_count,
            detection_type=alert.alert_type,
            rule_name=rule_name,
            service=alert.service,
            source_ip=source_ip,
            username=alert.username,
            distinct_users=distinct_users,
            distinct_source_ips=distinct_source_ips,
            window_seconds=window_seconds,
            threshold=threshold,
        ),
    )
