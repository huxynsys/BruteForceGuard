"""Rule registry and normalized-event boundary for authentication detection."""

import logging
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import Callable

from app.core.detection_config import (
    get_rule_windows,
    get_service_thresholds,
)
from app.models.alert import Alert
from app.services.detection_service import DetectionService

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NormalizedAuthEvent:
    id: int | None
    timestamp: datetime
    source_ip: str
    result: str
    username: str | None
    service: str | None
    port: int | None


@dataclass(frozen=True)
class DetectionResult:
    rule_id: str
    detection_type: str
    session_detection_type: str
    source_ip: str | None
    username: str | None
    severity: str
    failed_attempts: int
    time_window: int
    threshold: int
    reason: str
    confidence: int
    criteria: dict[str, int]
    alert: Alert


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    detection_type: str
    detector_name: str
    session_detection_type: str
    service_family: str | None = None
    extra_parameters: tuple[tuple[str, int], ...] = ()

    def parameters(self, service: str | None) -> dict[str, int]:
        thresholds = get_service_thresholds(service)
        parameters = dict(self.extra_parameters)

        if self.detector_name == "detect_single_account_bruteforce":
            parameters.update(
                threshold=thresholds["failure_threshold"],
                window_seconds=thresholds["window_seconds"],
            )
        elif self.detector_name == "detect_password_spraying":
            parameters.update(
                minimum_users=thresholds["password_spray_users"],
                minimum_failures=thresholds["failure_threshold"] * 2,
                window_seconds=thresholds["window_seconds"],
            )
        elif self.detector_name == "detect_distributed_bruteforce":
            parameters.update(
                minimum_source_ips=thresholds["distributed_ips"],
                minimum_failures=thresholds["failure_threshold"] * 2,
                window_seconds=thresholds["window_seconds"],
            )
        elif self.detector_name == "detect_credential_stuffing":
            windows = get_rule_windows()
            parameters.update(
                minimum_users=thresholds["credential_stuffing_users"],
                minimum_failures=thresholds["credential_stuffing_failures"],
                window_seconds=windows["credential_stuffing_window_seconds"],
            )
        elif self.detector_name == "detect_failed_then_success":
            windows = get_rule_windows()
            parameters.update(
                minimum_failures=windows["failed_then_success_minimum_failures"],
                window_seconds=windows["failed_then_success_window_seconds"],
            )
        elif self.detector_name == "detect_low_and_slow":
            windows = get_rule_windows()
            parameters.update(
                minimum_failures=windows["low_and_slow_minimum_failures"],
                window_seconds=windows["low_and_slow_window_seconds"],
                minimum_active_intervals=windows[
                    "low_and_slow_minimum_active_intervals"
                ],
            )
        return parameters


def normalize_event(event: object) -> NormalizedAuthEvent | None:
    """Extract and validate the fields required by the detection rules."""
    try:
        timestamp = getattr(event, "timestamp")
        result = str(getattr(event, "result")).strip().lower()
        source_ip = str(ip_address(str(getattr(event, "source_ip"))))
        if not isinstance(timestamp, datetime) or result not in {"failure", "success"}:
            return None

        username_value = getattr(event, "username", None)
        service_value = getattr(event, "service", None)
        port_value = getattr(event, "port", None)
        username = str(username_value).strip() if username_value is not None else None
        service = str(service_value).strip().lower() if service_value else None
        port = int(port_value) if port_value is not None else None
        if port is not None and not 1 <= port <= 65535:
            port = None

        return NormalizedAuthEvent(
            id=getattr(event, "id", None),
            timestamp=timestamp,
            source_ip=source_ip,
            result=result,
            username=username or None,
            service=service or None,
            port=port,
        )
    except (AttributeError, TypeError, ValueError):
        return None


def service_family(event: NormalizedAuthEvent) -> str | None:
    service = (event.service or "").replace("_", "-").replace(" ", "-")
    if service in {"ssh", "sshd", "secure-shell"}:
        return "ssh"
    if service in {"rdp", "ms-rdp", "remote-desktop"}:
        return "rdp"
    if service in {"web", "http", "https", "http-auth", "web-auth"}:
        return "web"
    if service in {"api", "rest", "graphql"}:
        return "api"
    if event.port == 22:
        return "ssh"
    if event.port == 3389:
        return "rdp"
    if event.port in {80, 443}:
        return "web"
    return None


RULES = (
    DetectionRule("ssh_bruteforce", "single_account_bruteforce", "detect_single_account_bruteforce", "single_account", "ssh"),
    DetectionRule("rdp_bruteforce", "single_account_bruteforce", "detect_single_account_bruteforce", "single_account", "rdp"),
    DetectionRule("web_auth_bruteforce", "single_account_bruteforce", "detect_single_account_bruteforce", "single_account", "web"),
    DetectionRule("api_auth_bruteforce", "single_account_bruteforce", "detect_single_account_bruteforce", "single_account", "api"),
    DetectionRule("generic_auth_bruteforce", "single_account_bruteforce", "detect_single_account_bruteforce", "single_account"),
    DetectionRule("password_spraying", "password_spraying", "detect_password_spraying", "password_spray"),
    DetectionRule("distributed_bruteforce", "distributed_bruteforce", "detect_distributed_bruteforce", "distributed"),
    DetectionRule("failed_then_success", "failed_then_success", "detect_failed_then_success", "failed_success"),
    DetectionRule("credential_stuffing", "credential_stuffing", "detect_credential_stuffing", "credential_stuffing"),
    DetectionRule("low_and_slow", "low_and_slow", "detect_low_and_slow", "low_and_slow"),
)


def _result_threshold(parameters: dict[str, int]) -> int:
    for key in ("threshold", "minimum_failures"):
        if key in parameters:
            return parameters[key]
    return 1


class DetectionEngine:
    """Runs independent rule definitions over a normalized authentication event."""

    def __init__(
        self,
        detection_service: DetectionService,
        rules: tuple[DetectionRule, ...] = RULES,
    ):
        self.detection_service = detection_service
        self.rules = rules

    def run(self, event: object) -> list[DetectionResult]:
        normalized = normalize_event(event)
        if normalized is None:
            logger.warning("Skipping detection for malformed authentication event")
            return []

        family = service_family(normalized)
        results = []
        for rule in self.rules:
            if rule.detector_name == "detect_single_account_bruteforce":
                if rule.service_family != family and not (
                    rule.service_family is None and family is None
                ):
                    continue

            parameters = rule.parameters(family or normalized.service)
            try:
                detector: Callable = getattr(self.detection_service, rule.detector_name)
                alert = detector(normalized, **parameters)
            except Exception:
                logger.exception(
                    "Detector %s failed for event %s (rule_id=%s)",
                    rule.detector_name,
                    normalized.id,
                    rule.rule_id,
                )
                continue

            if alert is None:
                continue

            evidence = alert.evidence or {}
            failed_attempts = evidence.get(
                "failure_count", evidence.get("failed_attempts", 0)
            )
            results.append(
                DetectionResult(
                    rule_id=rule.rule_id,
                    detection_type=rule.detection_type,
                    session_detection_type=rule.session_detection_type,
                    source_ip=str(alert.source_ip) if alert.source_ip else None,
                    username=alert.username,
                    severity=alert.severity,
                    failed_attempts=int(failed_attempts),
                    time_window=int(evidence.get("window_seconds", parameters.get("window_seconds", 0))),
                    threshold=_result_threshold(parameters),
                    reason=alert.description,
                    confidence=int(alert.confidence),
                    criteria={
                        key: value
                        for key, value in parameters.items()
                        if key not in {"threshold", "minimum_failures", "window_seconds"}
                    },
                    alert=alert,
                )
            )

        try:
            # Batch-persist any alert merges folded during this run: repeated
            # detections flush into the transaction and land here in one commit,
            # so an active attack costs one durable write per ingested event
            # instead of one per repeated detection.
            self.detection_service.db.commit()
        except Exception:
            logger.exception("Detector merge commit failed for event")

        return results