"""
Centralized Phase 7 security-intelligence configuration.

Everything that controls risk scoring, reputation thresholds, privileged
accounts, service sensitivity and threat-intelligence behaviour lives here
rather than being scattered across detectors or services.

Runtime configurability (Part 5)
--------------------------------
The important risk parameters can be overridden through environment
variables so a deployment can tune behaviour without code changes:

    RISK_WEIGHTS             e.g. "base_detection:40,confidence:20,behavior:15,threat_intelligence:15,target_sensitivity:10"
    RISK_LEVEL_BOUNDARIES    e.g. "25,50,70,85"  (start of low/medium/high/critical)
    REPUTATION_LEVEL_BOUNDARIES e.g. "20,40,60,80"
    PRIVILEGED_USERS         e.g. "root,administrator,admin"
    SERVICE_SENSITIVITY      e.g. "ssh:high,rdp:high,vpn:high"

Every loader validates its input so an invalid configuration can never
produce invalid risk scoring (weights must sum to 100, boundaries must be
strictly ordered and within 0-100).  Safe defaults are identical to the
canonical Phase 7 values, so existing behaviour/tests are unchanged.
"""

import os
from typing import List, Tuple

# --------------------------------------------------------------------------
# Risk scoring weights (frame for 7.2: sum must be 100)
# --------------------------------------------------------------------------
_DEFAULT_RISK_WEIGHTS: dict[str, int] = {
    "base_detection": 40,       # severity-derived baseline
    "confidence": 20,           # confidence of the detection
    "behavior": 15,             # behavioral/attack-freq context
    "threat_intelligence": 15,  # local/external indicator match
    "target_sensitivity": 10,   # privileged account + service sensitivity
}

VALID_RISK_FACTORS = frozenset(_DEFAULT_RISK_WEIGHTS.keys())


def validate_risk_weights(weights: dict[str, int]) -> dict[str, int]:
    """Validate risk weights: known keys, non-negative, sum == 100.

    Raises ``ValueError`` on invalid input so the app fails fast instead of
    producing out-of-range risk scores (Part 5 validation).
    """
    if set(weights.keys()) != VALID_RISK_FACTORS:
        raise ValueError(
            "RISK_WEIGHTS must define exactly the factors "
            f"{sorted(VALID_RISK_FACTORS)}; got {sorted(weights.keys())}"
        )
    for factor, value in weights.items():
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"RISK_WEIGHTS[{factor}] must be a non-negative integer")
    if sum(weights.values()) != 100:
        raise ValueError(
            f"RISK_WEIGHTS must sum to 100 (got {sum(weights.values())})"
        )
    return weights


def _load_risk_weights() -> dict[str, int]:
    raw = os.getenv("RISK_WEIGHTS")
    if not raw:
        return dict(_DEFAULT_RISK_WEIGHTS)
    parsed: dict[str, int] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Invalid RISK_WEIGHTS entry: {part!r}")
        key, _, value = part.partition(":")
        parsed[key.strip()] = int(value.strip())
    return validate_risk_weights(parsed)


RISK_WEIGHTS: dict[str, int] = _load_risk_weights()


# --------------------------------------------------------------------------
# Risk levels (7.3)
# --------------------------------------------------------------------------
RiskLevelRange = Tuple[int, int, str]

_DEFAULT_RISK_LEVEL_BOUNDARIES = [25, 50, 70, 85]  # start of low/med/high/crit


def validate_risk_level_boundaries(boundaries: List[int]) -> List[int]:
    """Boundaries must be 4 strictly ascending integers within (0..100)."""
    if len(boundaries) != 4:
        raise ValueError("RISK_LEVEL_BOUNDARIES must contain exactly 4 values")
    for b in boundaries:
        if not isinstance(b, int):
            raise ValueError("RISK_LEVEL_BOUNDARIES must be integers")
    if not (0 < boundaries[0] < boundaries[1] < boundaries[2] < boundaries[3] < 100):
        raise ValueError("RISK_LEVEL_BOUNDARIES must be strictly increasing within 0-100")
    return boundaries


def _load_risk_levels() -> List[RiskLevelRange]:
    raw = os.getenv("RISK_LEVEL_BOUNDARIES")
    boundaries = _DEFAULT_RISK_LEVEL_BOUNDARIES
    if raw:
        boundaries = validate_risk_level_boundaries(
            [int(x.strip()) for x in raw.split(",") if x.strip() != ""]
        )
    names = ["informational", "low", "medium", "high", "critical"]
    levels: List[RiskLevelRange] = []
    prev_high = 0
    for i, start in enumerate(boundaries):
        levels.append((prev_high, start - 1, names[i]))
        prev_high = start
    levels.append((prev_high, 100, names[4]))
    return levels


RISK_LEVELS: List[RiskLevelRange] = _load_risk_levels()

SEVERITY_RISK_BASE: dict[str, int] = {
    "informational": 5,
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

RISK_CONFIDENCE_WEIGHT = RISK_WEIGHTS["confidence"]          # 20
RISK_BEHAVIOR_WEIGHT = RISK_WEIGHTS["behavior"]              # 15
RISK_TI_WEIGHT = RISK_WEIGHTS["threat_intelligence"]         # 15
RISK_SENSITIVITY_WEIGHT = RISK_WEIGHTS["target_sensitivity"]  # 10


def risk_level_for_score(score: int) -> str:
    """Map a 0-100 risk score to a normalized risk level (7.3)."""
    score = max(0, min(100, score))
    for low, high, level in RISK_LEVELS:
        if low <= score <= high:
            return level
    return "informational"


def validate_risk_config() -> None:
    """Run all risk-configuration validators (used by health checks)."""
    validate_risk_weights(RISK_WEIGHTS)
    validate_risk_level_boundaries(
        [level[0] for level in RISK_LEVELS if level[0] != 0]
    )



# --------------------------------------------------------------------------
# Privileged accounts (7.14) - configurable, case-insensitive
# --------------------------------------------------------------------------
def _privileged_users() -> set[str]:
    raw = os.getenv("PRIVILEGED_USERS", "root,administrator,admin")
    return {user.strip().lower() for user in raw.split(",") if user.strip()}


PRIVILEGED_USERS: set[str] = _privileged_users()


def is_privileged_user(username: str | None) -> bool:
    if not username:
        return False
    return username.strip().lower() in PRIVILEGED_USERS


# --------------------------------------------------------------------------
# Service sensitivity (7.15)
# --------------------------------------------------------------------------
_DEFAULT_SERVICE_SENSITIVITY: dict[str, str] = {
    "ssh": "high",
    "rdp": "high",
    "vpn": "high",
    "web": "medium",
    "http": "medium",
    "https": "medium",
    "ftp": "medium",
    "smtp": "medium",
    "ldap": "medium",
    "imap": "low",
    "pop3": "low",
    "telnet": "low",
    "unknown": "low",
}

VALID_SENSITIVITY_LEVELS = frozenset({"high", "medium", "low", "unknown"})


def _load_service_sensitivity() -> dict[str, str]:
    raw = os.getenv("SERVICE_SENSITIVITY")
    if not raw:
        return dict(_DEFAULT_SERVICE_SENSITIVITY)
    parsed: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"Invalid SERVICE_SENSITIVITY entry: {part!r}")
        service, _, level = part.partition(":")
        level = level.strip().lower()
        if level not in VALID_SENSITIVITY_LEVELS:
            raise ValueError(
                f"Invalid sensitivity level {level!r} for service {service!r}"
            )
        parsed[service.strip().lower()] = level
    return parsed


SERVICE_SENSITIVITY: dict[str, str] = _load_service_sensitivity()

SERVICE_SENSITIVITY_ORDER: dict[str, int] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


def service_sensitivity(service: str | None) -> str:
    if service:
        normalized = service.strip().lower()
        if normalized in SERVICE_SENSITIVITY:
            return SERVICE_SENSITIVITY[normalized]
    return "unknown"


# --------------------------------------------------------------------------
# Reputation thresholds (7.8)
# --------------------------------------------------------------------------
ReputationLevelRange = Tuple[int, int, str]

_DEFAULT_REPUTATION_BOUNDARIES = [20, 40, 60, 80]  # low/suspicious/high/hostile


def validate_reputation_boundaries(boundaries: List[int]) -> List[int]:
    if len(boundaries) != 4:
        raise ValueError("REPUTATION_LEVEL_BOUNDARIES must contain exactly 4 values")
    for b in boundaries:
        if not isinstance(b, int):
            raise ValueError("REPUTATION_LEVEL_BOUNDARIES must be integers")
    if not (0 < boundaries[0] < boundaries[1] < boundaries[2] < boundaries[3] < 100):
        raise ValueError(
            "REPUTATION_LEVEL_BOUNDARIES must be strictly increasing within 0-100"
        )
    return boundaries


def _load_reputation_levels() -> List[ReputationLevelRange]:
    raw = os.getenv("REPUTATION_LEVEL_BOUNDARIES")
    boundaries = _DEFAULT_REPUTATION_BOUNDARIES
    if raw:
        boundaries = validate_reputation_boundaries(
            [int(x.strip()) for x in raw.split(",") if x.strip() != ""]
        )
    names = ["unknown", "low", "suspicious", "high", "hostile"]
    levels: List[ReputationLevelRange] = []
    prev_high = 0
    for i, start in enumerate(boundaries):
        levels.append((prev_high, start - 1, names[i]))
        prev_high = start
    levels.append((prev_high, 100, names[4]))
    return levels


REPUTATION_LEVELS: List[ReputationLevelRange] = _load_reputation_levels()


def reputation_level_for_score(score: int) -> str:
    score = max(0, min(100, score))
    for low, high, level in REPUTATION_LEVELS:
        if low <= score <= high:
            return level
    return "unknown"
