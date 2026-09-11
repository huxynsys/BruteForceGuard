"""
Centralized Phase 7 security-intelligence configuration.

Everything that controls risk scoring, reputation thresholds, privileged
accounts, service sensitivity and threat-intelligence behaviour lives here
rather than being scattered across detectors or services.
"""

import os
from typing import List, Tuple


# --------------------------------------------------------------------------
# Risk scoring weights (frame for 7.2: sum must be 100)
# --------------------------------------------------------------------------
RISK_WEIGHTS: dict[str, int] = {
    "base_detection": 40,       # severity-derived baseline
    "confidence": 20,           # confidence of the detection
    "behavior": 15,             # behavioral/attack-freq context
    "threat_intelligence": 15,  # local/external indicator match
    "target_sensitivity": 10,   # privileged account + service sensitivity
}

# --------------------------------------------------------------------------
# Risk levels (7.3)
# --------------------------------------------------------------------------
RiskLevelRange = Tuple[int, int, str]

RISK_LEVELS: List[RiskLevelRange] = [
    (0, 24, "informational"),
    (25, 49, "low"),
    (50, 69, "medium"),
    (70, 84, "high"),
    (85, 100, "critical"),
]

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
SERVICE_SENSITIVITY: dict[str, str] = {
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

REPUTATION_LEVELS: List[ReputationLevelRange] = [
    (0, 19, "unknown"),
    (20, 39, "low"),
    (40, 59, "suspicious"),
    (60, 79, "high"),
    (80, 100, "hostile"),
]


def reputation_level_for_score(score: int) -> str:
    score = max(0, min(100, score))
    for low, high, level in REPUTATION_LEVELS:
        if low <= score <= high:
            return level
    return "unknown"