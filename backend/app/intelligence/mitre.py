"""MITRE ATT&CK structured mapping (Phase 7, section 7.11).

Maps internal detection types / alert types to structured MITRE ATT&CK
context using the official technique terminology.  Unknown mappings fail
safely via ``MitreContext(is_mapped=False)``.
"""

from app.intelligence.schemas import MitreContext

# Keyed by BOTH the brief detection key (used in sessions) and the full
# alert_type (used in alerts) so either name resolves.
MITRE_ALIASES = {
    "single_account": "single_account_bruteforce",
    "single_account_bruteforce": "single_account_bruteforce",
    "password_spray": "password_spraying",
    "password_spraying": "password_spraying",
    "distributed": "distributed_bruteforce",
    "distributed_bruteforce": "distributed_bruteforce",
    "failed_success": "failed_then_success",
    "failed_then_success": "failed_then_success",
    "credential_stuffing": "credential_stuffing",
    "low_and_slow": "low_and_slow",
}

MITRE_MAPPING: dict[str, dict[str, str]] = {
    "single_account_bruteforce": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Password guessing against a single account without "
            "reusing known passwords."
        ),
    },
    "password_spraying": {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "tactic": "Credential Access",
        "description": (
            "Attempts to use many different passwords against many "
            "different accounts to avoid account lockout."
        ),
    },
    "distributed_bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "A brute-force attempt distributed across multiple source "
            "IPs targeting a single account."
        ),
    },
    "failed_then_success": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Multiple failed authentication attempts followed by a "
            "successful authentication, consistent with credential "
            "access."
        ),
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": (
            "Large numbers of credentials collected from prior breaches "
            "attempted against many accounts."
        ),
    },
    "low_and_slow": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Deliberately low-rate brute force spread across time to "
            "evade threshold-based detection."
        ),
    },
}


def get_mitre_context(detection_type: str | None) -> MitreContext:
    """Resolve structured MITRE context for a detection/alert type."""
    if not detection_type:
        return MitreContext(
            detection_type="unknown",
            technique_id="",
            technique_name="",
            tactic="",
            description="",
            is_mapped=False,
        )

    canonical = MITRE_ALIASES.get(detection_type)
    entry = MITRE_MAPPING.get(canonical or "")

    if entry is None:
        return MitreContext(
            detection_type=detection_type,
            technique_id="",
            technique_name="",
            tactic="",
            description="",
            is_mapped=False,
        )

    return MitreContext(
        detection_type=detection_type,
        technique_id=entry["technique_id"],
        technique_name=entry["technique_name"],
        tactic=entry["tactic"],
        description=entry["description"],
        is_mapped=True,
    )


def is_valid_technique(technique_id: str | None) -> bool:
    """Validate a technique id against the mapping (criterion 7.20)."""
    if not technique_id:
        return False
    return any(
        entry["technique_id"] == technique_id
        for entry in MITRE_MAPPING.values()
    )