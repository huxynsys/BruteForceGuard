"""Phase 7 - structured MITRE ATT&CK mapping (7.11, 7.19-7.21)."""

import pytest

from app.intelligence.mitre import (
    MITRE_MAPPING,
    get_mitre_context,
    is_valid_technique,
)


# --------------------------------------------------------------------------
# Known detection types map to structured context (criterion 7.19)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "detection_type,technique_id,technique_name",
    [
        ("single_account_bruteforce", "T1110.001", "Password Guessing"),
        ("password_spraying", "T1110.003", "Password Spraying"),
        ("distributed_bruteforce", "T1110", "Brute Force"),
        ("failed_then_success", "T1110", "Brute Force"),
        ("credential_stuffing", "T1110.004", "Credential Stuffing"),
        ("low_and_slow", "T1110", "Brute Force"),
    ],
)
def test_detection_type_maps_to_correct_technique(
    detection_type, technique_id, technique_name,
):
    context = get_mitre_context(detection_type)
    assert context.is_mapped is True
    assert context.technique_id == technique_id
    assert context.technique_name == technique_name
    assert context.tactic == "Credential Access"
    assert context.description


# --------------------------------------------------------------------------
# Brief session keys resolve through aliases
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "brief_key,technique_id",
    [
        ("single_account", "T1110.001"),
        ("password_spray", "T1110.003"),
        ("distributed", "T1110"),
        ("failed_success", "T1110"),
        ("credential_stuffing", "T1110.004"),
        ("low_and_slow", "T1110"),
    ],
)
def test_brief_session_keys_resolve(brief_key, technique_id):
    context = get_mitre_context(brief_key)
    assert context.is_mapped is True
    assert context.technique_id == technique_id


# --------------------------------------------------------------------------
# Unknown mappings fail safely (criterion 7.21)
# --------------------------------------------------------------------------
def test_unknown_detection_type_fails_safely():
    context = get_mitre_context("totally_unknown_detection")
    assert context.is_mapped is False
    assert context.technique_id == ""
    assert context.technique_name == ""


def test_none_detection_type_fails_safely():
    context = get_mitre_context(None)
    assert context.is_mapped is False


def test_all_mapped_technique_ids_are_valid():
    for detection_type, entry in MITRE_MAPPING.items():
        assert is_valid_technique(entry["technique_id"])
        assert entry["technique_name"]
        assert entry["tactic"]


# --------------------------------------------------------------------------
# Technique validation (criterion 7.20)
# --------------------------------------------------------------------------
def test_valid_technique_ids():
    assert is_valid_technique("T1110.001") is True
    assert is_valid_technique("T1110.003") is True
    assert is_valid_technique("T1110.004") is True
    assert is_valid_technique("T1110") is True


def test_invalid_technique_ids():
    assert is_valid_technique("T9999") is False
    assert is_valid_technique("") is False
    assert is_valid_technique(None) is False
