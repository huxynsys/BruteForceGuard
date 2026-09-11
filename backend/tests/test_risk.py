import pytest

from app.intelligence.config import (
    RISK_BEHAVIOR_WEIGHT,
    RISK_CONFIDENCE_WEIGHT,
    RISK_LEVELS,
    RISK_SENSITIVITY_WEIGHT,
    RISK_TI_WEIGHT,
    SEVERITY_RISK_BASE,
    risk_level_for_score,
)
from app.intelligence.risk import RiskScorer


@pytest.fixture
def risk_scorer():
    return RiskScorer()


# --------------------------------------------------------------------------
# Test base_detection_factor (criterion 7.7)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "severity, expected_value, expected_reason",
    [
        ("informational", 5, "Informational severity detection"),
        ("low", 10, "Low severity detection"),
        ("medium", 20, "Medium severity detection"),
        ("high", 30, "High severity detection"),
        ("critical", 40, "Critical severity detection"),
        ("unknown", 5, "Unknown severity detection"),  # Defaults to informational base
        (None, 5, "None severity detection"),  # Defaults to informational base
    ],
)
def test_base_detection_factor(
    risk_scorer, severity, expected_value, expected_reason
):
    factor = risk_scorer.base_detection_factor(severity)
    assert factor.factor == "detection_severity"
    assert factor.value == expected_value
    assert factor.reason == expected_reason


# --------------------------------------------------------------------------
# Test confidence_factor (criterion 7.8)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "confidence, expected_value",
    [
        (0, 0),
        (25, round(0.25 * RISK_CONFIDENCE_WEIGHT)),
        (50, round(0.50 * RISK_CONFIDENCE_WEIGHT)),
        (75, round(0.75 * RISK_CONFIDENCE_WEIGHT)),
        (100, RISK_CONFIDENCE_WEIGHT),
        (150, RISK_CONFIDENCE_WEIGHT),  # Capped at 100
        (-10, 0),  # Capped at 0
    ],
)
def test_confidence_factor(risk_scorer, confidence, expected_value):
    factor = risk_scorer.confidence_factor(confidence)
    assert factor.factor == "confidence"
    assert factor.value == expected_value
    assert factor.reason == f"Detection confidence {confidence}%"



# --------------------------------------------------------------------------
# Test behavior_factor (criterion 7.9)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "failure_count, distinct_users, distinct_services, source_reputation_level, expected_value, expected_reason",
    [
        (0, 0, 0, None, 0, "Limited behavioral context"),
        (1, 0, 0, None, 2, "Limited behavioral context"), # Score 2, but no reason appended. Default reason.
        (5, 0, 0, None, 4, "5 failed attempts"),
        (0, 1, 0, None, 0, "Limited behavioral context"),
        (0, 2, 0, None, 1, "Limited behavioral context"), # Score 1, but no reason appended. Default reason.
        (0, 5, 0, None, 3, "5 targeted accounts"),
        (0, 0, 1, None, 0, "Limited behavioral context"),
        (0, 0, 2, None, 2, "2 targeted services"),
        (0, 0, 0, "suspicious", 0, "Limited behavioral context"), # Reputation alone doesn\'t add to score.
        (0, 0, 0, "high", 4, "source reputation high"),
        (0, 0, 0, "hostile", 4, "source reputation hostile"),
        (5, 5, 2, "high", 4 + 3 + 2 + 4, "5 failed attempts; 5 targeted accounts; 2 targeted services; source reputation high"),
        (10, 10, 5, "hostile", 13, "10 failed attempts; 10 targeted accounts; 5 targeted services; source reputation hostile"), # Sum 13, capped at 15.
    ],
)
def test_behavior_factor(
    risk_scorer,
    failure_count,
    distinct_users,
    distinct_services,
    source_reputation_level,
    expected_value,
    expected_reason,
):
    factor = risk_scorer.behavior_factor(
        failure_count=failure_count,
        distinct_users=distinct_users,
        distinct_services=distinct_services,
        source_reputation_level=source_reputation_level,
    )
    assert factor.factor == "attack_frequency"
    assert factor.value == min(expected_value, RISK_BEHAVIOR_WEIGHT) # Ensure the value is capped


# --------------------------------------------------------------------------
# Test threat_intel_factor (criterion 7.10)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "known, confidence, source, expected_value, expected_reason",
    [
        (False, None, None, 0, "No threat-intelligence match"),
        (True, None, None, 8, "Known indicator from local (confidence 50%)"), # round(0.50 * 15) = 8
        (True, 0, "test_source", round((max(0, min(100, 0)) / 100) * RISK_TI_WEIGHT), "Known indicator from test_source (confidence 0%)"),
        (True, 75, "another_source", 11, "Known indicator from another_source (confidence 75%)"), # round(0.75 * 15) = 11
        (True, 100, "final_source", RISK_TI_WEIGHT, "Known indicator from final_source (confidence 100%)"),
        (True, 150, "capped_source", RISK_TI_WEIGHT, "Known indicator from capped_source (confidence 150%)"), # Reason uses input confidence
        (True, -10, "negative_source", 0, "Known indicator from negative_source (confidence -10%)"), # Reason uses input confidence
    ],
)
def test_threat_intel_factor(
    risk_scorer, known, confidence, source, expected_value, expected_reason
):
    factor = risk_scorer.threat_intel_factor(
        known=known,
        confidence=confidence,
        source=source,
    )
    assert factor.factor == "threat_intelligence"
    assert factor.value == expected_value
    assert factor.reason == expected_reason


# --------------------------------------------------------------------------
# Test sensitivity_factor (criterion 7.11)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "privileged_user, service_sensitivity, expected_value, expected_reason",
    [
        (False, "low", 0, "No target sensitivity signal"),
        (True, "low", 6, "Privileged account targeted"),
        (False, "medium", 4, "medium-sensitivity service"),
        (False, "high", 4, "high-sensitivity service"),
        (True, "medium", 6 + 4, "Privileged account targeted; medium-sensitivity service"),
        (True, "high", 6 + 4, "Privileged account targeted; high-sensitivity service"),
        (True, "unknown", 6, "Privileged account targeted"),
        (False, "unknown", 0, "No target sensitivity signal"),
    ],
)
def test_sensitivity_factor(
    risk_scorer, privileged_user, service_sensitivity, expected_value, expected_reason
):
    factor = risk_scorer.sensitivity_factor(
        privileged_user=privileged_user,
        service_sensitivity=service_sensitivity,
    )
    assert factor.factor == "target_sensitivity"
    assert factor.value == min(expected_value, RISK_SENSITIVITY_WEIGHT) # Ensure value is capped


# --------------------------------------------------------------------------
# Test score method (integration of all factors and total score, 7.12-7.13)
# --------------------------------------------------------------------------
def test_score_method_minimum_values(risk_scorer):
    result = risk_scorer.score(severity="informational", confidence=0)
    assert result.risk_score == 5 # base detection for informational
    assert result.risk_level == "informational"
    assert len(result.risk_factors) == 5
    assert sum(f.value for f in result.risk_factors) == result.risk_score
    for factor in result.risk_factors:
        assert factor.reason

def test_score_method_maximum_values(risk_scorer):
    result = risk_scorer.score(
        severity="critical",
        confidence=100,
        failure_count=10,
        distinct_users=10,
        distinct_services=5,
        source_reputation_level="hostile",
        ti_known=True,
        ti_confidence=100,
        ti_source="global_intel",
        privileged_user=True,
        service_sensitivity="high",
    )
    assert result.risk_score == 98 # 40 (base) + 20 (conf) + 13 (behavior) + 15 (ti) + 10 (sensitivity) = 98
    assert result.risk_level == "critical"
    assert len(result.risk_factors) == 5
    assert sum(f.value for f in result.risk_factors) == result.risk_score
    for factor in result.risk_factors:
        assert factor.reason

def test_score_method_mid_range_values(risk_scorer):
    result = risk_scorer.score(
        severity="medium",
        confidence=50,
        failure_count=3,
        distinct_users=1,
        distinct_services=1,
        source_reputation_level="low",
        ti_known=True,
        ti_confidence=50,
        ti_source="local",
        privileged_user=False,
        service_sensitivity="medium", # Corrected to sensitivity LEVEL
    )
    # Expected calculations:
    # base_detection: medium -> 20
    # confidence: 50% of 20 -> 10
    # behavior: failure_count=3 -> 2 (no reason appended, default "Limited behavioral context")
    # threat_intelligence: known=True, confidence=50% of 15 -> round(7.5) -> 8
    # target_sensitivity: service_sensitivity="medium" -> 4
    # Total: 20 + 10 + 2 + 8 + 4 = 44
    expected_score = 20 + 10 + 2 + 8 + 4 # 44
    assert result.risk_score == expected_score
    assert result.risk_level == risk_level_for_score(expected_score)
    assert len(result.risk_factors) == 5
    assert sum(f.value for f in result.risk_factors) == result.risk_score

def test_score_method_factor_reasons_present(risk_scorer):
    result = risk_scorer.score(severity="low", confidence=60)
    for factor in result.risk_factors:
        assert factor.reason is not None and len(factor.reason) > 0

def test_score_total_clamped_to_100(risk_scorer):
    result = risk_scorer.score(
        severity="critical",
        confidence=100,
        failure_count=10,
        distinct_users=10,
        distinct_services=10,
        source_reputation_level="hostile",
        ti_known=True,
        ti_confidence=100,
        ti_source="global_intel",
        privileged_user=True,
        service_sensitivity="high",
    )
    assert result.risk_score <= 100

def test_score_level_boundaries():
    assert risk_level_for_score(0) == "informational"
    assert risk_level_for_score(24) == "informational"
    assert risk_level_for_score(25) == "low"
    assert risk_level_for_score(49) == "low"
    assert risk_level_for_score(50) == "medium"
    assert risk_level_for_score(69) == "medium"
    assert risk_level_for_score(70) == "high"
    assert risk_level_for_score(84) == "high"
    assert risk_level_for_score(85) == "critical"
    assert risk_level_for_score(100) == "critical"
    assert risk_level_for_score(-1) == "informational"
    assert risk_level_for_score(101) == "critical"

def test_determinism(risk_scorer):
    """Scores must be deterministic given identical inputs."""
    result1 = risk_scorer.score(
        severity="medium", confidence=50, failure_count=5,
        distinct_users=5, distinct_services=2,
        source_reputation_level="high", ti_known=True,
        ti_confidence=75, ti_source="local",
        privileged_user=True, service_sensitivity="ssh"
    )
    result2 = risk_scorer.score(
        severity="medium", confidence=50, failure_count=5,
        distinct_users=5, distinct_services=2,
        source_reputation_level="high", ti_known=True,
        ti_confidence=75, ti_source="local",
        privileged_user=True, service_sensitivity="ssh"
    )
    assert result1.risk_score == result2.risk_score
    assert result1.risk_level == result2.risk_level

