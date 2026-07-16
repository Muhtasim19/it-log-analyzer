"""Tests for Log Analyzer risk scoring."""

from analyzer.risk_score import (
    calculate_risk_score,
    classify_risk,
    normalize_severity,
)


def test_empty_alerts_return_zero_risk():
    result = calculate_risk_score([])

    assert result["score"] == 0
    assert result["raw_score"] == 0
    assert result["category"] == "Low"
    assert result["active_alerts"] == 0
    assert result["ignored_alerts"] == 0


def test_none_alerts_return_zero_risk():
    result = calculate_risk_score(None)

    assert result["score"] == 0
    assert result["category"] == "Low"


def test_active_alerts_receive_severity_points():
    alerts = [
        {
            "severity": "Critical",
            "status": "Open",
        },
        {
            "severity": "High",
            "status": "Investigating",
        },
        {
            "severity": "Medium",
            "status": "Open",
        },
        {
            "severity": "Low",
            "status": "Open",
        },
        {
            "severity": "Informational",
            "status": "Open",
        },
    ]

    result = calculate_risk_score(alerts)

    assert result["raw_score"] == 56
    assert result["score"] == 56
    assert result["category"] == "High"
    assert result["active_alerts"] == 5

    assert result["severity_counts"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 1,
        "Low": 1,
        "Informational": 1,
    }


def test_resolved_and_closed_alerts_do_not_count():
    alerts = [
        {
            "severity": "Critical",
            "status": "Resolved",
        },
        {
            "severity": "High",
            "status": "Closed",
        },
        {
            "severity": "Medium",
            "status": "Open",
        },
    ]

    result = calculate_risk_score(alerts)

    assert result["score"] == 7
    assert result["category"] == "Low"
    assert result["active_alerts"] == 1
    assert result["ignored_alerts"] == 2


def test_missing_status_is_treated_as_active():
    alerts = [
        {
            "severity": "High",
        },
    ]

    result = calculate_risk_score(alerts)

    assert result["score"] == 15
    assert result["active_alerts"] == 1


def test_severity_matching_is_case_insensitive():
    alerts = [
        {
            "severity": " critical ",
            "status": " open ",
        },
        {
            "severity": "HIGH",
            "status": "INVESTIGATING",
        },
    ]

    result = calculate_risk_score(alerts)

    assert result["score"] == 45
    assert result["category"] == "Medium"


def test_unknown_or_malformed_alerts_are_ignored():
    alerts = [
        None,
        "not an alert",
        {},
        {
            "severity": "Unknown",
            "status": "Open",
        },
        {
            "severity": "High",
            "status": 123,
        },
        {
            "severity": "Low",
            "status": "Open",
        },
    ]

    result = calculate_risk_score(alerts)

    assert result["score"] == 3
    assert result["active_alerts"] == 1
    assert result["ignored_alerts"] == 5


def test_score_is_capped_at_one_hundred():
    alerts = [
        {
            "severity": "Critical",
            "status": "Open",
        }
        for _ in range(10)
    ]

    result = calculate_risk_score(alerts)

    assert result["raw_score"] == 300
    assert result["score"] == 100
    assert result["category"] == "Critical"
    assert result["active_alerts"] == 10


def test_risk_category_boundaries():
    assert classify_risk(0) == "Low"
    assert classify_risk(24) == "Low"

    assert classify_risk(25) == "Medium"
    assert classify_risk(49) == "Medium"

    assert classify_risk(50) == "High"
    assert classify_risk(74) == "High"

    assert classify_risk(75) == "Critical"
    assert classify_risk(100) == "Critical"


def test_classification_handles_out_of_range_values():
    assert classify_risk(-100) == "Low"
    assert classify_risk(500) == "Critical"


def test_normalize_severity():
    assert normalize_severity("critical") == "Critical"
    assert normalize_severity(" HIGH ") == "High"
    assert normalize_severity("unknown") is None
    assert normalize_severity(None) is None
