"""Tests for shared Log Analyzer configuration."""

from analyzer.config import (
    ALERT_REQUIRED_FIELDS,
    ALERT_SEVERITIES,
    ALERT_STATUSES,
    EVENT_REQUIRED_FIELDS,
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_MINUTES,
)


def test_event_schema_contains_standard_fields():
    expected_fields = {
        "timestamp",
        "source",
        "event_type",
        "source_ip",
        "username",
        "status",
        "message",
        "raw_log",
    }

    assert expected_fields.issubset(set(EVENT_REQUIRED_FIELDS))


def test_alert_schema_contains_standard_fields():
    expected_fields = {
        "alert_id",
        "timestamp",
        "rule_name",
        "severity",
        "source",
        "description",
        "event_count",
        "status",
    }

    assert expected_fields.issubset(set(ALERT_REQUIRED_FIELDS))


def test_allowed_alert_values():
    assert "Critical" in ALERT_SEVERITIES
    assert "High" in ALERT_SEVERITIES
    assert "Open" in ALERT_STATUSES
    assert "Closed" in ALERT_STATUSES


def test_failed_login_defaults():
    assert FAILED_LOGIN_THRESHOLD == 5
    assert FAILED_LOGIN_WINDOW_MINUTES == 10