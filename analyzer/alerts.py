"""
Alert helper functions for the IT Log Analyzer.
"""

import json
from datetime import datetime


_alert_counter = 0


def create_alert(
    rule_name,
    severity,
    source,
    source_ip,
    username,
    description,
    event_count,
    related_events,
    timestamp=None,
):
    """
    Create a security alert using the shared alert schema.
    """

    global _alert_counter

    _alert_counter += 1

    alert_id = f"ALT-{_alert_counter:04d}"

    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "rule_name": rule_name,
        "severity": severity,
        "source": source,
        "source_ip": source_ip,
        "username": username,
        "description": description,
        "event_count": event_count,
        "related_events": related_events or [],
        "status": "Open",
    }


def sort_alerts_by_timestamp(alerts):
    """
    Sort alerts by timestamp.
    Handles empty lists.
    """

    return sorted(
        alerts or [],
        key=lambda alert: alert.get("timestamp") or "",
    )


def filter_alerts_by_severity(alerts, severity):
    """
    Return alerts matching a severity level.
    """

    return [
        alert
        for alert in (alerts or [])
        if alert.get("severity") == severity
    ]


def filter_alerts_by_source(alerts, source):
    """
    Return alerts matching a log source.
    """

    return [
        alert
        for alert in (alerts or [])
        if alert.get("source") == source
    ]


def filter_alerts_by_status(alerts, status):
    """
    Return alerts matching a status.
    """

    return [
        alert
        for alert in (alerts or [])
        if alert.get("status") == status
    ]


def alerts_to_json(alerts):
    """
    Convert alerts into JSON-compatible output.
    """

    return json.dumps(alerts or [], indent=4)