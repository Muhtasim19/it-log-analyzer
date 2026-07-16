from analyzer.alerts import (
    create_alert,
    sort_alerts_by_timestamp,
    filter_alerts_by_severity,
    filter_alerts_by_source,
    filter_alerts_by_status,
    alerts_to_json,
)


def test_create_alert():
    alert = create_alert(
        "Repeated Failed Logins",
        "High",
        "linux_auth",
        "192.168.1.50",
        "admin",
        "Five failed login attempts.",
        5,
        [],
        "2026-07-15T21:30:00Z",
    )

    assert alert["alert_id"].startswith("ALT-")
    assert alert["severity"] == "High"
    assert alert["status"] == "Open"


def test_sort_alerts_by_timestamp():
    alerts = [
        {"timestamp": "2026-07-15T21:05:00Z"},
        {"timestamp": "2026-07-15T21:01:00Z"},
    ]

    sorted_alerts = sort_alerts_by_timestamp(alerts)

    assert sorted_alerts[0]["timestamp"] == "2026-07-15T21:01:00Z"


def test_filter_alerts():
    alerts = [
        {
            "severity": "High",
            "source": "linux_auth",
            "status": "Open",
        },
        {
            "severity": "Low",
            "source": "web_log",
            "status": "Closed",
        },
    ]

    assert len(filter_alerts_by_severity(alerts, "High")) == 1
    assert len(filter_alerts_by_source(alerts, "web_log")) == 1
    assert len(filter_alerts_by_status(alerts, "Open")) == 1


def test_alerts_to_json():
    result = alerts_to_json([])

    assert result == "[]"