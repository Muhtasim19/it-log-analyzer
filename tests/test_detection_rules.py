from analyzer.detection_rules import run_detection_rules


def test_repeated_failed_logins_creates_alert():
    events = []

    times = [
        "2026-07-15T21:00:00Z",
        "2026-07-15T21:02:00Z",
        "2026-07-15T21:04:00Z",
        "2026-07-15T21:06:00Z",
        "2026-07-15T21:08:00Z",
    ]

    for timestamp in times:
        events.append(
            {
                "event_type": "failed_login",
                "source": "linux_auth",
                "source_ip": "192.168.1.50",
                "username": "admin",
                "timestamp": timestamp,
            }
        )

    alerts = run_detection_rules(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Repeated Failed Logins"
    assert alerts[0]["severity"] == "High"


def test_failed_logins_outside_window_no_alert():
    events = []

    times = [
        "2026-07-15T21:00:00Z",
        "2026-07-15T21:02:00Z",
        "2026-07-15T21:04:00Z",
        "2026-07-15T21:06:00Z",
        "2026-07-15T21:20:00Z",
    ]

    for timestamp in times:
        events.append(
            {
                "event_type": "failed_login",
                "source": "linux_auth",
                "source_ip": "192.168.1.50",
                "username": "admin",
                "timestamp": timestamp,
            }
        )

    alerts = run_detection_rules(events)

    assert alerts == []


def test_suspicious_web_request_creates_alert():
    events = [
        {
            "event_type": "http_request",
            "source": "web_log",
            "source_ip": "192.168.1.80",
            "request_path": "/admin/.env",
            "timestamp": "2026-07-15T21:30:00Z",
        }
    ]

    alerts = run_detection_rules(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Suspicious Web Request"