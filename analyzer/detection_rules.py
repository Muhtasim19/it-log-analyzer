"""
Detection rules for normalized log events.
"""

from datetime import datetime, timedelta


def create_alert(
    rule_name,
    severity,
    source,
    source_ip,
    username,
    description,
    event_count,
    related_events,
    timestamp,
):
    return {
        "alert_id": None,
        "timestamp": timestamp,
        "rule_name": rule_name,
        "severity": severity,
        "source": source,
        "source_ip": source_ip,
        "username": username,
        "description": description,
        "event_count": event_count,
        "related_events": related_events,
        "status": "Open",
    }


def detect_repeated_failed_logins(events):
    alerts = []

    failed = {}

    for event in events:
        if event.get("event_type") == "failed_login":
            key = (
                event.get("source_ip"),
                event.get("username"),
            )

            failed.setdefault(key, []).append(event)

    for (ip, username), attempts in failed.items():

        if len(attempts) < 5:
            continue

        first_time = datetime.fromisoformat(
            attempts[0]["timestamp"].replace("Z", "+00:00")
        )

        recent_attempts = []

        for attempt in attempts:
            current_time = datetime.fromisoformat(
                attempt["timestamp"].replace("Z", "+00:00")
            )

            if current_time - first_time <= timedelta(minutes=10):
                recent_attempts.append(attempt)

        if len(recent_attempts) >= 5:
            alerts.append(
                create_alert(
                    "Repeated Failed Logins",
                    "High",
                    recent_attempts[0].get("source"),
                    ip,
                    username,
                    "Five or more failed login attempts occurred within ten minutes.",
                    len(recent_attempts),
                    recent_attempts,
                    recent_attempts[-1].get("timestamp"),
                )
            )

    return alerts


def detect_invalid_users(events):
    alerts = []

    attempts = {}

    for event in events:
        if event.get("event_type") == "invalid_user_login":

            key = (
                event.get("source_ip"),
                event.get("username"),
            )

            attempts.setdefault(key, []).append(event)

    for (ip, username), related in attempts.items():
        if len(related) >= 3:
            alerts.append(
                create_alert(
                    "Repeated Invalid User Attempts",
                    "Medium",
                    related[0].get("source"),
                    ip,
                    username,
                    "Repeated login attempts for invalid usernames.",
                    len(related),
                    related,
                    related[-1].get("timestamp"),
                )
            )

    return alerts


def detect_suspicious_web_requests(events):
    alerts = []

    patterns = [
        "union select",
        "drop table",
        "../",
        ".env",
        "/wp-admin",
        "/phpmyadmin",
    ]

    for event in events:

        path = str(event.get("request_path", "")).lower()

        for pattern in patterns:
            if pattern in path:

                alerts.append(
                    create_alert(
                        "Suspicious Web Request",
                        "High",
                        event.get("source"),
                        event.get("source_ip"),
                        None,
                        f"Suspicious pattern detected: {pattern}",
                        1,
                        [event],
                        event.get("timestamp"),
                    )
                )

    return alerts


def run_detection_rules(events):
    alerts = []

    alerts.extend(detect_repeated_failed_logins(events))
    alerts.extend(detect_invalid_users(events))
    alerts.extend(detect_suspicious_web_requests(events))

    return alerts