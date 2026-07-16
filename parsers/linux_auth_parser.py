"""
Linux authentication log parser.

Converts Linux auth.log style entries into normalized events.
"""


import re
from datetime import datetime


def parse_linux_auth_log(file_path):
    """
    Parse a Linux authentication log file.

    Args:
        file_path (str): Path to the log file.

    Returns:
        list: Normalized event dictionaries.
    """

    events = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                event = parse_linux_auth_line(line)

                if event:
                    events.append(event)

    except FileNotFoundError:
        return []

    return events


def parse_linux_auth_line(line):
    """
    Parse one Linux authentication log line.

    Returns:
        dict or None
    """

    timestamp = extract_timestamp(line)

    base_event = {
        "timestamp": timestamp,
        "source": "linux_auth",
        "event_type": "unknown",
        "source_ip": None,
        "username": None,
        "status": "unknown",
        "message": line,
        "raw_log": line,
    }

    # Successful SSH login
    success_match = re.search(
        r"Accepted \w+ for (\S+) from ([0-9.]+)",
        line,
    )

    if success_match:
        base_event["event_type"] = "successful_login"
        base_event["status"] = "success"
        base_event["username"] = success_match.group(1)
        base_event["source_ip"] = success_match.group(2)
        return base_event

    # Failed password login
    failed_match = re.search(
        r"Failed password for (\S+) from ([0-9.]+)",
        line,
    )

    if failed_match:
        base_event["event_type"] = "failed_login"
        base_event["status"] = "failure"
        base_event["username"] = failed_match.group(1)
        base_event["source_ip"] = failed_match.group(2)
        return base_event

    # Invalid user attempt
    invalid_match = re.search(
        r"Invalid user (\S+) from ([0-9.]+)",
        line,
    )

    if invalid_match:
        base_event["event_type"] = "invalid_user_login"
        base_event["status"] = "failure"
        base_event["username"] = invalid_match.group(1)
        base_event["source_ip"] = invalid_match.group(2)
        return base_event

    # Authentication errors
    if "authentication failure" in line.lower():
        base_event["event_type"] = "authentication_error"
        base_event["status"] = "failure"
        return base_event

    return base_event


def extract_timestamp(line):
    """
    Extract Linux syslog timestamp.

    Example:
    Jul 15 21:30:00
    """

    match = re.match(
        r"([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)",
        line,
    )

    if match:
        return match.group(1)

    return None