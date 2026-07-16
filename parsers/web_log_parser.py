"""
Apache/Nginx access log parser.

Converts web server access logs into normalized events.
"""

import re


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) .* .* '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) '
    r'(?P<path>\S+) '
    r'(?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_web_log(file_path):
    """
    Parse Apache/Nginx access log file.

    Args:
        file_path (str): Path to access log.

    Returns:
        list: Normalized events.
    """

    events = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                event = parse_web_line(line)

                if event:
                    events.append(event)

    except FileNotFoundError:
        return []

    return events


def parse_web_line(line):
    """
    Parse a single web access log line.
    """

    match = LOG_PATTERN.search(line)

    if not match:
        return {
            "timestamp": None,
            "source": "web_log",
            "event_type": "unknown",
            "source_ip": None,
            "username": None,
            "status": "unknown",
            "message": line,
            "raw_log": line,
            "http_method": None,
            "request_path": None,
            "http_status": None,
            "response_size": None,
            "user_agent": None,
        }

    data = match.groupdict()

    http_status = int(data["status"])

    event_type = "http_request"

    if http_status == 404:
        event_type = "http_404"
    elif 400 <= http_status < 500:
        event_type = "http_client_error"
    elif http_status >= 500:
        event_type = "http_server_error"

    return {
        "timestamp": data["timestamp"],
        "source": "web_log",
        "event_type": event_type,
        "source_ip": data["ip"],
        "username": None,
        "status": "success" if http_status < 400 else "failure",
        "message": line,
        "raw_log": line,
        "http_method": data["method"],
        "request_path": data["path"],
        "http_status": http_status,
        "response_size": None
        if data["size"] == "-"
        else int(data["size"]),
        "user_agent": data["user_agent"],
    }