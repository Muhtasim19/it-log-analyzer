"""Parser for fictional Windows Security Event Log records.

The MVP accepts JSON Lines input. Each non-empty line must contain one
JSON object representing a Windows Security event.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union


WINDOWS_EVENT_TYPES = {
    4624: {
        "event_type": "successful_login",
        "status": "success",
        "default_message": "An account was successfully logged on.",
    },
    4625: {
        "event_type": "failed_login",
        "status": "failure",
        "default_message": "An account failed to log on.",
    },
    4740: {
        "event_type": "account_lockout",
        "status": "locked",
        "default_message": "A user account was locked out.",
    },
}


def _normalize_optional_text(value: Any) -> Optional[str]:
    """Convert an optional value to clean text.

    Empty values and common missing-value markers become None.
    """

    if value is None:
        return None

    text = str(value).strip()

    if not text or text.lower() in {"-", "none", "null", "n/a"}:
        return None

    return text


def _normalize_timestamp(value: Any) -> Optional[str]:
    """Convert an ISO 8601 timestamp to UTC format.

    Invalid or missing timestamps return None rather than crashing.
    """

    if not isinstance(value, str) or not value.strip():
        return None

    timestamp = value.strip()

    # datetime.fromisoformat expects +00:00 rather than a trailing Z.
    if timestamp.endswith("Z"):
        timestamp = f"{timestamp[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_event_id(value: Any) -> Optional[int]:
    """Convert an event ID to an integer when possible."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _build_event(record: dict[str, Any], raw_log: str) -> Optional[dict[str, Any]]:
    """Convert one Windows record into the shared normalized event format."""

    event_id = _normalize_event_id(record.get("event_id"))

    if event_id not in WINDOWS_EVENT_TYPES:
        return None

    event_definition = WINDOWS_EVENT_TYPES[event_id]

    message = (
        _normalize_optional_text(record.get("message"))
        or event_definition["default_message"]
    )

    return {
        "timestamp": _normalize_timestamp(record.get("timestamp")),
        "source": "windows_security",
        "event_type": event_definition["event_type"],
        "source_ip": _normalize_optional_text(record.get("source_ip")),
        "username": _normalize_optional_text(record.get("username")),
        "status": event_definition["status"],
        "message": message,
        "raw_log": raw_log,
        "hostname": _normalize_optional_text(record.get("hostname")),
        "event_id": event_id,
    }


def parse_windows_log(
    file_path: Union[str, Path],
) -> list[dict[str, Any]]:
    """Parse a Windows Security log file containing JSON Lines records.

    Blank lines, malformed JSON, non-object values, and unsupported event
    IDs are skipped safely.

    Args:
        file_path: Path to the Windows sample log.

    Returns:
        A list of normalized Windows security events.

    Raises:
        FileNotFoundError: When the supplied path does not exist.
        IsADirectoryError: When the supplied path is a directory.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Windows log file not found: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"Windows log path is not a file: {path}")

    events: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for raw_line in log_file:
            stripped_line = raw_line.strip()

            if not stripped_line:
                continue

            try:
                record = json.loads(stripped_line)
            except json.JSONDecodeError:
                continue

            if not isinstance(record, dict):
                continue

            event = _build_event(record, stripped_line)

            if event is not None:
                events.append(event)

    return events