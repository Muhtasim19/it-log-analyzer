"""Command-line entry point for the IT Log Analyzer."""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.config import APP_NAME, APP_VERSION
from analyzer.detection_rules import run_detection_rules
from analyzer.risk_score import calculate_risk_score
from parsers.linux_auth_parser import parse_linux_auth_log
from parsers.web_log_parser import parse_web_log
from parsers.windows_parser import parse_windows_log
from reports.report_generator import (
    build_report_data,
    export_json_report,
    render_html_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIRECTORY = PROJECT_ROOT / "data"
DEFAULT_OUTPUT_DIRECTORY = PROJECT_ROOT / "output"


def normalize_timestamp(
    value: Any,
    *,
    default_year: int | None = None,
) -> str | None:
    """Convert supported timestamp formats to ISO 8601 UTC.

    Supported inputs:

    - ISO 8601, including timestamps ending in ``Z``
    - Linux syslog timestamps such as ``Jul 15 09:17:05``
    - Apache/Nginx timestamps such as
      ``15/Jul/2026:09:17:20 +0000``

    Linux syslog timestamps do not contain a year, so the current UTC year
    is used unless ``default_year`` is supplied.
    """

    if not isinstance(value, str) or not value.strip():
        return None

    timestamp = value.strip()

    # ISO 8601
    iso_timestamp = timestamp

    if iso_timestamp.endswith("Z"):
        iso_timestamp = f"{iso_timestamp[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        parsed = None

    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        return parsed.isoformat(timespec="seconds").replace(
            "+00:00",
            "Z",
        )

    # Apache/Nginx combined-log timestamp
    try:
        parsed = datetime.strptime(
            timestamp,
            "%d/%b/%Y:%H:%M:%S %z",
        ).astimezone(timezone.utc)

        return parsed.isoformat(timespec="seconds").replace(
            "+00:00",
            "Z",
        )
    except ValueError:
        pass

    # Linux syslog timestamp without a year
    year = default_year or datetime.now(timezone.utc).year

    try:
        parsed = datetime.strptime(
            f"{year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)

        return parsed.isoformat(timespec="seconds").replace(
            "+00:00",
            "Z",
        )
    except ValueError:
        return None


def normalize_events(
    events: Iterable[Mapping[str, Any]],
    *,
    default_year: int | None = None,
) -> list[dict[str, Any]]:
    """Copy events and normalize their timestamps."""

    normalized_events: list[dict[str, Any]] = []

    for event in events:
        if not isinstance(event, Mapping):
            continue

        normalized_event = dict(event)
        normalized_timestamp = normalize_timestamp(
            normalized_event.get("timestamp"),
            default_year=default_year,
        )

        if normalized_timestamp is not None:
            normalized_event["timestamp"] = normalized_timestamp

        normalized_events.append(normalized_event)

    return normalized_events


def load_events(
    data_directory: str | Path = DEFAULT_DATA_DIRECTORY,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Load and parse all supported sample log files."""

    data_path = Path(data_directory)

    windows_path = data_path / "sample_windows.log"
    linux_path = data_path / "sample_auth.log"
    web_path = data_path / "sample_access.log"

    windows_events = (
        parse_windows_log(windows_path)
        if windows_path.is_file()
        else []
    )

    linux_events = parse_linux_auth_log(str(linux_path))
    web_events = parse_web_log(str(web_path))

    event_counts = {
        "windows_security": len(windows_events),
        "linux_auth": len(linux_events),
        "web_log": len(web_events),
    }

    all_events = [
        *windows_events,
        *linux_events,
        *web_events,
    ]

    return all_events, event_counts


def prepare_detection_events(
    events: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return events that can safely be processed by detection rules.

    Failed-login correlation requires a usable timestamp. A failed-login
    event without one is ignored rather than allowing one malformed record
    to stop the whole analysis.
    """

    detection_events: list[dict[str, Any]] = []

    for event in events:
        if not isinstance(event, Mapping):
            continue

        normalized_event = dict(event)

        if (
            normalized_event.get("event_type") == "failed_login"
            and not normalized_event.get("timestamp")
        ):
            continue

        detection_events.append(normalized_event)

    return detection_events


def assign_alert_ids(
    alerts: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Assign deterministic IDs to alerts that do not already have one."""

    prepared_alerts: list[dict[str, Any]] = []
    used_ids: set[str] = set()

    for alert in alerts:
        if not isinstance(alert, Mapping):
            continue

        prepared_alert = dict(alert)
        current_id = prepared_alert.get("alert_id")

        if isinstance(current_id, str) and current_id.strip():
            used_ids.add(current_id.strip())

        prepared_alerts.append(prepared_alert)

    next_number = 1

    for alert in prepared_alerts:
        current_id = alert.get("alert_id")

        if isinstance(current_id, str) and current_id.strip():
            continue

        while True:
            candidate = f"ALT-{next_number:04d}"
            next_number += 1

            if candidate not in used_ids:
                break

        alert["alert_id"] = candidate
        used_ids.add(candidate)

    return prepared_alerts


def run_analysis(
    *,
    data_directory: str | Path = DEFAULT_DATA_DIRECTORY,
    output_directory: str | Path = DEFAULT_OUTPUT_DIRECTORY,
    default_year: int | None = None,
) -> dict[str, Any]:
    """Run the complete Log Analyzer workflow."""

    output_path = Path(output_directory)

    raw_events, event_counts = load_events(data_directory)

    events = normalize_events(
        raw_events,
        default_year=default_year,
    )

    detection_events = prepare_detection_events(events)
    detected_alerts = run_detection_rules(detection_events)
    alerts = assign_alert_ids(detected_alerts)

    risk = calculate_risk_score(alerts)

    report = build_report_data(
        events,
        alerts,
        risk_result=risk,
    )

    # Include complete data for future dashboard integration.
    report["events_by_source"] = event_counts
    report["events"] = events
    report["alerts"] = alerts

    json_report = export_json_report(
        report,
        output_path / "security_report.json",
    )

    html_report = render_html_report(
        report,
        output_path / "security_report.html",
    )

    return {
        "events": events,
        "alerts": alerts,
        "event_counts": event_counts,
        "risk": risk,
        "report": report,
        "json_report": json_report,
        "html_report": html_report,
    }


def print_summary(result: Mapping[str, Any]) -> None:
    """Print a readable terminal summary."""

    event_counts = result["event_counts"]
    alerts = result["alerts"]
    risk = result["risk"]

    severity_counts = Counter(
        alert.get("severity", "Unknown")
        for alert in alerts
    )

    print(f"{APP_NAME} v{APP_VERSION}")
    print("=" * 50)
    print("Analysis complete.")
    print()

    print("Events parsed:")
    print(
        f"  Windows Security: "
        f"{event_counts.get('windows_security', 0)}"
    )
    print(
        f"  Linux Authentication: "
        f"{event_counts.get('linux_auth', 0)}"
    )
    print(
        f"  Web Access: "
        f"{event_counts.get('web_log', 0)}"
    )
    print(f"  Total: {len(result['events'])}")
    print()

    print(f"Security alerts: {len(alerts)}")

    for severity in (
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ):
        print(
            f"  {severity}: "
            f"{severity_counts.get(severity, 0)}"
        )

    print()
    print(
        f"Overall risk: {risk['score']}/100 "
        f"({risk['category']})"
    )
    print()
    print(f"JSON report: {result['json_report']}")
    print(f"HTML report: {result['html_report']}")


def main() -> int:
    """Run the command-line application."""

    try:
        result = run_analysis()
    except (OSError, TypeError, ValueError) as error:
        print(
            f"Analysis failed: {error}",
            file=sys.stderr,
        )
        return 1

    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())