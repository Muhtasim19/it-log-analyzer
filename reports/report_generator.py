"""JSON and HTML report generation for the IT Log Analyzer."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from analyzer.risk_score import calculate_risk_score


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE_DIRECTORY = PROJECT_ROOT / "templates"
DEFAULT_TEMPLATE_NAME = "report.html"

SEVERITY_ORDER = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


def _normalize_records(
    records: Iterable[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Return valid mapping records as normal dictionaries."""

    if records is None:
        return []

    normalized: list[dict[str, Any]] = []

    for record in records:
        if isinstance(record, Mapping):
            normalized.append(dict(record))

    return normalized


def _timestamp_value(value: Any) -> float:
    """Convert an ISO timestamp into a sortable Unix timestamp.

    Missing or invalid values sort below valid timestamps.
    """

    if not isinstance(value, str) or not value.strip():
        return float("-inf")

    timestamp = value.strip()

    if timestamp.endswith("Z"):
        timestamp = f"{timestamp[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return float("-inf")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed.timestamp()


def _normalize_severity(value: Any) -> str | None:
    """Return a recognized report severity."""

    if not isinstance(value, str):
        return None

    lookup = {
        severity.lower(): severity
        for severity in SEVERITY_ORDER
    }

    return lookup.get(value.strip().lower())


def build_report_data(
    events: Iterable[Mapping[str, Any]] | None,
    alerts: Iterable[Mapping[str, Any]] | None,
    risk_result: Mapping[str, Any] | None = None,
    *,
    recent_limit: int = 10,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-compatible report summary.

    Args:
        events: Normalized event dictionaries.
        alerts: Security alert dictionaries.
        risk_result: Optional precomputed risk-score result.
        recent_limit: Maximum number of recent alerts to include.
        generated_at: Optional timestamp used for deterministic tests.

    Returns:
        A dictionary containing report totals, groupings, risk information,
        top source addresses, and recent alerts.
    """

    if recent_limit < 0:
        raise ValueError("recent_limit must not be negative")

    event_records = _normalize_records(events)
    alert_records = _normalize_records(alerts)

    alerts_by_severity = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    alerts_by_source: Counter[str] = Counter()
    source_ip_counts: Counter[str] = Counter()

    for alert in alert_records:
        severity = _normalize_severity(alert.get("severity"))

        if severity is not None:
            alerts_by_severity[severity] += 1

        source = alert.get("source")

        if isinstance(source, str) and source.strip():
            alerts_by_source[source.strip()] += 1

        source_ip = alert.get("source_ip")

        if isinstance(source_ip, str) and source_ip.strip():
            source_ip_counts[source_ip.strip()] += 1

    recent_alerts = sorted(
        alert_records,
        key=lambda alert: _timestamp_value(alert.get("timestamp")),
        reverse=True,
    )[:recent_limit]

    top_source_ips = [
        {
            "source_ip": source_ip,
            "alert_count": alert_count,
        }
        for source_ip, alert_count in source_ip_counts.most_common(10)
    ]

    if risk_result is None:
        calculated_risk = calculate_risk_score(alert_records)
    elif isinstance(risk_result, Mapping):
        calculated_risk = dict(risk_result)
    else:
        raise TypeError("risk_result must be a mapping or None")

    report_timestamp = generated_at

    if report_timestamp is None:
        report_timestamp = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    return {
        "generated_at": report_timestamp,
        "total_events": len(event_records),
        "total_alerts": len(alert_records),
        "alerts_by_severity": alerts_by_severity,
        "alerts_by_source": dict(
            sorted(alerts_by_source.items())
        ),
        "top_source_ips": top_source_ips,
        "recent_alerts": recent_alerts,
        "risk": calculated_risk,
    }


def export_json_report(
    report_data: Mapping[str, Any],
    output_path: str | Path,
) -> Path:
    """Write report data to a formatted JSON file."""

    if not isinstance(report_data, Mapping):
        raise TypeError("report_data must be a mapping")

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_text(
        json.dumps(
            dict(report_data),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )

    return destination


def render_html_report(
    report_data: Mapping[str, Any],
    output_path: str | Path,
    *,
    template_directory: str | Path = DEFAULT_TEMPLATE_DIRECTORY,
    template_name: str = DEFAULT_TEMPLATE_NAME,
) -> Path:
    """Render a safely escaped HTML report using Jinja2."""

    if not isinstance(report_data, Mapping):
        raise TypeError("report_data must be a mapping")

    template_path = Path(template_directory)

    environment = Environment(
        loader=FileSystemLoader(str(template_path)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "xml"),
            default_for_string=True,
        ),
    )

    template = environment.get_template(template_name)
    rendered_report = template.render(report=dict(report_data))

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered_report, encoding="utf-8")

    return destination