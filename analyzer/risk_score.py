"""Risk-score calculations for security alerts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical": 30,
    "High": 15,
    "Medium": 7,
    "Low": 3,
    "Informational": 1,
}

ACTIVE_ALERT_STATUSES = {
    "open",
    "investigating",
}


def normalize_severity(value: Any) -> str | None:
    """Return a recognized severity name or None.

    Severity matching is case-insensitive and ignores surrounding spaces.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip().lower()

    severity_lookup = {
        severity.lower(): severity for severity in SEVERITY_WEIGHTS
    }

    return severity_lookup.get(normalized)


def is_active_alert(alert: Mapping[str, Any]) -> bool:
    """Return True when an alert should contribute to the risk score.

    Alerts without a status are treated as active for compatibility with
    early MVP alert records.
    """

    status = alert.get("status")

    if status is None:
        return True

    if not isinstance(status, str):
        return False

    return status.strip().lower() in ACTIVE_ALERT_STATUSES


def classify_risk(score: int | float) -> str:
    """Convert a numeric score into a risk category."""

    normalized_score = max(0, min(100, float(score)))

    if normalized_score >= 75:
        return "Critical"

    if normalized_score >= 50:
        return "High"

    if normalized_score >= 25:
        return "Medium"

    return "Low"


def calculate_risk_score(
    alerts: Iterable[Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Calculate an overall risk score from security alerts.

    Only active alerts with recognized severity values contribute points.
    The final score is capped at 100.

    Args:
        alerts: Iterable of alert dictionaries, or None.

    Returns:
        A dictionary containing the score, category, active alert count,
        ignored alert count, raw score, and severity counts.
    """

    severity_counts = {
        severity: 0 for severity in SEVERITY_WEIGHTS
    }

    if alerts is None:
        return {
            "score": 0,
            "category": "Low",
            "raw_score": 0,
            "active_alerts": 0,
            "ignored_alerts": 0,
            "severity_counts": severity_counts,
        }

    raw_score = 0
    active_alerts = 0
    ignored_alerts = 0

    for alert in alerts:
        if not isinstance(alert, Mapping):
            ignored_alerts += 1
            continue

        if not is_active_alert(alert):
            ignored_alerts += 1
            continue

        severity = normalize_severity(alert.get("severity"))

        if severity is None:
            ignored_alerts += 1
            continue

        raw_score += SEVERITY_WEIGHTS[severity]
        severity_counts[severity] += 1
        active_alerts += 1

    score = min(100, raw_score)

    return {
        "score": score,
        "category": classify_risk(score),
        "raw_score": raw_score,
        "active_alerts": active_alerts,
        "ignored_alerts": ignored_alerts,
        "severity_counts": severity_counts,
    }
