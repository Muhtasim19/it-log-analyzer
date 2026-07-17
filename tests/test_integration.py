"""End-to-end integration tests for the IT Log Analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from main import run_analysis


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DATA_DIRECTORY = PROJECT_ROOT / "data"


def test_complete_sample_log_workflow(tmp_path):
    result = run_analysis(
        data_directory=SAMPLE_DATA_DIRECTORY,
        output_directory=tmp_path,
        default_year=2026,
    )

    assert result["event_counts"]["windows_security"] > 0
    assert result["event_counts"]["linux_auth"] > 0
    assert result["event_counts"]["web_log"] > 0

    assert len(result["events"]) > 0
    assert len(result["alerts"]) > 0

    assert all(
        isinstance(alert.get("alert_id"), str)
        and alert["alert_id"].startswith("ALT-")
        for alert in result["alerts"]
    )

    assert 0 <= result["risk"]["score"] <= 100

    assert result["risk"]["category"] in {
        "Low",
        "Medium",
        "High",
        "Critical",
    }

    json_report = tmp_path / "security_report.json"
    html_report = tmp_path / "security_report.html"

    assert json_report.exists()
    assert html_report.exists()

    saved_report = json.loads(
        json_report.read_text(encoding="utf-8")
    )

    assert saved_report["total_events"] == len(
        result["events"]
    )

    assert saved_report["total_alerts"] == len(
        result["alerts"]
    )

    assert saved_report["events_by_source"] == (
        result["event_counts"]
    )

    assert len(saved_report["events"]) == len(
        result["events"]
    )

    assert len(saved_report["alerts"]) == len(
        result["alerts"]
    )

    html = html_report.read_text(encoding="utf-8")

    assert "IT Log Analyzer Security Report" in html
    assert "Risk Score" in html
