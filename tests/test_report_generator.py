"""Tests for JSON and HTML report generation."""

import json

import pytest

from reports.report_generator import (
    build_report_data,
    export_json_report,
    render_html_report,
)


def _sample_events():
    return [
        {
            "timestamp": "2026-07-15T20:00:00Z",
            "source": "windows_security",
            "event_type": "failed_login",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "status": "failure",
            "message": "Failed login",
            "raw_log": "raw event",
        },
        {
            "timestamp": "2026-07-15T20:01:00Z",
            "source": "web_access",
            "event_type": "http_404",
            "source_ip": "192.168.1.60",
            "username": None,
            "status": "failure",
            "message": "HTTP 404",
            "raw_log": "raw web event",
        },
    ]


def _sample_alerts():
    return [
        {
            "alert_id": "ALT-0001",
            "timestamp": "2026-07-15T21:00:00Z",
            "rule_name": "Repeated Failed Logins",
            "severity": "High",
            "source": "windows_security",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "description": "Repeated failures detected.",
            "event_count": 5,
            "related_events": [],
            "status": "Open",
        },
        {
            "alert_id": "ALT-0002",
            "timestamp": "2026-07-15T21:10:00Z",
            "rule_name": "HTTP 404 Spike",
            "severity": "Medium",
            "source": "web_access",
            "source_ip": "192.168.1.60",
            "username": None,
            "description": "Repeated 404 responses detected.",
            "event_count": 6,
            "related_events": [],
            "status": "Open",
        },
        {
            "alert_id": "ALT-0003",
            "timestamp": "2026-07-15T21:15:00Z",
            "rule_name": "Suspicious Path",
            "severity": "Low",
            "source": "web_access",
            "source_ip": "192.168.1.60",
            "username": None,
            "description": "Request for a sensitive path.",
            "event_count": 1,
            "related_events": [],
            "status": "Resolved",
        },
    ]


def test_build_report_data():
    report = build_report_data(
        _sample_events(),
        _sample_alerts(),
        generated_at="2026-07-15T22:00:00Z",
    )

    assert report["generated_at"] == "2026-07-15T22:00:00Z"
    assert report["total_events"] == 2
    assert report["total_alerts"] == 3

    assert report["alerts_by_severity"]["High"] == 1
    assert report["alerts_by_severity"]["Medium"] == 1
    assert report["alerts_by_severity"]["Low"] == 1

    assert report["alerts_by_source"] == {
        "web_access": 2,
        "windows_security": 1,
    }

    assert report["risk"]["score"] == 22
    assert report["risk"]["category"] == "Low"

    assert report["recent_alerts"][0]["alert_id"] == "ALT-0003"


def test_top_source_ips_are_ranked():
    report = build_report_data([], _sample_alerts())

    assert report["top_source_ips"][0] == {
        "source_ip": "192.168.1.60",
        "alert_count": 2,
    }

    assert report["top_source_ips"][1] == {
        "source_ip": "192.168.1.50",
        "alert_count": 1,
    }


def test_recent_alert_limit():
    report = build_report_data(
        [],
        _sample_alerts(),
        recent_limit=2,
    )

    assert len(report["recent_alerts"]) == 2
    assert report["recent_alerts"][0]["alert_id"] == "ALT-0003"
    assert report["recent_alerts"][1]["alert_id"] == "ALT-0002"


def test_negative_recent_limit_is_rejected():
    with pytest.raises(
        ValueError,
        match="recent_limit must not be negative",
    ):
        build_report_data([], [], recent_limit=-1)


def test_empty_report_data():
    report = build_report_data(
        None,
        None,
        generated_at="2026-07-15T22:00:00Z",
    )

    assert report["total_events"] == 0
    assert report["total_alerts"] == 0
    assert report["recent_alerts"] == []
    assert report["top_source_ips"] == []
    assert report["risk"]["score"] == 0
    assert report["risk"]["category"] == "Low"


def test_export_json_report(tmp_path):
    report = build_report_data(
        _sample_events(),
        _sample_alerts(),
        generated_at="2026-07-15T22:00:00Z",
    )

    output_file = tmp_path / "reports" / "report.json"

    result = export_json_report(report, output_file)

    assert result == output_file
    assert output_file.exists()

    saved_report = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert saved_report["total_events"] == 2
    assert saved_report["total_alerts"] == 3
    assert saved_report["risk"]["score"] == 22


def test_render_html_report(tmp_path):
    report = build_report_data(
        _sample_events(),
        _sample_alerts(),
        generated_at="2026-07-15T22:00:00Z",
    )

    output_file = tmp_path / "report.html"

    result = render_html_report(report, output_file)

    assert result == output_file
    assert output_file.exists()

    html = output_file.read_text(encoding="utf-8")

    assert "IT Log Analyzer Security Report" in html
    assert "Repeated Failed Logins" in html
    assert "192.168.1.60" in html
    assert "2026-07-15T22:00:00Z" in html


def test_html_report_escapes_untrusted_content(tmp_path):
    alerts = [
        {
            "alert_id": "ALT-0001",
            "timestamp": "2026-07-15T21:00:00Z",
            "rule_name": "Suspicious Request",
            "severity": "High",
            "source": "web_access",
            "source_ip": "192.168.1.50",
            "username": None,
            "description": "<script>alert('test')</script>",
            "event_count": 1,
            "related_events": [],
            "status": "Open",
        }
    ]

    report = build_report_data([], alerts)
    output_file = tmp_path / "report.html"

    render_html_report(report, output_file)

    html = output_file.read_text(encoding="utf-8")

    assert "<script>alert('test')</script>" not in html
    assert "&lt;script&gt;" in html
