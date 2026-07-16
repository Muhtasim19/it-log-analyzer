"""Tests for the Windows Security Event Log parser."""

import pytest

from parsers.windows_parser import parse_windows_log


def test_parse_supported_windows_events(tmp_path):
    log_file = tmp_path / "windows.log"

    log_file.write_text(
        "\n".join(
            [
                (
                    '{"timestamp":"2026-07-15T21:30:00Z",'
                    '"event_id":4624,'
                    '"source_ip":"192.168.1.10",'
                    '"username":"administrator",'
                    '"hostname":"WIN-SRV-01",'
                    '"message":"Successful login."}'
                ),
                (
                    '{"timestamp":"2026-07-15T21:32:00Z",'
                    '"event_id":4625,'
                    '"source_ip":"192.168.1.50",'
                    '"username":"admin",'
                    '"hostname":"WIN-SRV-01",'
                    '"message":"Failed login."}'
                ),
                (
                    '{"timestamp":"2026-07-15T21:35:00Z",'
                    '"event_id":4740,'
                    '"source_ip":"192.168.1.50",'
                    '"username":"admin",'
                    '"hostname":"WIN-SRV-01",'
                    '"message":"Account locked."}'
                ),
            ]
        ),
        encoding="utf-8",
    )

    events = parse_windows_log(log_file)

    assert len(events) == 3

    assert events[0]["event_type"] == "successful_login"
    assert events[0]["status"] == "success"
    assert events[0]["event_id"] == 4624

    assert events[1]["event_type"] == "failed_login"
    assert events[1]["status"] == "failure"
    assert events[1]["event_id"] == 4625

    assert events[2]["event_type"] == "account_lockout"
    assert events[2]["status"] == "locked"
    assert events[2]["event_id"] == 4740


def test_parser_uses_shared_event_fields(tmp_path):
    log_file = tmp_path / "windows.log"

    log_file.write_text(
        (
            '{"timestamp":"2026-07-15T21:30:00Z",'
            '"event_id":"4625",'
            '"source_ip":"192.168.1.50",'
            '"username":"admin",'
            '"hostname":"WIN-SRV-01"}'
        ),
        encoding="utf-8",
    )

    event = parse_windows_log(log_file)[0]

    expected_fields = {
        "timestamp",
        "source",
        "event_type",
        "source_ip",
        "username",
        "status",
        "message",
        "raw_log",
    }

    assert expected_fields.issubset(event)
    assert event["source"] == "windows_security"
    assert event["timestamp"] == "2026-07-15T21:30:00Z"
    assert event["event_id"] == 4625


def test_parser_skips_malformed_and_unsupported_records(tmp_path):
    log_file = tmp_path / "windows.log"

    log_file.write_text(
        "\n".join(
            [
                "this is not json",
                "[]",
                '{"timestamp":"2026-07-15T21:30:00Z","event_id":9999}',
                (
                    '{"timestamp":"2026-07-15T21:31:00Z",'
                    '"event_id":4625,'
                    '"source_ip":"192.168.1.50",'
                    '"username":"admin"}'
                ),
            ]
        ),
        encoding="utf-8",
    )

    events = parse_windows_log(log_file)

    assert len(events) == 1
    assert events[0]["event_id"] == 4625


def test_parser_handles_empty_file(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    assert parse_windows_log(log_file) == []


def test_parser_handles_missing_optional_values(tmp_path):
    log_file = tmp_path / "windows.log"

    log_file.write_text(
        (
            '{"timestamp":"invalid-date",'
            '"event_id":4740,'
            '"source_ip":"-",'
            '"username":"",'
            '"hostname":null}'
        ),
        encoding="utf-8",
    )

    event = parse_windows_log(log_file)[0]

    assert event["timestamp"] is None
    assert event["source_ip"] is None
    assert event["username"] is None
    assert event["hostname"] is None
    assert event["message"] == "A user account was locked out."


def test_parser_raises_for_missing_file(tmp_path):
    missing_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError, match="Windows log file not found"):
        parse_windows_log(missing_file)


def test_parser_raises_for_directory(tmp_path):
    with pytest.raises(IsADirectoryError, match="is not a file"):
        parse_windows_log(tmp_path)