from pathlib import Path

from parsers.linux_auth_parser import parse_linux_auth_log


def test_linux_parser_successful_login(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Jul 15 21:30:00 server sshd[1234]: Accepted password for alice from 192.168.1.20 port 51234 ssh2"
    )

    events = parse_linux_auth_log(str(log_file))

    assert len(events) == 1
    assert events[0]["event_type"] == "successful_login"
    assert events[0]["username"] == "alice"
    assert events[0]["source_ip"] == "192.168.1.20"


def test_linux_parser_failed_login(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Jul 15 21:31:00 server sshd[1235]: Failed password for admin from 192.168.1.50 port 51235 ssh2"
    )

    events = parse_linux_auth_log(str(log_file))

    assert events[0]["event_type"] == "failed_login"
    assert events[0]["status"] == "failure"


def test_linux_parser_invalid_user(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Jul 15 21:34:00 server sshd[1238]: Invalid user testuser from 192.168.1.60 port 51238 ssh2"
    )

    events = parse_linux_auth_log(str(log_file))

    assert events[0]["event_type"] == "invalid_user_login"
    assert events[0]["username"] == "testuser"


def test_linux_parser_malformed_line(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text("malformed unsupported log line")

    events = parse_linux_auth_log(str(log_file))

    assert len(events) == 1
    assert events[0]["event_type"] == "unknown"


def test_linux_parser_missing_file():
    events = parse_linux_auth_log("missing_file.log")

    assert events == []