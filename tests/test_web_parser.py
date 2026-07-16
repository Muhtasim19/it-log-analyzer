from parsers.web_log_parser import parse_web_log


def test_web_parser_successful_request(tmp_path):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        '192.168.1.50 - - [15/Jul/2026:21:30:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    )

    events = parse_web_log(str(log_file))

    assert len(events) == 1
    assert events[0]["event_type"] == "http_request"
    assert events[0]["http_status"] == 200
    assert events[0]["request_path"] == "/index.html"


def test_web_parser_404(tmp_path):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        '192.168.1.50 - - [15/Jul/2026:21:31:00 +0000] '
        '"GET /admin HTTP/1.1" 404 321 "-" "Mozilla/5.0"'
    )

    events = parse_web_log(str(log_file))

    assert events[0]["event_type"] == "http_404"


def test_web_parser_missing_file():
    events = parse_web_log("missing_access.log")

    assert events == []


def test_web_parser_malformed_line(tmp_path):
    log_file = tmp_path / "access.log"

    log_file.write_text("not a valid web log")

    events = parse_web_log(str(log_file))

    assert events[0]["event_type"] == "unknown"