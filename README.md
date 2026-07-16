# IT Log Analyzer

A Python-based security log analysis application that parses Windows, Linux, and web-server logs, normalizes events, detects suspicious activity, calculates an overall risk score, and generates JSON and HTML security reports.

This project is part of a larger **IT Operations and Security Suite** containing:

1. Helpdesk Ticketing System
2. Asset Inventory
3. Network Vulnerability Scanner
4. Security Dashboard
5. IT Log Analyzer

## Project Status

The standalone MVP is in final integration and testing.

Implemented components include:

* Windows Security Event Log parser
* Linux authentication-log parser
* Apache/Nginx access-log parser
* Shared normalized event structure
* Suspicious-activity detection rules
* Alert creation and filtering
* Risk scoring
* JSON report generation
* HTML report generation
* Fictional sample logs
* Automated unit tests

Future Ubuntu deployment, Tailscale access, real-log collection, scheduled analysis, and Security Dashboard integration are outside the current standalone MVP.

## Features

### Supported Log Sources

#### Windows Security Events

The Windows parser accepts fictional Security Event records in JSON Lines format.

Supported event IDs:

| Event ID | Description              | Normalized Event Type |
| -------- | ------------------------ | --------------------- |
| `4624`   | Successful account logon | `successful_login`    |
| `4625`   | Failed account logon     | `failed_login`        |
| `4740`   | Account lockout          | `account_lockout`     |

Example:

```json
{"timestamp":"2026-07-15T21:30:00Z","event_id":4624,"source_ip":"192.168.1.10","username":"administrator","hostname":"WIN-SRV-01","message":"An account was successfully logged on."}
```

#### Linux Authentication Logs

The Linux parser supports common Ubuntu/Debian-style authentication records, including:

* Successful SSH logins
* Failed SSH logins
* Invalid-user attempts
* Authentication failures
* Malformed or unsupported records

Example:

```text
Jul 15 21:30:00 ubuntu-server sshd[1234]: Failed password for admin from 192.168.1.50 port 54321 ssh2
```

#### Apache/Nginx Access Logs

The web parser supports common combined access-log records and extracts:

* Source IP
* Timestamp
* HTTP method
* Request path
* HTTP status
* Response size
* User agent

Example:

```text
192.168.1.80 - - [15/Jul/2026:21:30:00 +0000] "GET /admin/.env HTTP/1.1" 404 512 "-" "Mozilla/5.0"
```

### Normalized Events

All parsers transform their input into a common event structure:

```python
{
    "timestamp": "2026-07-15T21:30:00Z",
    "source": "linux_auth",
    "event_type": "failed_login",
    "source_ip": "192.168.1.50",
    "username": "admin",
    "status": "failure",
    "message": "Failed password for admin",
    "raw_log": "Original log record"
}
```

Additional source-specific fields may include:

* `hostname`
* `event_id`
* `destination_ip`
* `http_method`
* `request_path`
* `http_status`
* `response_size`
* `user_agent`

Unavailable values use `None` instead of invented information.

## Detection Rules

The current MVP includes detection for:

### Repeated Failed Logins

Creates a high-severity alert when five or more failed login attempts involving the same source IP and username occur within ten minutes.

### Repeated Invalid-User Attempts

Creates a medium-severity alert when three or more attempts target an invalid username.

### Suspicious Web Requests

Creates alerts for request paths containing suspicious patterns such as:

* `UNION SELECT`
* `DROP TABLE`
* `../`
* `.env`
* `/wp-admin`
* `/phpmyadmin`

Detection rules process normalized events rather than reading log files directly.

## Alert Structure

Generated security alerts use a shared structure:

```python
{
    "alert_id": "ALT-0001",
    "timestamp": "2026-07-15T21:35:00Z",
    "rule_name": "Repeated Failed Logins",
    "severity": "High",
    "source": "linux_auth",
    "source_ip": "192.168.1.50",
    "username": "admin",
    "description": "Five or more failed login attempts occurred within ten minutes.",
    "event_count": 5,
    "related_events": [],
    "status": "Open"
}
```

Supported severity levels:

* Critical
* High
* Medium
* Low
* Informational

Supported alert statuses:

* Open
* Investigating
* Resolved
* Closed

Alert helpers can:

* Create alerts
* Generate alert IDs
* Sort alerts by timestamp
* Filter by severity
* Filter by source
* Filter by status
* Convert alerts to JSON-compatible output

## Risk Scoring

The application calculates an overall security risk score from active alerts.

Alerts with `Open` or `Investigating` status contribute to the score. Alerts marked `Resolved` or `Closed` do not contribute.

Severity weights:

| Severity      | Points |
| ------------- | -----: |
| Critical      |     30 |
| High          |     15 |
| Medium        |      7 |
| Low           |      3 |
| Informational |      1 |

The final score is capped at `100`.

Risk categories:

| Score  | Category |
| ------ | -------- |
| 0–24   | Low      |
| 25–49  | Medium   |
| 50–74  | High     |
| 75–100 | Critical |

The calculation also returns:

* Raw uncapped score
* Active alert count
* Ignored alert count
* Alert count by severity

## Reports

The application produces:

```text
output/security_report.json
output/security_report.html
```

Reports include:

* Generation timestamp
* Total normalized events
* Total security alerts
* Alerts by severity
* Alerts by source
* Top suspicious source IP addresses
* Recent alerts
* Overall risk score
* Overall risk category

The HTML report uses Jinja2 autoescaping to prevent untrusted log content from being rendered as executable HTML.

## Project Structure

```text
it-log-analyzer/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── LICENSE
├── analyzer/
│   ├── __init__.py
│   ├── config.py
│   ├── detection_rules.py
│   ├── alerts.py
│   └── risk_score.py
├── parsers/
│   ├── __init__.py
│   ├── windows_parser.py
│   ├── linux_auth_parser.py
│   └── web_log_parser.py
├── reports/
│   ├── __init__.py
│   └── report_generator.py
├── templates/
│   └── report.html
├── data/
│   ├── sample_windows.log
│   ├── sample_auth.log
│   └── sample_access.log
├── output/
│   └── .gitkeep
└── tests/
    ├── __init__.py
    ├── test_alerts.py
    ├── test_config.py
    ├── test_detection_rules.py
    ├── test_integration.py
    ├── test_linux_parser.py
    ├── test_report_generator.py
    ├── test_risk_score.py
    ├── test_web_parser.py
    └── test_windows_parser.py
```

## Requirements

* Python 3.10 or newer
* `pytest`
* `Jinja2`

Installable dependencies are listed in:

```text
requirements.txt
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Muhtasim19/it-log-analyzer.git
cd it-log-analyzer
```

### macOS or Linux

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

### Windows PowerShell

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Running the Application

Run the complete analysis workflow:

```bash
python3 main.py
```

On Windows, the command may be:

```powershell
python main.py
```

The application will:

1. Read the fictional sample logs.
2. Parse Windows Security records.
3. Parse Linux authentication records.
4. Parse web access records.
5. Normalize event timestamps.
6. Combine all normalized events.
7. Run the detection rules.
8. Assign alert IDs.
9. Calculate the overall risk score.
10. Generate JSON and HTML reports.
11. Print a terminal summary.

Open the HTML report on macOS:

```bash
open output/security_report.html
```

On Linux:

```bash
xdg-open output/security_report.html
```

On Windows PowerShell:

```powershell
start output/security_report.html
```

## Running Tests

Run the full automated test suite:

```bash
python3 -m pytest -v
```

Run a specific test file:

```bash
python3 -m pytest tests/test_windows_parser.py -v
```

Run the end-to-end integration test:

```bash
python3 -m pytest tests/test_integration.py -v
```

The test suite covers:

* Shared configuration
* Windows parsing
* Linux authentication parsing
* Web access-log parsing
* Empty and malformed records
* Missing files
* Detection thresholds
* Suspicious request patterns
* Alert creation and filtering
* Risk-score calculations
* Risk-category boundaries
* JSON report generation
* HTML report generation
* HTML escaping
* Complete sample-log workflow

## Git Workflow

Development follows this workflow:

```text
feature branch
    ↓
pull request
    ↓
develop
    ↓
integration testing
    ↓
main
```

Do not merge unfinished feature work directly into `main`.

Before starting work:

```bash
git checkout develop
git pull origin develop
```

After completing a feature:

```bash
git add .
git commit -m "Describe the completed feature"
git push origin <feature-branch>
```

Create a pull request from the feature branch into `develop`.

After all features pass integration testing, create a final pull request from `develop` into `main`.

## Team Contributions

### Muhtasim

Responsible for:

* Repository and project foundation
* Shared configuration and schemas
* Application entry point
* Windows Security Event Log parser
* Risk-score calculation
* JSON and HTML reporting
* Final integration
* Final testing

### Sabirul

Responsible for:

* Fictional sample logs
* Linux authentication-log parser
* Apache/Nginx access-log parser
* Suspicious-activity detection rules
* Alert creation and filtering
* Tests for assigned components

Both team members participated in pull-request review and integration testing.

## Security and Privacy

This project is intended for educational, portfolio, home-lab, and explicitly authorized security-monitoring use.

Follow these rules:

* Use only fictional logs or logs you are authorized to analyze.
* Do not commit real production logs.
* Do not commit passwords, API tokens, private keys, cookies, or Tailscale keys.
* Treat all log content as untrusted input.
* Never execute content found inside logs.
* Do not use `eval` or `exec` to process log data.
* Escape untrusted content before rendering HTML.
* Keep real deployment credentials outside Git.
* Restrict access to reports containing internal network information.

The included sample records are fictional and are provided only for testing.

## Current Limitations

The standalone MVP has the following limitations:

* Windows logs use fictional JSON Lines records rather than direct Windows Event Log collection.
* Linux timestamps may not contain a year and require normalization during integration.
* Detection thresholds are fixed configuration values.
* Detection rules are intentionally small and demonstration-focused.
* Web detection uses pattern matching rather than a complete web application firewall engine.
* The application processes local files rather than collecting logs remotely.
* No database is currently used.
* No authentication or multi-user interface is included.
* No continuous monitoring service is included.
* The Log Analyzer is not yet directly connected to the Security Dashboard.

## Future Improvements

Planned future work may include:

* Ubuntu home-lab deployment
* Tailscale-secured access
* Authorized reading of Ubuntu authentication logs
* Scheduled or continuous analysis
* Systemd service configuration
* Secure remote log collection
* Persistent alert storage
* Security Dashboard integration
* REST API endpoints
* Additional Windows Event IDs
* HTTP 404 spike detection
* Successful login after repeated failures
* Additional SQL-injection patterns
* URL-decoded attack detection
* Directory-traversal variants
* Alert deduplication
* Configurable detection thresholds
* Command-line file arguments
* Logging and audit history
* Additional report filters

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Disclaimer

This software is an educational security-analysis project. It is not a replacement for a professionally maintained SIEM, intrusion-detection platform, or production security-monitoring service.
