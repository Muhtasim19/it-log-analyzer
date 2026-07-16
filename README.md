# IT Log Analyzer

A Python-based security log analyzer built as part of an IT Operations and Security Suite.

## Current MVP Goals

The application will:

- Parse Windows Security Event Logs
- Parse Linux authentication logs
- Parse Apache or Nginx access logs
- Normalize events into one shared structure
- Detect suspicious activity
- Generate security alerts
- Calculate an overall risk score
- Produce JSON and HTML reports

## Project Status

The project foundation and shared schemas are currently being developed.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt