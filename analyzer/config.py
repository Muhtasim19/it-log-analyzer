"""Shared configuration and schemas for the IT Log Analyzer."""

APP_NAME = "IT Log Analyzer"
APP_VERSION = "0.1.0"

EVENT_REQUIRED_FIELDS = (
    "timestamp",
    "source",
    "event_type",
    "source_ip",
    "username",
    "status",
    "message",
    "raw_log",
)

EVENT_OPTIONAL_FIELDS = (
    "destination_ip",
    "hostname",
    "http_method",
    "request_path",
    "http_status",
    "response_size",
    "user_agent",
    "event_id",
)

ALERT_REQUIRED_FIELDS = (
    "alert_id",
    "timestamp",
    "rule_name",
    "severity",
    "source",
    "source_ip",
    "username",
    "description",
    "event_count",
    "related_events",
    "status",
)

ALERT_SEVERITIES = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)

ALERT_STATUSES = (
    "Open",
    "Investigating",
    "Resolved",
    "Closed",
)

# Initial detection-rule settings.
# These values can be adjusted later after team testing.
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10

INVALID_USER_THRESHOLD = 3
INVALID_USER_WINDOW_MINUTES = 10

HTTP_404_THRESHOLD = 5
HTTP_404_WINDOW_MINUTES = 5