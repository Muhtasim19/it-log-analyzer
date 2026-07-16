"""Command-line entry point for the IT Log Analyzer."""

from analyzer.config import APP_NAME, APP_VERSION


def main() -> int:
    """Run the Log Analyzer application."""

    print(f"{APP_NAME} v{APP_VERSION}")
    print("Project foundation is ready.")
    print("Parsers, detection rules, risk scoring, and reports are under development.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())