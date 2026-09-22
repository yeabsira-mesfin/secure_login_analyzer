import argparse
import json
from pathlib import Path

from .analyzer import analyze_events
from .models import LoginEvent


def load_events(path: Path) -> list[LoginEvent]:
    """Load and validate login events from a JSON file."""

    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, list):
        raise ValueError("Input JSON must contain a list of events")

    return [LoginEvent.from_dict(item) for item in payload]


def print_report(report) -> None:
    print("\nSECURE LOGIN ANALYZER")
    print("=" * 34)
    print(f"Total events:       {report.total_events}")
    print(f"Successful logins:  {report.successful_logins}")
    print(f"Failed logins:      {report.failed_logins}")
    print(f"Alerts detected:    {len(report.alerts)}")

    if report.alerts:
        print("\nALERTS")
        print("-" * 34)
        for index, alert in enumerate(report.alerts, start=1):
            print(f"{index}. {alert}")
    else:
        print("\nNo suspicious activity detected.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze authentication events for suspicious activity."
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to a JSON file containing login events",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        events = load_events(args.input_file)
        report = analyze_events(events)
        print_report(report)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
