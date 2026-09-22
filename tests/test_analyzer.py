import unittest
from datetime import datetime, timezone

from src.analyzer import analyze_events
from src.models import LoginEvent


def make_event(
    username: str,
    success: bool,
    ip_address: str = "192.0.2.10",
    country: str = "US",
) -> LoginEvent:
    return LoginEvent(
        timestamp=datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc),
        username=username,
        ip_address=ip_address,
        country=country,
        success=success,
    )


class AnalyzerTests(unittest.TestCase):
    def test_counts_successful_and_failed_logins(self):
        events = [
            make_event("alice", True),
            make_event("bob", False),
            make_event("carol", True),
        ]

        report = analyze_events(events)

        self.assertEqual(report.total_events, 3)
        self.assertEqual(report.successful_logins, 2)
        self.assertEqual(report.failed_logins, 1)

    def test_repeated_failed_logins_trigger_alert(self):
        events = [
            make_event("alice", False),
            make_event("alice", False),
            make_event("alice", False),
        ]

        report = analyze_events(events)

        self.assertTrue(
            any("Repeated failures" in alert for alert in report.alerts)
        )

    def test_threshold_is_configurable(self):
        events = [
            make_event("alice", False),
            make_event("alice", False),
        ]

        report = analyze_events(events, failed_threshold=2)

        self.assertTrue(
            any("Repeated failures" in alert for alert in report.alerts)
        )

    def test_blocked_ip_triggers_alert(self):
        events = [
            make_event("alice", True, ip_address="203.0.113.77"),
        ]

        report = analyze_events(events)

        self.assertTrue(
            any("Blocked IP activity" in alert for alert in report.alerts)
        )

    def test_multiple_successful_countries_trigger_location_alert(self):
        events = [
            make_event("alice", True, country="US"),
            make_event("alice", True, country="DE"),
        ]

        report = analyze_events(events)

        self.assertTrue(
            any("Location anomaly" in alert for alert in report.alerts)
        )

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_events([], failed_threshold=0)


if __name__ == "__main__":
    unittest.main()
