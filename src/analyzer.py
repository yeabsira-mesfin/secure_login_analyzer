from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .models import LoginEvent


BLOCKED_IPS = {"203.0.113.77", "198.51.100.45"}


@dataclass
class AnalysisReport:
    total_events: int
    successful_logins: int
    failed_logins: int
    alerts: list[str] = field(default_factory=list)


def analyze_events(
    events: list[LoginEvent],
    failed_threshold: int = 3,
) -> AnalysisReport:
    """Analyze authentication events and return a security summary."""

    if failed_threshold < 1:
        raise ValueError("failed_threshold must be at least 1")

    successful = sum(event.success for event in events)
    failed = len(events) - successful
    alerts: list[str] = []

    failed_by_user = Counter(
        event.username for event in events if not event.success
    )

    for username, count in sorted(failed_by_user.items()):
        if count >= failed_threshold:
            alerts.append(
                f"Repeated failures: {username} had {count} failed login attempts."
            )

    for event in events:
        if event.ip_address in BLOCKED_IPS:
            alerts.append(
                f"Blocked IP activity: {event.username} attempted login from "
                f"{event.ip_address}."
            )

    countries_by_user: dict[str, set[str]] = defaultdict(set)
    for event in events:
        if event.success:
            countries_by_user[event.username].add(event.country)

    for username, countries in sorted(countries_by_user.items()):
        if len(countries) >= 2:
            country_list = ", ".join(sorted(countries))
            alerts.append(
                f"Location anomaly: {username} logged in successfully from "
                f"multiple countries ({country_list})."
            )

    # Remove duplicate alert messages while preserving their order.
    alerts = list(dict.fromkeys(alerts))

    return AnalysisReport(
        total_events=len(events),
        successful_logins=successful,
        failed_logins=failed,
        alerts=alerts,
    )
