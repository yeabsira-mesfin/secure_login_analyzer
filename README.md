# Secure Login Analyzer

A lightweight Python security project that analyzes authentication events and identifies suspicious login behavior from structured JSON data.

The goal of this project is to demonstrate clear security-focused detection logic, defensive input validation, automated testing, and a simple command-line workflow without relying on external packages.

## What it detects

The analyzer currently looks for three types of suspicious authentication activity:

- **Repeated failed logins**: flags a user when failed attempts reach the configured analysis threshold.
- **Blocked IP activity**: flags authentication attempts originating from IP addresses on the analyzer's blocked-IP list.
- **Location anomalies**: flags users who successfully authenticate from more than one country in the supplied event set.

The location rule is intentionally simple. It detects a multi-country pattern rather than claiming to perform full impossible-travel detection, which would require time, distance, trusted geolocation data, and additional context.

## Example analysis

Using the included sample data, the analyzer reports:

```text
SECURE LOGIN ANALYZER
==================================
Total events:       6
Successful logins:  3
Failed logins:      3
Alerts detected:    3

ALERTS
----------------------------------
1. Repeated failures: bob had 3 failed login attempts.
2. Blocked IP activity: carol attempted login from 203.0.113.77.
3. Location anomaly: alice logged in successfully from multiple countries (DE, US).
```

## Project structure

```text
.
├── data/
│   └── sample_events.json
├── src/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── main.py
│   └── models.py
├── tests/
│   └── test_analyzer.py
├── .github/
│   └── workflows/
│       └── tests.yml
├── DEMO_TASK.md
├── run_demo.bat
├── .gitignore
└── README.md
```

## How it works

The code is separated into three small responsibilities:

1. **Data modeling**: `src/models.py` defines an immutable `LoginEvent` dataclass and validates required fields, ISO-8601 timestamps, and boolean login results.
2. **Detection logic**: `src/analyzer.py` counts successful and failed logins, evaluates failed-login thresholds, checks blocked IP addresses, and detects multi-country successful-login patterns.
3. **CLI workflow**: `src/main.py` loads JSON events, converts them into validated models, runs the analyzer, and prints a concise security report.

This separation keeps the detection logic testable without depending on file I/O or terminal output.

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Run the analyzer

From the repository root:

```bash
python -m src.main data/sample_events.json
```

On Windows, you can also use:

```bat
run_demo.bat
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The test suite covers:

- successful and failed login counts
- repeated failed-login detection
- configurable analysis thresholds
- blocked-IP detection
- multi-country location alerts
- invalid threshold rejection

GitHub Actions runs the test suite automatically on pushes and pull requests.

## Input format

The analyzer expects a JSON array. Each event must contain:

```json
{
  "timestamp": "2026-09-18T12:00:00Z",
  "username": "alice",
  "ip_address": "192.0.2.10",
  "country": "US",
  "success": true
}
```

Required fields:

| Field | Description |
| --- | --- |
| `timestamp` | ISO-8601 authentication timestamp |
| `username` | Account identifier |
| `ip_address` | Source IP address |
| `country` | Country associated with the event |
| `success` | Boolean authentication result |

Malformed input is rejected with a clear error instead of being silently accepted.

## Security engineering concepts demonstrated

- authentication-event analysis
- threshold-based detection
- suspicious IP identification
- location anomaly detection
- input validation
- deterministic security rules
- Python dataclasses
- JSON parsing
- separation of concerns
- automated unit testing
- CI with GitHub Actions

## Design notes

This is a deliberately small rule-based analyzer, not a replacement for a SIEM, identity-protection platform, or production authentication-monitoring system. The simple design makes each detection decision easy to inspect, explain, test, and extend.

The current blocked-IP list is defined locally in `src/analyzer.py` for demonstration purposes. In a production implementation, threat intelligence and policy data should come from maintained external sources or configuration rather than being hard-coded.

## Production improvements

A production version could add:

- identity-provider or SIEM event ingestion
- configurable detection rules and policy files
- time-windowed brute-force detection
- real impossible-travel analysis using timestamps and geolocation confidence
- structured JSON logging
- alert severity and risk scoring
- persistent alert storage
- threat-intelligence enrichment
- API or streaming input support
- metrics, dashboards, and alert routing
- code coverage, linting, and security scanning in CI

## Tests verified

The included six unit tests pass against the current implementation using Python's built-in `unittest` framework.

---

**Built as a security-focused Python portfolio project demonstrating authentication-event analysis, defensive programming, and testable detection logic.**
