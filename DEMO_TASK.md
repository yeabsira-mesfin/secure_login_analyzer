# Live Demo Task

## Goal

Make the failed-login detection threshold configurable from the command line.

The current default threshold is 3 failed logins for one user.

## Step 1: Open `src/main.py`

Find the `argparse` section.

Add this argument:

```python
parser.add_argument(
    "--failed-threshold",
    type=int,
    default=3,
    help="Failed-login count that triggers an alert (default: 3)",
)
```

## Step 2: Pass the value into the analyzer

Find:

```python
report = analyze_events(events)
```

Change it to:

```python
report = analyze_events(events, failed_threshold=args.failed_threshold)
```

## Step 3: Verify

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Then run the application with a more sensitive setting:

```bash
python -m src.main data/sample_events.json --failed-threshold 2
```

## What to say

> The detection logic already supports a threshold parameter, but the command-line interface was using the default. I’m exposing that setting to the user so the same code can support different security policies without changing source code.

This is a small change, but it demonstrates configuration management, separation of concerns, and regression testing.
