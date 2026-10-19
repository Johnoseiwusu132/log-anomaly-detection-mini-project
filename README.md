# Log Anomaly Detection Mini-Project

A small Python project that analyzes **synthetic CSV log events** and flags simple patterns for a security analyst to review.

## Features
- Counts event types and log levels.
- Flags source IP addresses with repeated failed-login events.
- Flags elevated counts of `error` or `critical` log levels.
- Includes five automated unit tests.
- Uses only the Python standard library.

## Project files
- `analyze_logs.py` — analysis logic and command-line report.
- `sample_logs.csv` — fictional sample data for demonstration.
- `tests/test_analyzer.py` — unit tests.

## Requirements
Python 3.9 or newer is recommended. No third-party packages are required.

## Run the analysis
From this folder, run:

```bash
python analyze_logs.py
```

Analyze another CSV file:

```bash
python analyze_logs.py path/to/your_logs.csv
```

Change thresholds:

```bash
python analyze_logs.py --failed-login-threshold 5 --error-threshold 4
```

Expected CSV columns: `timestamp`, `source_ip`, `event`, `level`.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Example interpretation
The included sample contains three failed-login events from `198.51.100.23` and three `error` events. With the default threshold of three, both patterns are flagged for review.

## Limitations and responsible use
This is a beginner educational lab, not a production detection system. It uses simple count thresholds and does not establish malicious intent. IP addresses and events in the sample are fictional/documentation-only examples. Real environments need context, time-window analysis, data validation, privacy safeguards, and analyst review. Only analyze logs you are authorized to access.
