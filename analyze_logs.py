"""Analyze a CSV of synthetic application/security logs for simple anomalies."""
from __future__ import annotations
import argparse
import csv
from collections import Counter
from pathlib import Path

FAILED_LOGIN_EVENTS = {"failed_login", "login_failed", "authentication_failure"}
ERROR_LEVELS = {"error", "critical"}


def analyze_logs(path: str | Path, failed_login_threshold: int = 3, error_threshold: int = 3) -> dict:
    """Return summaries and simple threshold-based flags from a CSV log file.

    Expected columns: timestamp, source_ip, event, level
    Thresholds flag a source/event or level when its count is >= threshold.
    """
    if failed_login_threshold < 1 or error_threshold < 1:
        raise ValueError("Thresholds must be at least 1.")

    source_failures: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    level_counts: Counter[str] = Counter()
    total = 0

    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "source_ip", "event", "level"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("CSV must contain columns: timestamp, source_ip, event, level")
        for row in reader:
            total += 1
            source = (row.get("source_ip") or "").strip() or "unknown"
            event = (row.get("event") or "").strip().lower()
            level = (row.get("level") or "").strip().lower()
            event_counts[event] += 1
            level_counts[level] += 1
            if event in FAILED_LOGIN_EVENTS:
                source_failures[source] += 1

    repeated_failures = {
        source: count for source, count in sorted(source_failures.items())
        if count >= failed_login_threshold
    }
    elevated_errors = {
        level: count for level, count in sorted(level_counts.items())
        if level in ERROR_LEVELS and count >= error_threshold
    }
    return {
        "total_events": total,
        "event_counts": dict(sorted(event_counts.items())),
        "level_counts": dict(sorted(level_counts.items())),
        "repeated_failed_logins": repeated_failures,
        "elevated_error_levels": elevated_errors,
    }


def print_report(report: dict) -> None:
    print("LOG ANOMALY ANALYSIS")
    print("=" * 24)
    print(f"Total events: {report['total_events']}")
    print("\nEvent counts:")
    for event, count in report["event_counts"].items():
        print(f"  {event or '(blank)'}: {count}")
    print("\nRepeated failed logins:")
    if report["repeated_failed_logins"]:
        for source, count in report["repeated_failed_logins"].items():
            print(f"  REVIEW {source}: {count} failed login events")
    else:
        print("  None met the threshold")
    print("\nElevated error levels:")
    if report["elevated_error_levels"]:
        for level, count in report["elevated_error_levels"].items():
            print(f"  REVIEW {level}: {count} events")
    else:
        print("  None met the threshold")
    print("\nThese are heuristic flags for review, not proof of an attack.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Flag simple patterns in a CSV log file.")
    parser.add_argument("csv_file", nargs="?", default="sample_logs.csv", help="Path to CSV log file")
    parser.add_argument("--failed-login-threshold", type=int, default=3)
    parser.add_argument("--error-threshold", type=int, default=3)
    args = parser.parse_args()
    report = analyze_logs(args.csv_file, args.failed_login_threshold, args.error_threshold)
    print_report(report)


if __name__ == "__main__":
    main()
