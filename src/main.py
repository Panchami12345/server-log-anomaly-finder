"""Command-line entry point.

Usage:
    python src/main.py logs/sample_logs.txt
    python src/main.py logs/sample_logs.txt --json reports/report.json --chart reports/anomaly_chart.png
    python src/main.py logs/sample_logs.txt --no-color

The detection engine lives in src/scanner.py and must expose:
    scan_file(path: str) -> list[models.Anomaly]
"""
import argparse
import os
import sys

from report import build_report, print_console, write_json
from visualize import make_chart


def count_lines(path: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as f:
        return sum(1 for _ in f)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Server Log Anomaly Finder")
    p.add_argument("logfile", help="path to an Apache/Nginx-style log file")
    p.add_argument("--json", default="reports/report.json", help="JSON report path")
    p.add_argument("--chart", default="reports/anomaly_chart.png", help="chart image path")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = p.parse_args(argv)

    if not os.path.isfile(args.logfile):
        print(f"error: file not found: {args.logfile}", file=sys.stderr)
        return 1

    try:
        from scanner import scan_file
    except ImportError:
        print("error: src/scanner.py (detection engine) not found or incomplete.", file=sys.stderr)
        return 2

    anomalies = scan_file(args.logfile)
    report = build_report(anomalies, args.logfile, count_lines(args.logfile))
    print_console(report, color=False if args.no_color else None)
    print(f"\nJSON report : {write_json(report, args.json)}")
    print(f"Chart       : {make_chart(report, args.chart)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
