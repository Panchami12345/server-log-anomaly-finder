"""Generates a demo report from hand-made anomalies (no scanner needed).

Run from the repo root:  python tests/demo_report.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from models import *  # noqa: E402,F403
from report import build_report, print_console, write_json  # noqa: E402
from visualize import make_chart  # noqa: E402


def demo_anomalies():
    return [
        Anomaly(DIRECTORY_SCANNING, "HIGH", "192.168.1.5", "03:21:00", "03:21:02",
                [41, 42, 43], "3 consecutive 404s on /admin paths - possible reconnaissance"),
        Anomaly(FAILED_LOGIN_FLOOD, "HIGH", "10.0.0.77", "14:02:10", "14:02:50",
                list(range(90, 98)), "8 failed POST /login (401) within 40 seconds"),
        Anomaly(OFF_HOURS_ACCESS, "MEDIUM", "172.16.4.9", "02:14:33", "02:14:33",
                [120], "Access to /admin at 02:14 (outside 09:00-18:00)"),
        Anomaly(SUSPICIOUS_USER_AGENT, "MEDIUM", "203.0.113.50", "11:11:11", "11:11:11",
                [150], "User-agent 'sqlmap/1.7' matches known scanner"),
        Anomaly(OFF_HOURS_ACCESS, "LOW", "192.168.1.20", "23:45:00", "23:45:00",
                [170], "Access to /index.html at 23:45"),
    ]


if __name__ == "__main__":
    rep = build_report(demo_anomalies(), "logs/sample_logs.txt", 200)
    print_console(rep)
    print(write_json(rep, "reports/demo_report.json"))
    print(make_chart(rep, "reports/demo_chart.png"))
