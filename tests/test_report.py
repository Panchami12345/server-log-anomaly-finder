"""Unit tests for the reporting layer. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from models import Anomaly, DIRECTORY_SCANNING, OFF_HOURS_ACCESS  # noqa: E402
from report import build_report, render_console, write_json, duration_seconds  # noqa: E402
from visualize import make_chart  # noqa: E402


def sample():
    return [
        Anomaly(OFF_HOURS_ACCESS, "LOW", "1.1.1.1", "23:00:00", "23:00:00", [9], "late"),
        Anomaly(DIRECTORY_SCANNING, "HIGH", "2.2.2.2", "03:21:00", "03:21:02", [1, 2, 3], "scan"),
    ]


class ReportTests(unittest.TestCase):
    def test_summary_counts_and_sorting(self):
        r = build_report(sample(), "x.log", 50)
        self.assertEqual(r["summary"]["total_anomalies"], 2)
        self.assertEqual(r["summary"]["by_severity"]["HIGH"], 1)
        self.assertEqual(r["anomalies"][0]["severity"], "HIGH")
        self.assertEqual(r["summary"]["flagged_lines"], 4)

    def test_duration(self):
        self.assertEqual(duration_seconds(sample()[1]), 3)

    def test_console_contains_key_fields(self):
        text = render_console(build_report(sample(), "x.log", 50), color=False)
        self.assertIn("ANOMALY DETECTED: Directory Scanning", text)
        self.assertIn("2.2.2.2", text)
        self.assertNotIn("\033[", text)

    def test_empty_report(self):
        r = build_report([], "x.log", 10)
        self.assertEqual(r["summary"]["total_anomalies"], 0)
        render_console(r, color=False)

    def test_json_and_chart_written(self):
        r = build_report(sample(), "x.log", 50)
        with tempfile.TemporaryDirectory() as d:
            p = write_json(r, os.path.join(d, "r.json"))
            with open(p) as f:
                self.assertEqual(json.load(f)["summary"]["total_anomalies"], 2)
            png = make_chart(r, os.path.join(d, "c.png"))
            self.assertTrue(os.path.getsize(png) > 1000)


if __name__ == "__main__":
    unittest.main()
