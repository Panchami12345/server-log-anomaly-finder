import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from scanner import (
    parse_line, scan_file, detect_directory_scanning,
    detect_failed_login_flood, SUSPICIOUS_USER_AGENT,
    DIRECTORY_SCANNING, FAILED_LOGIN_FLOOD,
)


def line(n, time, status=200, path="/", ua='Mozilla/5.0', date="19/Oct/2026", ip="192.168.1.5"):
    return (f'{ip} - - [{date}:{time} +0000] "GET {path} HTTP/1.1" '
            f'{status} 123 "-" "{ua}"')


class ScannerTests(unittest.TestCase):
    def test_parser_extracts_user_agent(self):
        rec = parse_line(1, line(1, "10:00:00", ua="sqlmap/1.4"))
        self.assertIsNotNone(rec)
        self.assertEqual(rec.user_agent, "sqlmap/1.4")

    def test_parser_rejects_invalid_ipv4(self):
        self.assertIsNone(parse_line(1, line(1, "10:00:00", ip="999.999.999.999")))

    def test_parser_accepts_single_quoted_suspicious_agent(self):
        raw = "192.168.1.5 - - [19/Oct/2026:10:00:00 +0000] 'GET / HTTP/1.1' 200 12 'sqlmap/1.4'"
        rec = parse_line(1, raw)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.user_agent, "sqlmap/1.4")

    def test_directory_scan_window_crosses_midnight(self):
        records = [parse_line(i, line(i, t, 404, f"/missing{i}")) for i, t in enumerate(
            ["23:59:40", "23:59:55", "00:00:10"], 1)]
        # Use actual date change for the third record.
        records[2].date = "20/Oct/2026"
        found = detect_directory_scanning(records)
        self.assertTrue(any(a.type == DIRECTORY_SCANNING for a in found))

    def test_failed_login_flood(self):
        records = [parse_line(i, line(i, f"10:00:{i:02d}", 401, "/login")) for i in range(1, 6)]
        found = detect_failed_login_flood(records)
        self.assertTrue(any(a.type == FAILED_LOGIN_FLOOD for a in found))

    def test_scan_file_end_to_end(self):
        contents = "\n".join(line(i, f"10:00:0{i}", 404, f"/no{i}", ua="sqlmap/1.4") for i in range(1, 4))
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write(contents)
            path = f.name
        try:
            found = scan_file(path)
            self.assertTrue(any(a.type == DIRECTORY_SCANNING for a in found))
            self.assertTrue(any(a.type == SUSPICIOUS_USER_AGENT for a in found))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
