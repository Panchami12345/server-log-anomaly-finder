import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from scanner import (
    parse_line,
    scan_file,
    detect_directory_scanning,
    detect_failed_login_flood,
    detect_off_hours,
    detect_suspicious_user_agent,
)
from models import (
    DIRECTORY_SCANNING,
    FAILED_LOGIN_FLOOD,
    OFF_HOURS_ACCESS,
    SUSPICIOUS_USER_AGENT,
)


def make_line(line_no, time, status=200, path="/", ua="Mozilla/5.0",
              date="19/Oct/2026", ip="192.168.1.5", quote='"'):
    return (
        f"{ip} - - [{date}:{time} +0000] {quote}GET {path} HTTP/1.1{quote} "
        f'{status} 123 "-" "{ua}"'
    )


def parsed(line_no, time, status=200, path="/", ua="Mozilla/5.0",
           date="19/Oct/2026", ip="192.168.1.5"):
    record = parse_line(line_no, make_line(line_no, time, status, path, ua, date, ip))
    assert record is not None
    return record


class ScannerTests(unittest.TestCase):
    def test_parser_extracts_user_agent(self):
        rec = parse_line(1, make_line(1, "10:00:00", ua="sqlmap/1.4"))
        self.assertIsNotNone(rec)
        self.assertEqual(rec.user_agent, "sqlmap/1.4")

    def test_parser_rejects_invalid_ipv4(self):
        self.assertIsNone(parse_line(1, make_line(1, "10:00:00", ip="999.999.999.999")))

    def test_parser_rejects_malformed_line(self):
        self.assertIsNone(parse_line(1, "this is not an access log line"))
        self.assertIsNone(parse_line(2, ""))

    def test_parser_accepts_single_quoted_request_and_ua(self):
        raw = "192.168.1.5 - - [19/Oct/2026:10:00:00 +0000] 'GET / HTTP/1.1' 200 12 'sqlmap/1.4'"
        rec = parse_line(1, raw)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.user_agent, "sqlmap/1.4")

    def test_directory_scan_window_crosses_midnight(self):
        records = [
            parsed(1, "23:59:40", 404, "/missing1"),
            parsed(2, "23:59:55", 404, "/missing2"),
            parsed(3, "00:00:10", 404, "/missing3", date="20/Oct/2026"),
        ]
        found = detect_directory_scanning(records)
        self.assertTrue(any(a.type == DIRECTORY_SCANNING for a in found))

    def test_directory_scan_resets_on_non_404(self):
        records = [
            parsed(1, "10:00:01", 404, "/one"),
            parsed(2, "10:00:02", 200, "/ok"),
            parsed(3, "10:00:03", 404, "/two"),
            parsed(4, "10:00:04", 404, "/three"),
        ]
        found = detect_directory_scanning(records)
        self.assertFalse(any(a.type == DIRECTORY_SCANNING for a in found))

    def test_failed_login_flood(self):
        records = [parsed(i, f"10:00:{i:02d}", 401, "/login") for i in range(1, 6)]
        found = detect_failed_login_flood(records)
        self.assertTrue(any(a.type == FAILED_LOGIN_FLOOD for a in found))

    def test_failed_login_resets_on_non_failure(self):
        records = [
            parsed(1, "10:00:01", 401, "/login"),
            parsed(2, "10:00:02", 401, "/login"),
            parsed(3, "10:00:03", 200, "/login"),
            parsed(4, "10:00:04", 401, "/login"),
            parsed(5, "10:00:05", 401, "/login"),
            parsed(6, "10:00:06", 401, "/login"),
        ]
        found = detect_failed_login_flood(records)
        self.assertFalse(any(a.type == FAILED_LOGIN_FLOOD for a in found))

    def test_login_prefix_false_positive_is_rejected(self):
        records = [parsed(i, f"10:00:{i:02d}", 401, "/loginXYZ") for i in range(1, 6)]
        found = detect_failed_login_flood(records)
        self.assertFalse(any(a.type == FAILED_LOGIN_FLOOD for a in found))

    def test_off_hours_and_business_hours(self):
        records = [parsed(1, "08:59:59"), parsed(2, "09:00:00"), parsed(3, "17:59:59"), parsed(4, "18:00:00")]
        found = detect_off_hours(records)
        self.assertEqual([a.line_numbers[0] for a in found if a.type == OFF_HOURS_ACCESS], [1, 4])

    def test_empty_user_agent_is_flagged(self):
        record = parsed(1, "10:00:00", ua="")
        found = detect_suspicious_user_agent([record])
        self.assertTrue(any(a.type == SUSPICIOUS_USER_AGENT and a.severity == "MEDIUM" for a in found))

    def test_suspicious_user_agent_is_flagged(self):
        record = parsed(1, "10:00:00", ua="sqlmap/1.4")
        found = detect_suspicious_user_agent([record])
        self.assertTrue(any(a.type == SUSPICIOUS_USER_AGENT and a.severity == "HIGH" for a in found))

    def test_scan_file_end_to_end(self):
        contents = "\n".join(
            make_line(i, f"10:00:0{i}", 404, f"/no{i}", ua="sqlmap/1.4")
            for i in range(1, 4)
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(contents)
            path = handle.name
        try:
            found = scan_file(path)
            self.assertTrue(any(a.type == DIRECTORY_SCANNING for a in found))
            self.assertTrue(any(a.type == SUSPICIOUS_USER_AGENT for a in found))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
