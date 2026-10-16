"""Detection engine - SKELETON (owner: Member 2 / scanner author).

Contract used by main.py:  scan_file(path) -> list[Anomaly]
Fill in the TODOs using the patterns and thresholds from docs/regex_patterns.md
and docs/dfa_design.md. Keep the function names so the other modules keep working.
"""
import re
from typing import Iterable, List, Optional

from models import (Anomaly, LogRecord, DIRECTORY_SCANNING, FAILED_LOGIN_FLOOD,
                    OFF_HOURS_ACCESS, SUSPICIOUS_USER_AGENT)

# TODO: replace with the final regex from docs/regex_patterns.md.
# Must accept BOTH quote styles: "GET /x HTTP/1.1" (Apache) and 'GET /x HTTP/1.1' (problem-statement sample),
# with or without timezone, and with or without trailing referer/user-agent fields.
LOG_RE = re.compile(r"")

# Thresholds - agree with Member 2 and keep in ONE place.
SCAN_MIN_404 = 3          # consecutive 404s from one IP ...
SCAN_WINDOW_SEC = 10      # ... within this many seconds
LOGIN_MIN_FAILS = 5       # failed logins from one IP ...
LOGIN_WINDOW_SEC = 60     # ... within this many seconds
BUSINESS_START, BUSINESS_END = 9, 18   # business hours 09:00-18:00
SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "masscan", "curl", "python-requests"]  # TODO: finalise


def parse_line(line_no: int, line: str) -> Optional[LogRecord]:
    """Parse one raw line into a LogRecord, or None if malformed (never raise)."""
    raise NotImplementedError("TODO: implement with LOG_RE")


def detect_directory_scanning(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateful: repeated 404s from one IP inside a short window."""
    raise NotImplementedError


def detect_failed_login_flood(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateful: many failed logins (401/403 on login paths) from one IP in a window."""
    raise NotImplementedError


def detect_off_hours(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateless: request time outside business hours."""
    raise NotImplementedError


def detect_suspicious_user_agent(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateless: user-agent matches known tool list or is empty/abnormal."""
    raise NotImplementedError


def scan_file(path: str) -> List[Anomaly]:
    records = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            rec = parse_line(n, line.rstrip("\n"))
            if rec:
                records.append(rec)
    anomalies: List[Anomaly] = []
    for detector in (detect_directory_scanning, detect_failed_login_flood,
                     detect_off_hours, detect_suspicious_user_agent):
        anomalies.extend(detector(records))
    return anomalies
