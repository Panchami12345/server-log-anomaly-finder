"""Detection engine — Member 2 implementation.

Contract used by main.py:  scan_file(path) -> list[Anomaly]
Patterns and thresholds from docs/regex_patterns.md and docs/dfa_design.md.
Function names kept identical to skeleton so all other modules keep working.
"""
import re
from collections import defaultdict
from typing import Iterable, List, Optional

from models import (Anomaly, LogRecord, DIRECTORY_SCANNING, FAILED_LOGIN_FLOOD,
                    OFF_HOURS_ACCESS, SUSPICIOUS_USER_AGENT)

# ---------------------------------------------------------------------------
# Log line regex — Apache/Nginx Combined Log Format
# Handles BOTH quote styles: "GET /x HTTP/1.1" and 'GET /x HTTP/1.1'
# Handles optional timezone, optional referer, optional user-agent
# Example:
#   192.168.1.5 - - [12/Jan/2025:03:21:00 +0000] "GET /admin HTTP/1.1" 404 512 "-" "sqlmap/1.4"
# ---------------------------------------------------------------------------
LOG_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+\S+\s+\S+'
    r'\s+\[(?P<date>\d{2}/[A-Za-z]{3}/\d{4}):'
    r'(?P<time>\d{2}:\d{2}:\d{2})'
    r'(?:\s+(?P<tz>[+-]\d{4}))?\]'
    r'\s+(?P<q>[\"\'])'
    r'(?P<method>[A-Za-z]+)\s+(?P<path>\S+)\s+HTTP/\d\.\d'
    r'(?P=q)\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?P<tail>.*)$'
)
QUOTED_FIELD_RE = re.compile(r'\s+([\"\'])(.*?)\1')
IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


# ---------------------------------------------------------------------------
# Thresholds — single source of truth (also documented in docs/thresholds.md)
# ---------------------------------------------------------------------------
SCAN_MIN_404      = 3     # consecutive 404s from one IP to trigger alert
SCAN_WINDOW_SEC   = 60    # sliding window in seconds for 404 counting
LOGIN_MIN_FAILS   = 5     # failed logins from one IP to trigger alert
LOGIN_WINDOW_SEC  = 60    # sliding window in seconds for login counting
BUSINESS_START    = 9     # business hours start (inclusive) 09:00
BUSINESS_END      = 18    # business hours end (exclusive) 18:00 is off-hours

# Known attack/scanner tool keywords — case-insensitive match on user-agent
SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "scrapy",
    "python-requests", "libwww-perl", "go-http-client",
    "curl/", "wget/",
]

# Login paths monitored for brute-force
LOGIN_PATHS = ("login", "signin", "auth", "wp-login.php", "admin/login")

# Status codes that indicate a failed login attempt
FAILED_LOGIN_CODES = {401, 403}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _timestamp(rec: LogRecord):
    """Return a real datetime so windows work across midnight and dates."""
    from datetime import datetime
    try:
        return datetime.strptime(f"{rec.date} {rec.time}", "%d/%b/%Y %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _within_window(records, current, seconds: int):
    """Keep only records no more than seconds before current timestamp."""
    current_ts = _timestamp(current)
    if current_ts is None:
        return []
    kept = []
    for record in records:
        ts = _timestamp(record)
        if ts is not None and 0 <= (current_ts - ts).total_seconds() <= seconds:
            kept.append(record)
    return kept


def _is_login_path(path: str) -> bool:
    """Return True if path starts with any known login endpoint."""
    p = path.lower().lstrip("/")
    return any(p.startswith(lp) for lp in LOGIN_PATHS)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_line(line_no: int, line: str) -> Optional[LogRecord]:
    """Parse Apache/Nginx combined-style log line. Invalid lines return None."""
    if not line or not line.strip():
        return None
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ip = m.group("ip")
        # Validate octet ranges, not just dotted-decimal shape.
        octets = [int(part) for part in ip.split(".")]
        if len(octets) != 4 or any(part < 0 or part > 255 for part in octets):
            return None
        # Validate date/time as well as syntax.
        from datetime import datetime
        datetime.strptime(f'{m.group("date")} {m.group("time")}', "%d/%b/%Y %H:%M:%S")
        tail = m.group("tail")
        quoted = list(QUOTED_FIELD_RE.finditer(tail))
        referer, user_agent = "", ""
        if len(quoted) >= 2:
            referer, user_agent = quoted[0].group(2), quoted[1].group(2)
        elif len(quoted) == 1:
            # Some shortened logs include only a user-agent. Recognize known
            # scanner/client markers; otherwise treat the lone field as referer.
            value = quoted[0].group(2)
            if any(k in value.lower() for k in SUSPICIOUS_UA) or value.lower().startswith(("mozilla/", "opera/")):
                user_agent = value
            else:
                referer = value
        size_str = m.group("size")
        return LogRecord(
            line_no=line_no, ip=ip, date=m.group("date"), time=m.group("time"),
            method=m.group("method").upper(), path=m.group("path"),
            status=int(m.group("status")), size=int(size_str) if size_str != "-" else 0,
            user_agent=user_agent.strip(), raw=line,
        )
    except (ValueError, AttributeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# DFA 1 — Directory Scanning (repeated 404s)
#
# States:  q0 (0 hits) → q1 (1) → q2 (2) → q3 (alert, accept state)
# Input:   404 → advance state | OTHER → reset to q0
# Window:  only count 404s that fall within SCAN_WINDOW_SEC of each other
# Per-IP:  each IP runs its own independent DFA instance
# ---------------------------------------------------------------------------

def detect_directory_scanning(records: Iterable[LogRecord]) -> List[Anomaly]:
    anomalies: List[Anomaly] = []
    # Per-IP: state (int) and sliding window of matching records
    ip_state: dict = defaultdict(lambda: {"state": 0, "window": []})

    for rec in records:
        bucket = ip_state[rec.ip]

        if rec.status != 404:
            # Non-404 → reset DFA to q0
            bucket["state"] = 0
            bucket["window"] = []
            continue

        bucket["window"] = _within_window(bucket["window"], rec, SCAN_WINDOW_SEC)

        # Only advance state if current record fits in the window
        if bucket["window"] or bucket["state"] == 0:
            bucket["window"].append(rec)
            bucket["state"] = len(bucket["window"])
        else:
            # Window is empty and this is a fresh start
            bucket["window"] = [rec]
            bucket["state"] = 1

        # DFA accept state: SCAN_MIN_404 or more consecutive 404s in window
        if bucket["state"] >= SCAN_MIN_404:
            window = bucket["window"]
            anomalies.append(Anomaly(
                type         = DIRECTORY_SCANNING,
                severity     = "HIGH",
                ip           = rec.ip,
                start_time   = window[0].time,
                end_time     = rec.time,
                line_numbers = [r.line_no for r in window],
                description  = (
                    f"{rec.ip} made {len(window)} consecutive 404 requests "
                    f"within {SCAN_WINDOW_SEC}s — possible directory scanning."
                ),
                evidence     = [r.raw for r in window],
            ))
            # Reset after alert to avoid duplicate alerts for same burst
            bucket["state"] = 0
            bucket["window"] = []

    return anomalies


# ---------------------------------------------------------------------------
# DFA 2 — Failed Login Flood
#
# States:  q0 → q1 → q2 → q3 → q4 → q5 (alert, accept state)
# Input:   FAIL (401/403 on login path) → advance | OTHER → reset to q0
# Window:  only count failures within LOGIN_WINDOW_SEC
# Per-IP:  each IP runs its own independent DFA instance
# ---------------------------------------------------------------------------

def detect_failed_login_flood(records: Iterable[LogRecord]) -> List[Anomaly]:
    anomalies: List[Anomaly] = []
    ip_state: dict = defaultdict(lambda: {"state": 0, "window": []})

    for rec in records:
        bucket = ip_state[rec.ip]
        is_fail = rec.status in FAILED_LOGIN_CODES and _is_login_path(rec.path)

        if not is_fail:
            # Not a failed login → reset DFA to q0
            bucket["state"] = 0
            bucket["window"] = []
            continue

        bucket["window"] = _within_window(bucket["window"], rec, LOGIN_WINDOW_SEC)

        bucket["window"].append(rec)
        bucket["state"] = len(bucket["window"])

        # DFA accept state: LOGIN_MIN_FAILS or more failures in window
        if bucket["state"] >= LOGIN_MIN_FAILS:
            window = bucket["window"]
            anomalies.append(Anomaly(
                type         = FAILED_LOGIN_FLOOD,
                severity     = "HIGH",
                ip           = rec.ip,
                start_time   = window[0].time,
                end_time     = rec.time,
                line_numbers = [r.line_no for r in window],
                description  = (
                    f"{rec.ip} made {len(window)} failed login attempts "
                    f"within {LOGIN_WINDOW_SEC}s — possible brute-force attack."
                ),
                evidence     = [r.raw for r in window],
            ))
            # Reset after alert
            bucket["state"] = 0
            bucket["window"] = []

    return anomalies


# ---------------------------------------------------------------------------
# DFA 3 — Off-Hours Access (stateless per line)
#
# States:  q0 → q_h0 (first digit 0) / q_h1 (first digit 1) / q_off (digit 2+)
#          q_h0 + second digit 0-8 → q_off (alert)
#          q_h0 + second digit 9   → q_biz (safe)
#          q_h1 + second digit 0-7 → q_biz (safe)
#          q_h1 + second digit 8-9 → q_off (alert)
# Stateless: each log line checked independently
# ---------------------------------------------------------------------------

def detect_off_hours(records: Iterable[LogRecord]) -> List[Anomaly]:
    anomalies: List[Anomaly] = []

    for rec in records:
        hour = int(rec.time.split(":")[0])

        # DFA 3 transition: integer(HH) < 9 or integer(HH) >= 18 → q_off
        is_off_hours = hour < BUSINESS_START or hour >= BUSINESS_END

        if is_off_hours:
            # Severity: MEDIUM for hours just outside business hours, LOW for deep night
            severity = "MEDIUM" if (6 <= hour < 9 or 18 <= hour < 20) else "LOW"
            anomalies.append(Anomaly(
                type         = OFF_HOURS_ACCESS,
                severity     = severity,
                ip           = rec.ip,
                start_time   = rec.time,
                end_time     = rec.time,
                line_numbers = [rec.line_no],
                description  = (
                    f"{rec.ip} accessed {rec.path} at {rec.time} "
                    f"(hour={hour:02d}) — outside business hours "
                    f"({BUSINESS_START:02d}:00–{BUSINESS_END:02d}:00)."
                ),
                evidence     = [rec.raw],
            ))

    return anomalies


# ---------------------------------------------------------------------------
# DFA 4 — Suspicious User-Agent (stateless per line)
#
# States:  q0 → q_scan (known tool keyword found — HIGH)
#               q_empty (empty or dash-only UA — MEDIUM)
#               q_norm  (normal UA — no alert)
# Once in q_scan or q_empty the state stays (no transition back to q_norm)
# Stateless: each log line checked independently
# ---------------------------------------------------------------------------

_UA_RE = re.compile(
    "|".join(re.escape(k) for k in SUSPICIOUS_UA),
    re.IGNORECASE,
)

# Empty or identity-concealing user-agent values
_EMPTY_UA = {"", "-", '"-"', '""'}


def detect_suspicious_user_agent(records: Iterable[LogRecord]) -> List[Anomaly]:
    anomalies: List[Anomaly] = []

    for rec in records:
        ua = rec.user_agent.strip()

        # DFA 4 — q_empty state: empty or dash-only user-agent
        if ua in _EMPTY_UA:
            anomalies.append(Anomaly(
                type         = SUSPICIOUS_USER_AGENT,
                severity     = "MEDIUM",
                ip           = rec.ip,
                start_time   = rec.time,
                end_time     = rec.time,
                line_numbers = [rec.line_no],
                description  = (
                    f"{rec.ip} sent a request with empty/missing user-agent "
                    f"at {rec.time} — identity concealment suspected."
                ),
                evidence     = [rec.raw],
            ))
            continue

        # DFA 4 — q_scan state: known attack tool keyword found
        match = _UA_RE.search(ua)
        if match:
            anomalies.append(Anomaly(
                type         = SUSPICIOUS_USER_AGENT,
                severity     = "HIGH",
                ip           = rec.ip,
                start_time   = rec.time,
                end_time     = rec.time,
                line_numbers = [rec.line_no],
                description  = (
                    f"{rec.ip} used known attack tool '{match.group()}' "
                    f"as user-agent at {rec.time}."
                ),
                evidence     = [rec.raw],
            ))
        # q_norm: no action — normal user-agent

    return anomalies


# ---------------------------------------------------------------------------
# Main entry point — called by main.py
# scan_file(path) -> list[Anomaly]  (contract must not change)
# ---------------------------------------------------------------------------

def scan_file(path: str) -> List[Anomaly]:
    """Read log file at path, parse every line, run all 4 detectors.
    Returns a list of Anomaly objects sorted by first line number.
    """
    records: List[LogRecord] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            rec = parse_line(n, line.rstrip("\n"))
            if rec:
                records.append(rec)

    # Process chronologically so time windows behave correctly across midnight.
    records.sort(key=lambda r: (_timestamp(r) or __import__("datetime").datetime.min, r.line_no))

    anomalies: List[Anomaly] = []
    for detector in (
        detect_directory_scanning,
        detect_failed_login_flood,
        detect_off_hours,
        detect_suspicious_user_agent,
    ):
        anomalies.extend(detector(records))

    # Sort by first line number for clean report output
    anomalies.sort(key=lambda a: a.line_numbers[0])
    return anomalies
