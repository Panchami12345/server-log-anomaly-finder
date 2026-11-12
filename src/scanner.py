"""Detection engine (owner: Member 2).

Contract used by main.py:  scan_file(path) -> list[Anomaly]

Patterns come from docs/regex_patterns.md, DFA state machines from
docs/dfa_design.md, thresholds from docs/thresholds.md.  Thresholds live ONLY
in the constants block below.

Each detector is a finite automaton:
  DFA 1  directory scanning  states q0..q3, accept q3   (per IP, stateful)
  DFA 2  failed-login flood  states q0..q5, accept q5   (per IP, stateful)
  DFA 3  off-hours access    stateless, reads the hour  (per line)
  DFA 4  suspicious UA       stateless keyword match    (per line)
"""
import re
from typing import Dict, Iterable, List, Optional

from models import (Anomaly, LogRecord, DIRECTORY_SCANNING, FAILED_LOGIN_FLOOD,
                    OFF_HOURS_ACCESS, SUSPICIOUS_USER_AGENT)

# ---------------------------------------------------------------- parsing ---
# Accepts Apache/Nginx combined or common format. The request line may use
# double quotes ("GET /x HTTP/1.1") or single quotes ('GET /x HTTP/1.1');
# timezone, protocol, referer and user-agent are all optional.
LOG_RE = re.compile(
    r"""^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"""
    r"""\[(?P<date>\d{2}/\w{3}/\d{4}):(?P<time>\d{2}:\d{2}:\d{2})(?:\s+[+-]\d{4})?\]\s+"""
    r"""(?:"(?P<req_d>[^"]*)"|'(?P<req_s>[^']*)')\s+"""
    r"""(?P<status>\d{3})\s+(?P<size>\d+|-)"""
    r"""(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?""")

REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$")

# ------------------------------------------------------------- thresholds ---
SCAN_MIN_404 = 2          # consecutive 404s from one IP ...
SCAN_WINDOW_SEC = 60      # ... within this many seconds
LOGIN_MIN_FAILS = 5       # failed logins from one IP ...
LOGIN_WINDOW_SEC = 60     # ... within this many seconds
BUSINESS_START, BUSINESS_END = 9, 18   # business hours 09:00-17:59 (18:00 is off-hours)

LOGIN_PATH_RE = re.compile(r"^/(?:login|signin|auth|wp-login\.php|admin/login)(?:[/?#]\S*)?$", re.I)
FAIL_STATUSES = (401, 403)

SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "scrapy", "python-requests",
                 "libwww-perl", "go-http-client", "curl/", "wget/"]
UA_RE = re.compile("|".join(re.escape(k) for k in SUSPICIOUS_UA), re.I)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _epoch(date: str, time: str) -> int:
    """Seconds since an arbitrary origin; only differences are used (locale-free)."""
    d, mon, y = date.split("/")
    h, m, s = (int(x) for x in time.split(":"))
    day_index = int(y) * 372 + _MONTHS.get(mon.capitalize(), 0) * 31 + int(d)
    return day_index * 86400 + h * 3600 + m * 60 + s


def parse_line(line_no: int, line: str) -> Optional[LogRecord]:
    """Parse one raw line into a LogRecord, or None if malformed (never raises)."""
    try:
        m = LOG_RE.match(line.strip())
        if not m:
            return None
        req = REQUEST_RE.match(m.group("req_d") if m.group("req_d") is not None else m.group("req_s"))
        if not req:
            return None
        ua = m.group("ua")
        if ua is None:
            ua = ""                      # field absent (common log format)
        elif ua.strip() == "":
            ua = "-"                     # present but empty
        return LogRecord(
            line_no=line_no, ip=m.group("ip"), time=m.group("time"), date=m.group("date"),
            method=req.group("method"), path=req.group("path"), status=int(m.group("status")),
            size=0 if m.group("size") == "-" else int(m.group("size")),
            user_agent=ua, raw=line)
    except Exception:
        return None


def _ts(r: LogRecord) -> int:
    return _epoch(r.date, r.time)


def _burst(rtype, severity, recs, text) -> Anomaly:
    return Anomaly(type=rtype, severity=severity, ip=recs[0].ip,
                   start_time=recs[0].time, end_time=recs[-1].time,
                   line_numbers=[r.line_no for r in recs], description=text,
                   evidence=[r.raw for r in recs])


# ------------------------------------------------------------------ DFA 1 ---
def detect_directory_scanning(records: Iterable[LogRecord]) -> List[Anomaly]:
    """DFA 1: q0 -404-> q1 -404-> q2 -404-> q3 (accept, self-loop on 404);
    any non-404 from that IP resets to q0. Count must be reached inside the window."""
    window: Dict[str, List[LogRecord]] = {}
    active: Dict[str, Anomaly] = {}          # IP currently in accept state q3
    out: List[Anomaly] = []
    for r in records:
        if r.status != 404:
            window.pop(r.ip, None)
            active.pop(r.ip, None)
            continue
        if r.ip in active:                   # q3 --404--> q3 : extend the alert
            a = active[r.ip]
            a.end_time = r.time
            a.line_numbers.append(r.line_no)
            a.evidence.append(r.raw)
            a.description = _scan_text(len(a.line_numbers), a.evidence)
            continue
        w = window.setdefault(r.ip, [])
        w.append(r)
        t = _ts(r)
        while w and t - _ts(w[0]) > SCAN_WINDOW_SEC:
            w.pop(0)
        if len(w) >= SCAN_MIN_404:           # reached q3
            a = _burst(DIRECTORY_SCANNING, "HIGH", list(w), "")
            a.description = _scan_text(len(w), a.evidence)
            active[r.ip] = a
            out.append(a)
    return out


def _scan_text(n: int, evidence: List[str]) -> str:
    return f"{n} consecutive 404s within {SCAN_WINDOW_SEC}s - possible directory scanning / reconnaissance"


# ------------------------------------------------------------------ DFA 2 ---
def detect_failed_login_flood(records: Iterable[LogRecord]) -> List[Anomaly]:
    """DFA 2: q0..q5, each 401/403 on a login path advances; q5 accepts and stays.
    A successful login or any non-failure request from that IP resets to q0."""
    window: Dict[str, List[LogRecord]] = {}
    active: Dict[str, Anomaly] = {}
    out: List[Anomaly] = []
    for r in records:
        is_fail = (r.status in FAIL_STATUSES and r.method in ("GET", "POST")
                   and bool(LOGIN_PATH_RE.match(r.path)))
        if not is_fail:
            window.pop(r.ip, None)
            active.pop(r.ip, None)
            continue
        if r.ip in active:
            a = active[r.ip]
            a.end_time = r.time
            a.line_numbers.append(r.line_no)
            a.evidence.append(r.raw)
            a.description = _login_text(len(a.line_numbers))
            continue
        w = window.setdefault(r.ip, [])
        w.append(r)
        t = _ts(r)
        while w and t - _ts(w[0]) > LOGIN_WINDOW_SEC:
            w.pop(0)
        if len(w) >= LOGIN_MIN_FAILS:
            a = _burst(FAILED_LOGIN_FLOOD, "HIGH", list(w), _login_text(len(w)))
            active[r.ip] = a
            out.append(a)
    return out


def _login_text(n: int) -> str:
    return f"{n} failed logins (401/403) within {LOGIN_WINDOW_SEC}s - possible brute-force attack"


# ------------------------------------------------------------------ DFA 3 ---
def _hour_dfa(hh: str) -> str:
    """Reads the two hour digits; returns 'q_off' (accept) or 'q_biz'."""
    state = "q0"
    for ch in hh:
        if state == "q0":
            state = "q_h0" if ch == "0" else "q_h1" if ch == "1" else "q_off"
        elif state == "q_h0":
            state = "q_biz" if ch == "9" else "q_off"
        elif state == "q_h1":
            state = "q_biz" if ch in "01234567" else "q_off"
    return state


def detect_off_hours(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateless: flag requests outside 09:00-17:59. MEDIUM near the edges (06-08, 18-19), else LOW."""
    out: List[Anomaly] = []
    for r in records:
        hour = int(r.time[:2])
        if _hour_dfa(r.time[:2]) != "q_off":
            continue
        sev = "MEDIUM" if hour in (6, 7, 8, 18, 19) else "LOW"
        out.append(_burst(OFF_HOURS_ACCESS, sev, [r],
                          f"{r.method} {r.path} at {r.time} is outside business hours "
                          f"({BUSINESS_START:02d}:00-{BUSINESS_END:02d}:00)"))
    return out


# ------------------------------------------------------------------ DFA 4 ---
def detect_suspicious_user_agent(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Stateless: known attack-tool keyword -> HIGH; present-but-empty ('-') UA -> MEDIUM."""
    out: List[Anomaly] = []
    for r in records:
        ua = r.user_agent.strip()
        m = UA_RE.search(ua)
        if m:
            out.append(_burst(SUSPICIOUS_USER_AGENT, "HIGH", [r],
                              f"User-agent contains known tool '{m.group(0)}': {ua[:60]}"))
        elif ua == "-":
            out.append(_burst(SUSPICIOUS_USER_AGENT, "MEDIUM", [r],
                              "Empty user-agent - client hides its identity"))
    return out


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
