# Detection Thresholds — Member 2
**Course:** Theory of Computation (BIS503) | Project 8

This document defines the detection thresholds for all four anomaly detectors.
These values are the **single source of truth** — `src/scanner.py` imports and
uses these exact values. Any change here must be reflected in the scanner.

---

## Threshold Table

| Detector | Parameter | Value | Unit | Justification |
|----------|-----------|-------|------|---------------|
| Directory Scanning | Minimum consecutive 404s | **3** | requests | 1–2 accidental; 3+ is scanning behaviour |
| Directory Scanning | Sliding window | **60** | seconds | Burst attacks happen fast; 60s is tight enough |
| Failed Login Flood | Minimum failures | **5** | requests | Occasional typos allowed; 5 in a row = brute force |
| Failed Login Flood | Sliding window | **60** | seconds | Matches OWASP brute-force detection guideline |
| Off-Hours Access | Business hours start | **09:00** | hour (inclusive) | Standard office hours |
| Off-Hours Access | Business hours end | **18:00** | hour (exclusive) | 18:00 itself is off-hours (hour ≥ 18 flagged) |
| Suspicious User-Agent | Match count | **1** | per line | Single keyword match = instant flag, no threshold |

---

## DFA 1 — Directory Scanning

```
Threshold:  SCAN_MIN_404    = 3   consecutive 404 responses from same IP
Window:     SCAN_WINDOW_SEC = 60  seconds (sliding window)
Severity:   HIGH
```

**How it works:**
- The DFA counts consecutive 404 responses from the same IP
- Any non-404 response resets the count to zero (back to state q0)
- Alert fires when count reaches 3 (state q3) within 60 seconds
- After alert fires, counter resets to avoid duplicate alerts for the same burst

**Why 3 and not 5 or 10?**
A legitimate user almost never gets 3 consecutive 404s. Scanners like `dirbuster`
or `gobuster` send hundreds per second. Setting threshold at 3 catches even
slow/evasive scanners while keeping false positives near zero.

---

## DFA 2 — Failed Login Flood

```
Threshold:  LOGIN_MIN_FAILS  = 5   failed login attempts from same IP
Window:     LOGIN_WINDOW_SEC = 60  seconds (sliding window)
Severity:   HIGH
```

**How it works:**
- Only counts 401/403 responses on known login paths (`/login`, `/signin`,
  `/auth`, `/wp-login.php`, `/admin/login`)
- Any successful response (200) or request to a non-login path resets the count
- Alert fires when count reaches 5 within 60 seconds (state q5 in DFA 2)

**Why 5?**
A user can mistype their password 1–2 times. 5 failures in 60 seconds strongly
indicates automated brute-force. This matches industry standard (e.g. Fail2ban
default is 5 failures in 10 minutes — we use a stricter 60-second window).

---

## DFA 3 — Off-Hours Access

```
Business hours:  09:00 (inclusive) to 18:00 (exclusive)
Off-hours:       00:00–08:59  and  18:00–23:59
Severity:        MEDIUM (hours 06–08 and 18–19)
                 LOW    (hours 00–05 and 20–23)
```

**How it works:**
- Extracts the 2-digit hour from each log line's timestamp
- DFA reads digits: first digit → q_h0 (if 0) or q_h1 (if 1) or q_off (if 2+)
- q_h0 + second digit 0–8 → q_off (alert); second digit 9 → q_biz (safe)
- q_h1 + second digit 0–7 → q_biz (safe); second digit 8–9 → q_off (alert)
- Stateless — every line checked independently

**Severity split:**
Requests just outside business hours (6–8 AM, 6–7 PM) are MEDIUM — could be
an early/late worker. Deep night requests (midnight–5 AM, 8–11 PM) are LOW
because they are suspicious but less urgent than active attack patterns.

---

## DFA 4 — Suspicious User-Agent

```
Match count:  1 keyword match per line = instant alert
Severity:     HIGH  (known tool keyword matched)
              MEDIUM (empty or dash-only user-agent)
```

**Known tool keywords (case-insensitive):**

| Keyword | Tool | Risk |
|---------|------|------|
| `sqlmap` | SQL injection scanner | CRITICAL |
| `nikto` | Web vulnerability scanner | CRITICAL |
| `nmap` | Network port scanner | HIGH |
| `masscan` | Fast internet scanner | HIGH |
| `zgrab` | TLS/banner grabber | HIGH |
| `scrapy` | Python web scraper | MEDIUM |
| `python-requests` | Automated HTTP script | MEDIUM |
| `libwww-perl` | Old Perl HTTP library | MEDIUM |
| `go-http-client` | Raw Go HTTP client | MEDIUM |
| `curl/` | curl with version number | MEDIUM |
| `wget/` | wget with version number | MEDIUM |
| `-` or empty | Identity concealment | MEDIUM |

**Why immediate alert (threshold = 1)?**
Legitimate browsers never send tool-specific user-agents. A single appearance
of `sqlmap` or `nikto` is already 100% indicative of malicious intent — there
is no legitimate reason for these strings to appear in production logs.

---

## Threshold Values in Code

All thresholds are defined as constants at the top of `src/scanner.py`:

```python
SCAN_MIN_404       = 3     # DFA 1 — consecutive 404s before alert
SCAN_WINDOW_SEC    = 60    # DFA 1 — sliding window in seconds
LOGIN_MIN_FAILS    = 5     # DFA 2 — failed logins before alert
LOGIN_WINDOW_SEC   = 60    # DFA 2 — sliding window in seconds
BUSINESS_START     = 9     # DFA 3 — business hours start (inclusive)
BUSINESS_END       = 18    # DFA 3 — business hours end (exclusive)
SUSPICIOUS_UA_KEYWORDS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "scrapy",
    "python-requests", "libwww-perl", "go-http-client", "curl/", "wget/",
]
```

To tune any threshold, change **only** the constant in `scanner.py` —
no other file needs to change.

---

*Prepared by: Member 2 — Regex Patterns & DFA Design*
*Course: BIS503 — Theory of Computation*
