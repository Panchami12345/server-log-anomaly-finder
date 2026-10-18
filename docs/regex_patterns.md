# Regex Patterns — Member 2
**Course:** Theory of Computation (BIS503) | Project 8

This document defines the four regular expression patterns used to detect anomalies in Apache/Nginx server logs. Each pattern is explained with its structure, sample matches, and how it connects to finite automata theory.

---

## Log Line Format (Reference)

A standard Apache Combined Log Format line looks like:

```
192.168.1.5 - - [12/Jan/2025:03:21:00 +0000] "GET /admin/config HTTP/1.1" 404 512 "-" "Mozilla/5.0"
```

Fields: `IP - - [timestamp] "METHOD /path HTTP/version" status size "referer" "user-agent"`

---

## Pattern 1 — Directory Scanning (Repeated 404 Errors)

**Anomaly:** An attacker probes for hidden files or admin paths by sending many requests that return 404. Three or more 404 responses from the same IP within a short window is flagged.

### Regex — Single line match (status code 404)
```regex
^(\d{1,3}(?:\.\d{1,3}){3}).*?"(?:GET|POST|HEAD)\s+(\S+)\s+HTTP/\d\.\d"\s+404\s
```

**Explanation of each part:**

| Part | Meaning |
|------|---------|
| `^` | Start of log line |
| `(\d{1,3}(?:\.\d{1,3}){3})` | Captures IPv4 address (e.g. `192.168.1.5`) |
| `.*?` | Skips timestamp and other fields (non-greedy) |
| `"(?:GET\|POST\|HEAD)` | Matches HTTP methods |
| `\s+(\S+)\s+HTTP/\d\.\d"` | Captures the URL path |
| `\s+404\s` | Status code is exactly 404 |

**Sample matches:**
```
192.168.1.5 - - [12/Jan/2025:03:21:00 +0000] "GET /admin HTTP/1.1" 404 512       ✓ MATCH
192.168.1.5 - - [12/Jan/2025:03:21:01 +0000] "GET /admin/login HTTP/1.1" 404 512 ✓ MATCH
10.0.0.1    - - [12/Jan/2025:10:05:00 +0000] "GET /index.html HTTP/1.1" 200 1024  ✗ NO MATCH
```

**Detection logic:** The regex matches individual 404 lines. The detector groups matches by IP and flags any IP with **≥ 3 consecutive 404s** within a 60-second sliding window.

**Threshold:** 3 consecutive 404 responses from the same IP.

---

## Pattern 2 — Failed Login Flood

**Anomaly:** Brute-force login attempts produce repeated 401 (Unauthorized) or 403 (Forbidden) responses on authentication paths like `/login`, `/signin`, `/auth`.

### Regex — Single line match
```regex
^(\d{1,3}(?:\.\d{1,3}){3}).*?"(?:GET|POST)\s+(\/(?:login|signin|auth|wp-login\.php|admin\/login)\S*)\s+HTTP/\d\.\d"\s+(?:401|403)\s
```

**Explanation of each part:**

| Part | Meaning |
|------|---------|
| `(\d{1,3}(?:\.\d{1,3}){3})` | Captures source IP |
| `(?:GET\|POST)` | Only GET or POST on login paths |
| `\/(?:login\|signin\|auth\|wp-login\.php\|admin\/login)` | Matches known login endpoints |
| `\S*` | Any additional path suffix |
| `(?:401\|403)` | Failed authentication status codes |

**Sample matches:**
```
10.0.0.55 - - [12/Jan/2025:14:32:01 +0000] "POST /login HTTP/1.1" 401 256         ✓ MATCH
10.0.0.55 - - [12/Jan/2025:14:32:02 +0000] "POST /login HTTP/1.1" 401 256         ✓ MATCH
10.0.0.55 - - [12/Jan/2025:14:32:03 +0000] "POST /auth HTTP/1.1" 403 256          ✓ MATCH
192.168.1.1 - - [12/Jan/2025:09:10:00 +0000] "GET /home HTTP/1.1" 200 1024        ✗ NO MATCH
```

**Detection logic:** The regex matches individual failed-auth lines. The detector flags any IP with **≥ 5 failures within 60 seconds**.

**Threshold:** 5 failed login attempts from the same IP within 60 seconds.

---

## Pattern 3 — Access Outside Business Hours

**Anomaly:** Requests made between **00:00–08:59** or **18:00–23:59** are flagged as off-hours access. This covers late-night crawlers, insider threats, or misconfigured bots.

### Regex — Timestamp extraction
```regex
\[(\d{2}/\w{3}/\d{4}):(\d{2}):(\d{2}):\d{2}\s[+-]\d{4}\]
```

**Explanation of each part:**

| Part | Meaning |
|------|---------|
| `\[` | Opening bracket of timestamp field |
| `\d{2}/\w{3}/\d{4}` | Date: `12/Jan/2025` |
| `:(\d{2})` | Captures the **hour** (group 2) |
| `:(\d{2})` | Captures the **minute** (group 3) |
| `[+-]\d{4}\]` | UTC offset and closing bracket |

**Off-hours check (applied after regex extraction):**
```
hour < 9  OR  hour >= 18   →  flag as OFF-HOURS ACCESS
```

**Sample matches:**
```
[12/Jan/2025:03:21:00 +0000]  → hour = 03 → 03 < 9  → ✓ FLAGGED (off-hours)
[12/Jan/2025:23:55:10 +0000]  → hour = 23 → 23 >= 18 → ✓ FLAGGED (off-hours)
[12/Jan/2025:10:30:00 +0000]  → hour = 10 → in range → ✗ NOT FLAGGED
[12/Jan/2025:17:59:00 +0000]  → hour = 17 → in range → ✗ NOT FLAGGED
```

**Business hours definition:** 09:00 to 17:59 only. 18:00 onwards is considered off-hours (hour >= 18 is flagged).

---

## Pattern 4 — Suspicious User-Agent Strings

**Anomaly:** Known scanning tools, exploit frameworks, and empty/malformed user-agent strings are flagged. Legitimate browsers always send well-formed user-agent headers.

### Regex — User-agent field match
```regex
"([^"]*(?:sqlmap|nikto|nmap|masscan|zgrab|python-requests|curl\/[0-9]|wget\/[0-9]|scrapy|go-http-client|java\/|libwww-perl|-|)[^"]*)"$
```

**Simplified version used in detection:**
```regex
(?i)(sqlmap|nikto|nmap|masscan|zgrab|scrapy|python-requests|libwww-perl|go-http-client|curl\/[0-9]|wget\/[0-9])
```

**Empty/dash user-agent check (separate condition):**
A bare `-` in the user-agent field cannot be reliably caught by the keyword regex alone since `-` appears elsewhere in log lines. It is checked separately in Python:
```python
if user_agent.strip() in ('-', '', '"-"', '""'):
    → flag as EMPTY USER-AGENT
```

**Explanation of each part:**

| Part | Meaning |
|------|---------|
| `(?i)` | Case-insensitive matching |
| `sqlmap` | SQL injection tool |
| `nikto` | Web vulnerability scanner |
| `nmap` | Network mapper/port scanner |
| `masscan` | Fast internet port scanner |
| `zgrab` | TLS/banner grabber |
| `scrapy` | Python web scraper |
| `python-requests` | Automated HTTP library |
| `libwww-perl` | Old Perl HTTP library, often used in attacks |
| `go-http-client` | Raw Go HTTP client |
| `curl\/[0-9]` | curl with version — command-line tool |
| `wget\/[0-9]` | wget with version — automated downloader |
| bare `-` or empty | Checked separately — identity hidden |

**Sample matches:**
```
"sqlmap/1.4 (https://sqlmap.org)"              ✓ FLAGGED — SQL injection tool
"Nikto/2.1.6"                                  ✓ FLAGGED — web scanner
"python-requests/2.28.0"                       ✓ FLAGGED — automated script
"-"                                            ✓ FLAGGED — empty user-agent
"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"   ✗ NORMAL — real browser
"curl/7.68.0"                                  ✓ FLAGGED — command-line tool
```

---

## Summary Table

| # | Anomaly Type | Regex Detects | Threshold | Severity |
|---|---|---|---|---|
| 1 | Directory Scanning | Status `404` + any path | ≥ 3 in 60s from same IP | HIGH |
| 2 | Failed Login Flood | Status `401`/`403` on login paths | ≥ 5 in 60s from same IP | HIGH |
| 3 | Off-Hours Access | Hour from timestamp | hour < 9 or hour ≥ 18 | LOW/MEDIUM |
| 4 | Suspicious User-Agent | Known tool names or empty string | Single match per line | MEDIUM/HIGH |

---

## Connection Between Regular Expressions and Finite Automata

A **regular expression** and a **finite automaton (DFA/NFA)** are two representations of the same thing — a **regular language**.

- Every regex can be converted to an **NFA** using **Thompson's construction**.
- Every NFA can be converted to an equivalent **DFA** using **subset construction**.
- Python's `re` module internally compiles a regex into a state machine (NFA/DFA hybrid) before matching.

This means when we write:
```python
import re
pattern = re.compile(r'.*404\s')
```
Python is building a finite automaton under the hood. The DFA diagrams in `dfa_design.md` represent exactly what the regex engine is doing — transitioning between states as it reads each character of a log line.

**In cybersecurity terms:** The log scanner is a collection of finite automata running in parallel, each watching for its own pattern. This is the same principle used in industrial SIEM tools like Splunk, Snort, and Suricata.

---

*Prepared by: Member 2 — Regex Patterns & DFA Design*
*Course: BIS503 — Theory of Computation*
