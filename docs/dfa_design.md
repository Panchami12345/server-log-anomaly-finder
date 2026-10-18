# DFA Design — Member 2
**Course:** Theory of Computation (BIS503) | Project 8

This document contains the DFA state diagrams, transition tables, and explanations for all four anomaly detection patterns. Each DFA models the logic of its corresponding regex pattern from `regex_patterns.md`.

---

## DFA 1 — Directory Scanning (Repeated 404 Errors)

**What it detects:** A sequence of 3 or more HTTP 404 responses from the same IP.

**States:**

| State | Meaning |
|-------|---------|
| `q0` | Start — no 404 seen yet from this IP |
| `q1` | One 404 seen |
| `q2` | Two consecutive 404s seen |
| `q3` | Three or more 404s — **ALERT** (accept state) |

**Input alphabet:** `{404, OTHER}` where OTHER = any status code that is not 404.

**Transition Table:**

| Current State | Input: `404` | Input: `OTHER` |
|--------------|-------------|----------------|
| → q0 | q1 | q0 |
| q1 | q2 | q0 |
| q2 | q3 | q0 |
| * q3 | q3 | q0 |

**State Diagram:**
```
         404          404          404
  → q0 -------> q1 -------> q2 -------> *q3 ←(self, 404)
     ↑           |           |            |
     |  OTHER    | OTHER     | OTHER      | OTHER
     └───────────┴───────────┴────────────┘
           (all OTHER transitions reset to q0)
```

**Explanation:**
- The DFA resets to `q0` whenever a non-404 status is seen — counting only **consecutive** 404s.
- `q3` is the accept (alert) state. Once reached, further 404s keep it in `q3` (the alert persists).
- Any `OTHER` status from `q3` resets to `q0` (the scanning burst is over).
- This DFA runs **per IP address** — each IP has its own independent instance.

---

## DFA 2 — Failed Login Flood

**What it detects:** Five or more failed authentication attempts (401/403 on login paths) from the same IP within a time window.

**States:**

| State | Meaning |
|-------|---------|
| `q0` | Start — no failure seen |
| `q1` | 1 failed login attempt |
| `q2` | 2 failed login attempts |
| `q3` | 3 failed login attempts |
| `q4` | 4 failed login attempts |
| `q5` | 5 or more failures — **ALERT** (accept state) |

**Input alphabet:** `{FAIL, OTHER}` where FAIL = 401 or 403 on a login path.

**Transition Table:**

| Current State | Input: `FAIL` | Input: `OTHER` |
|--------------|--------------|----------------|
| → q0 | q1 | q0 |
| q1 | q2 | q0 |
| q2 | q3 | q0 |
| q3 | q4 | q0 |
| q4 | q5 | q0 |
| * q5 | q5 | q0 |

**State Diagram:**
```
      FAIL     FAIL     FAIL     FAIL     FAIL
→ q0 ──→ q1 ──→ q2 ──→ q3 ──→ q4 ──→ *q5 ←(self, FAIL)
   ↑      |      |      |      |       |
   └──────┴──────┴──────┴──────┴───────┘
              (all OTHER transitions reset to q0)
```

**Explanation:**
- Each FAIL input advances the DFA one state forward.
- Any non-login or successful request resets back to `q0`.
- `q5` is the accept state (brute-force alert). Like DFA 1, it stays in `q5` on further failures.
- Time window enforcement (60 seconds) is handled by the detector wrapper — the DFA itself only counts; the wrapper discards events older than 60 seconds.

---

## DFA 3 — Off-Hours Access

**What it detects:** Any request made between 00:00–08:59 or 18:00–23:59 (outside business hours 09:00–17:59).

**States:**

| State | Meaning |
|-------|---------|
| `q0` | Start — no digit read yet |
| `q_h0` | First digit was '0' — awaiting second digit to decide (00–08 off-hours, 09 business) |
| `q_h1` | First digit was '1' — awaiting second digit to decide (10–17 business, 18–19 off-hours) |
| `q_off` | Hour is outside business hours — **ALERT** (accept state) |
| `q_biz` | Hour is within business hours — no alert (reject state) |

**Input alphabet:** Digits `{0–9}` from the 2-digit hour field of the timestamp.

**DFA (operates on the 2-digit hour HH extracted from timestamp):**

This DFA reads the 2-character hour field `HH` extracted by the regex from the timestamp.

| Current State | Condition | Next State |
|--------------|-----------|------------|
| → q0 | digit 0 | q_h0 |
| → q0 | digit 1 | q_h1 |
| → q0 | digit 2–9 | q_off |
| q_h0 | digit 0–8 | q_off (00–08 → off-hours) |
| q_h0 | digit 9 | q_biz (09 → business hours) |
| q_h1 | digit 0–7 | q_biz (10–17 → business hours) |
| q_h1 | digit 8–9 | q_off (18–19 → off-hours) |
| * q_off | — | accept (ALERT) |
| q_biz | — | reject (normal) |

**State Diagram:**
```
            '0'              '0'-'8'
  → q0 ──────────→ q_h0 ──────────→ *q_off (ALERT)
      |               |
      |               | '9'
      |               ↓
      |             q_biz (normal, 09:xx)
      |
      | '1'              '0'-'7'
      └──────────→ q_h1 ──────────→ q_biz  (normal, 10-17)
                      |
                      | '8'-'9'
                      ↓
                   *q_off (ALERT, 18-19:xx)

  '2'-'9' from q0 → *q_off directly (20–23 always off-hours)
```

**Explanation:**
- This is a **stateless per-line** detector — each log line is checked independently.
- The DFA processes the 2-digit hour extracted by the regex from the timestamp.
- Business hours are 09:00 to 17:59. Hours 00–08 and 18–23 trigger the alert.

---

## DFA 4 — Suspicious User-Agent

**What it detects:** Known attack/scanner tool names or empty/malformed user-agent strings in the log line.

**States:**

| State | Meaning |
|-------|---------|
| `q0` | Start — reading user-agent string |
| `q_scan` | Matched a known suspicious tool name — **ALERT** (accept) |
| `q_empty` | User-agent is empty or `-` — **ALERT** (accept) |
| `q_norm` | Normal user-agent — no alert (reject) |

**Input alphabet:** Substrings of the user-agent field: `{KNOWN_TOOL, EMPTY, NORMAL_UA}`

| State | Input: `KNOWN_TOOL` | Input: `EMPTY/DASH` | Input: `NORMAL_UA` |
|-------|--------------------|--------------------|-------------------|
| → q0 | q_scan | q_empty | q_norm |
| * q_scan | q_scan | q_scan | q_scan |
| * q_empty | q_scan | q_empty | q_empty |
| q_norm | q_scan | q_empty | q_norm |

**Known tool keywords:** `sqlmap`, `nikto`, `nmap`, `masscan`, `zgrab`, `scrapy`, `python-requests`, `libwww-perl`, `go-http-client`, `curl/`, `wget/`

**State Diagram:**
```
                  KNOWN_TOOL
              ┌──────────────────────────────┐
              ↓                              │
  → q0 ──────→ *q_scan (ALERT — known tool) ──(self, any)
      │
      │ EMPTY/DASH
      └──────→ *q_empty (ALERT — missing UA)
      │
      │ NORMAL_UA
      └──────→ q_norm  (no alert)
```

**Explanation:**
- This DFA is also **stateless per line** — the user-agent of each request is checked independently.
- Once in `q_scan`, the state stays there — a tool keyword anywhere in the UA string is enough to flag it.
- Once in `q_empty`, the state also stays — an empty or dash-only UA is always suspicious regardless of other content.
- `q_norm` is the only non-alert state — reached only when no suspicious keyword or empty string is detected.
- In practice, the keyword check uses the regex above; the empty/dash check is a separate Python condition.

---

## Summary of All Four DFAs

| DFA | Input Alphabet | States | Accept State | Stateful? |
|-----|---------------|--------|-------------|-----------|
| 1 — Dir Scanning | {404, OTHER} | q0–q3 | q3 | Yes (per IP) |
| 2 — Login Flood | {FAIL, OTHER} | q0–q5 | q5 | Yes (per IP + time window) |
| 3 — Off-Hours | {hour digits} | q0, q_h0, q_h1, q_off, q_biz | q_off | No (per line) |
| 4 — Susp UA | {KNOWN_TOOL, EMPTY, NORMAL} | q0, q_scan, q_empty, q_norm | q_scan, q_empty | No (per line) |

---

## How DFAs Connect to the Implementation

In `src/scanner.py`, each detector models the DFA logic:

```python
# DFA 1 — Directory Scanning (conceptual Python mapping)
# State is tracked as an integer per IP

state = {ip: 0}   # q0 for every IP

def transition(ip, status_code):
    s = state[ip]
    if status_code == 404:
        state[ip] = min(s + 1, 3)   # q0→q1→q2→q3, stays at q3
    else:
        state[ip] = 0                # reset to q0 on any other status
    return state[ip] == 3            # True = accept state reached
```

The regex extracts the relevant field (status code, hour, user-agent), and the DFA transition function decides which state to move to. When the DFA reaches an accept state, an `Anomaly` object is raised and added to the report.

---

## Formal Definitions — All Four DFAs

### DFA 1 — Directory Scanning

**M = (Q, Σ, δ, q0, F)** where:
- **Q** = {q0, q1, q2, q3}
- **Σ** = {404, OTHER}
- **δ** = transition function defined in the table above
- **q0** = q0 (start state)
- **F** = {q3}

**L(M)** = { sequences of status codes | sequence contains 3 or more consecutive 404s }

---

### DFA 2 — Failed Login Flood

**M = (Q, Σ, δ, q0, F)** where:
- **Q** = {q0, q1, q2, q3, q4, q5}
- **Σ** = {FAIL, OTHER}
- **δ** = transition function defined in the table above
- **q0** = q0 (start state)
- **F** = {q5}

**L(M)** = { sequences of login responses | sequence contains 5 or more consecutive FAIL responses }

---

### DFA 3 — Off-Hours Access

**M = (Q, Σ, δ, q0, F)** where:
- **Q** = {q0, q_h0, q_h1, q_off, q_biz}
- **Σ** = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
- **δ** = transition function defined in the table above
- **q0** = q0 (start state)
- **F** = {q_off}

**L(M)** = { 2-digit strings HH over {0–9} | integer(HH) < 9 or integer(HH) ≥ 18 }

---

### DFA 4 — Suspicious User-Agent

**M = (Q, Σ, δ, q0, F)** where:
- **Q** = {q0, q_scan, q_empty, q_norm}
- **Σ** = {KNOWN_TOOL, EMPTY, NORMAL_UA}
- **δ** = transition function defined in the table above
- **q0** = q0 (start state)
- **F** = {q_scan, q_empty}

**L(M)** = { user-agent strings | string contains a known tool keyword OR is empty/dash-only }

---

*Prepared by: Member 2 — Regex Patterns & DFA Design*
*Course: BIS503 — Theory of Computation*
