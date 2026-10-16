# Server Log Anomaly Finder

**Course:** Theory of Computation (BIS503) | **Project 8** | **Team size:** 4 | **Duration:** 2 weeks

A simplified, SIEM-style tool that scans Apache/Nginx-style server logs and flags suspicious
activity using **regular expressions** and **deterministic finite automata (DFA)**.

## Objective
Show how the theory of regular languages and finite automata is used in real cybersecurity
tooling (SIEMs such as Splunk), by building a mini log-analysis engine that detects four
anomaly types and produces a structured, colour-coded report.

## Scope
| # | Anomaly type | What we look for | Typical severity |
|---|---|---|---|
| 1 | Directory Scanning | Repeated 404 responses from one IP in a short time window | HIGH |
| 2 | Failed Login Flood | Many failed login attempts (401/403 on login paths) from one IP in a short window | HIGH |
| 3 | Off-Hours Access | Requests outside business hours (09:00-18:00) | LOW / MEDIUM |
| 4 | Suspicious User-Agent | Known scanner/attack tools or empty/abnormal user-agent strings | MEDIUM / HIGH |

*Exact thresholds (e.g. "3 consecutive 404s", "5 failures in 60 s") are defined in
[`docs/regex_patterns.md`](docs/regex_patterns.md) and used by the scanner.*

**Out of scope:** real-time streaming, a web dashboard, or ingesting live production logs.

## Tools
Python 3 (`re` module), Matplotlib, sample Apache/Nginx logs, VS Code, Git/GitHub.

## Repository structure
```
server-log-anomaly-finder/
├── README.md
├── requirements.txt
├── logs/
│   └── sample_logs.txt          # ~200 lines, normal + injected anomalies  
├── docs/
│   ├── log_format.md            # log format + SIEM/Splunk notes           
│   ├── regex_patterns.md        # 4 regex patterns + sample matches  
│   ├── dfa_design.md            # DFA diagrams + transition tables        
│   ├── architecture.md          # workflow/architecture diagram          
│   ├── architecture.png


├── tests/
│   ├── expected_anomalies.md    # ground truth: line numbers + types       
│   ├── test_report.py           # unit tests for reporting
│   └── demo_report.py           # demo report without the scanner
├── src/
│   ├── models.py                # shared Anomaly data contract
│   ├── scanner.py               # parser + regex/DFA detectors (skeleton, to implement)
│   ├── report.py                # JSON + coloured console report
│   ├── visualize.py             # Matplotlib chart
│   └── main.py                  # command-line entry point
└── reports/                     # generated output (JSON, PNG)
```

## How it works
`log file -> parser -> 4 detectors (regex / DFA) -> Anomaly list -> report (console + JSON) + chart`
See [`docs/architecture.md`](docs/architecture.md) for the full diagram.

## Setup
```bash
git clone <repo-url>
cd server-log-anomaly-finder
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python src/main.py logs/sample_logs.txt
```
Options:
```bash
python src/main.py logs/sample_logs.txt --json reports/report.json --chart reports/anomaly_chart.png
python src/main.py logs/sample_logs.txt --no-color
```
Try the reporting layer alone (no scanner needed):
```bash
python tests/demo_report.py
```

## Test
```bash
python -m unittest discover -s tests
```

## Sample output
```
[HIGH] ANOMALY DETECTED: Directory Scanning  (#1)
  IP:       192.168.1.5
  Time:     03:21:00 - 03:21:02 (3 seconds)
  Lines:    41, 42, 43
  Details:  3 consecutive 404s on /admin paths - possible reconnaissance
  Severity: HIGH
```
Full format: [`docs/report_format.md`](docs/report_format.md).

pass (O(n), no backtracking), so the same
approach parallelises across files/servers. See the final slides for the mini-SIEM vs Splunk comparison.
