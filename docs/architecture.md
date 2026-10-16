# Architecture & Workflow

![Architecture diagram](architecture.png)

## Pipeline

```mermaid
flowchart LR
    A[logs/sample_logs.txt] --> B[Log Reader<br/>line by line + line numbers]
    B --> C[Parser<br/>regex extracts IP, time, method,<br/>path, status, user-agent]
    C --> D1[Detector 1<br/>Directory scanning<br/>repeated 404s]
    C --> D2[Detector 2<br/>Failed-login flood]
    C --> D3[Detector 3<br/>Off-hours access]
    C --> D4[Detector 4<br/>Suspicious user-agent]
    D1 --> E[Anomaly list<br/>models.Anomaly]
    D2 --> E
    D3 --> E
    D4 --> E
    E --> F[Report generator<br/>console + JSON]
    E --> G[Visualizer<br/>Matplotlib chart]
    F --> H[reports/report.json]
    G --> I[reports/anomaly_chart.png]
```

## Stages
| Stage | Module | Input | Output |
|---|---|---|---|
| 1. Read | `scanner.py` | log file path | (line_no, raw line) stream |
| 2. Parse | `scanner.py` | raw line | record: ip, timestamp, method, path, status, size, user-agent |
| 3. Detect | `scanner.py` | records | `Anomaly` objects (regex/DFA per type, with sliding window per IP) |
| 4. Report | `report.py` | `Anomaly` list | coloured console report + JSON |
| 5. Visualise | `visualize.py` | report dict | PNG chart |

## Design decisions
- **Single shared contract** (`models.Anomaly`): detectors and reporting are developed independently.
- **One pass over the file**; each line is parsed once, then offered to all four detectors.
- **Stateful detectors** (directory scanning, login flood) keep a per-IP window of recent events; stateless ones
  (off-hours, user-agent) decide from a single line.
- **Malformed lines** are skipped and counted, never crash the scan.
- **Line numbers are 1-based** and refer to the original file, so results can be compared directly with
  `tests/expected_anomalies.md`.

## Interface the scanner must provide
```python
# src/scanner.py
def scan_file(path: str) -> list[models.Anomaly]: ...
```
