# Report Format & Visualization Requirements

## 1. Console report (coloured)
Printed by `python src/main.py <logfile>`. Colours: **HIGH = red, MEDIUM = yellow, LOW = blue**.
Colour turns off automatically when output is piped, or with `--no-color` / `NO_COLOR`.

```
================================================================
  SERVER LOG ANOMALY FINDER - REPORT
================================================================
  File scanned : logs/sample_logs.txt
  Lines scanned: 200
  Anomalies    : 5  (14 suspicious lines)
  Severity     : HIGH=2  MEDIUM=2  LOW=1

[HIGH] ANOMALY DETECTED: Directory Scanning  (#1)
  IP:       192.168.1.5
  Time:     03:21:00 - 03:21:02 (3 seconds)
  Lines:    41, 42, 43
  Details:  3 consecutive 404s on /admin paths - possible reconnaissance
  Severity: HIGH
```
Each anomaly shows: type, IP, time window + duration, **line numbers**, description, severity.
Anomalies are sorted HIGH -> LOW, then by line number. A summary of counts by type and top IPs ends the report.

## 2. JSON report (`reports/report.json`)
```json
{
  "report_generated": "2026-06-20T10:00:00",
  "source_file": "logs/sample_logs.txt",
  "summary": {
    "total_lines_scanned": 200,
    "total_anomalies": 5,
    "flagged_lines": 14,
    "by_type": {"Directory Scanning": 1, "Failed Login Flood": 1, "Off-Hours Access": 2, "Suspicious User-Agent": 1},
    "by_severity": {"LOW": 1, "MEDIUM": 2, "HIGH": 2},
    "top_ips": [{"ip": "192.168.1.5", "anomalies": 1}]
  },
  "anomalies": [
    {
      "id": 1,
      "type": "Directory Scanning",
      "severity": "HIGH",
      "ip": "192.168.1.5",
      "start_time": "03:21:00",
      "end_time": "03:21:02",
      "duration_seconds": 3,
      "line_numbers": [41, 42, 43],
      "description": "3 consecutive 404s on /admin paths - possible reconnaissance",
      "evidence": []
    }
  ]
}
```

## 3. Severity guide (proposed - confirm thresholds with Member 2)
| Anomaly | LOW | MEDIUM | HIGH |
|---|---|---|---|
| Directory Scanning | - | 3-4 consecutive 404s | 5+ 404s, or paths such as /admin, /.env, /config |
| Failed Login Flood | - | 3-4 failures in the window | 5+ failures in the window |
| Off-Hours Access | public page | login/private page | /admin or other sensitive path |
| Suspicious User-Agent | empty/odd UA | unknown automated tool (curl, python-requests) | known attack tool (sqlmap, nikto, nmap) |

## 4. Visualization requirements (`reports/anomaly_chart.png`)
- **Panel 1:** bar chart of anomaly counts by type, stacked by severity (all four types shown, even if 0).
- **Panel 2:** horizontal bar chart of top offending IPs.
- Title includes total anomalies and lines scanned; axes labelled; legend for severity; readable at 150 dpi.
- Generated automatically by `main.py`; produced with Matplotlib only.
