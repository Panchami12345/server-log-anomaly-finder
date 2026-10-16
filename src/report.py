"""Anomaly report generation: structured JSON + coloured console output."""
import json
import os
import sys
from collections import Counter
from datetime import datetime
from typing import List

from models import Anomaly, ANOMALY_TYPES, SEVERITIES

RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
CYAN = "\033[96m"
DIM = "\033[90m"


def _seconds(t: str) -> int:
    h, m, s = (int(x) for x in t.split(":"))
    return h * 3600 + m * 60 + s


def duration_seconds(a: Anomaly) -> int:
    return max(0, _seconds(a.end_time) - _seconds(a.start_time)) + 1  # inclusive, matches problem-statement sample


def sort_anomalies(anomalies: List[Anomaly]) -> List[Anomaly]:
    """Highest severity first, then by earliest line number."""
    return sorted(
        anomalies,
        key=lambda a: (-SEVERITIES.index(a.severity), a.line_numbers[0] if a.line_numbers else 0),
    )


def build_report(anomalies: List[Anomaly], source_file: str, total_lines: int) -> dict:
    """Build the JSON-serialisable report dictionary (see docs/report_format.md)."""
    ordered = sort_anomalies(anomalies)
    by_type = Counter({t: 0 for t in ANOMALY_TYPES})
    by_sev = Counter({s: 0 for s in SEVERITIES})
    by_ip = Counter()
    flagged_lines = set()
    for a in ordered:
        by_type[a.type] += 1
        by_sev[a.severity] += 1
        by_ip[a.ip] += 1
        flagged_lines.update(a.line_numbers)

    items = []
    for i, a in enumerate(ordered, 1):
        d = a.to_dict()
        d = {"id": i, **d, "duration_seconds": duration_seconds(a)}
        items.append(d)

    return {
        "report_generated": datetime.now().isoformat(timespec="seconds"),
        "source_file": source_file,
        "summary": {
            "total_lines_scanned": total_lines,
            "total_anomalies": len(ordered),
            "flagged_lines": len(flagged_lines),
            "by_type": dict(by_type),
            "by_severity": dict(by_sev),
            "top_ips": [{"ip": ip, "anomalies": n} for ip, n in by_ip.most_common(5)],
        },
        "anomalies": items,
    }


def write_json(report: dict, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def _lines_text(lines: List[int]) -> str:
    if not lines:
        return "-"
    if len(lines) > 6:
        return f"{lines[0]}-{lines[-1]} ({len(lines)} lines)"
    return ", ".join(str(n) for n in lines)


def render_console(report: dict, color: bool = True) -> str:
    """Return the console report as a string (colour optional)."""
    def c(text, code):
        return f"{code}{text}{RESET}" if color else text

    s = report["summary"]
    out = []
    bar = "=" * 64
    out.append(c(bar, CYAN))
    out.append(c("  SERVER LOG ANOMALY FINDER - REPORT", BOLD))
    out.append(c(bar, CYAN))
    out.append(f"  File scanned : {report['source_file']}")
    out.append(f"  Lines scanned: {s['total_lines_scanned']}")
    out.append(f"  Anomalies    : {s['total_anomalies']}  "
               f"({s['flagged_lines']} suspicious lines)")
    sev = s["by_severity"]
    out.append("  Severity     : " + "  ".join(
        c(f"{k}={sev[k]}", COLORS[k]) for k in reversed(SEVERITIES)))
    out.append("")

    for a in report["anomalies"]:
        tag = c(f"[{a['severity']}]", COLORS[a["severity"]] + BOLD) if color else f"[{a['severity']}]"
        out.append(f"{tag} ANOMALY DETECTED: {c(a['type'], BOLD)}  (#{a['id']})")
        out.append(f"  IP:       {a['ip']}")
        out.append(f"  Time:     {a['start_time']} - {a['end_time']} ({a['duration_seconds']} seconds)")
        out.append(f"  Lines:    {_lines_text(a['line_numbers'])}")
        out.append(f"  Details:  {a['description']}")
        out.append(f"  Severity: {c(a['severity'], COLORS[a['severity']])}")
        out.append(c("  " + "-" * 60, DIM))

    out.append("")
    out.append(c("  Anomalies by type:", BOLD))
    for t, n in s["by_type"].items():
        out.append(f"    {t:<24} {'#' * n} {n}")
    if s["top_ips"]:
        out.append(c("  Top offending IPs:", BOLD))
        for row in s["top_ips"]:
            out.append(f"    {row['ip']:<18} {row['anomalies']} anomalies")
    out.append(c(bar, CYAN))
    return "\n".join(out)


def print_console(report: dict, color: bool = None) -> None:
    """Print to stdout. Colour auto-disables when piped or when NO_COLOR is set."""
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if sys.platform == "win32":
        os.system("")  # enables ANSI escapes in Windows terminals
    print(render_console(report, color))
