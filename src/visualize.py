"""Matplotlib visualisation of the anomaly distribution."""
import os

import matplotlib
matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt

from models import ANOMALY_TYPES, SEVERITIES

SEV_COLORS = {"LOW": "#4C8BF5", "MEDIUM": "#F5B942", "HIGH": "#E5484D"}


def make_chart(report: dict, out_path: str = "reports/anomaly_chart.png") -> str:
    """Save a two-panel chart: anomalies by type (stacked by severity) + top IPs."""
    items = report["anomalies"]
    counts = {t: {s: 0 for s in SEVERITIES} for t in ANOMALY_TYPES}
    for a in items:
        counts[a["type"]][a["severity"]] += 1

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5),
                                   gridspec_kw={"width_ratios": [3, 2]})
    bottoms = [0] * len(ANOMALY_TYPES)
    for sev in SEVERITIES:
        vals = [counts[t][sev] for t in ANOMALY_TYPES]
        ax1.bar(ANOMALY_TYPES, vals, bottom=bottoms, label=sev, color=SEV_COLORS[sev])
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    for i, total in enumerate(bottoms):
        ax1.text(i, total + 0.05, str(total), ha="center", fontweight="bold")
    ax1.set_title("Anomalies by type and severity")
    ax1.set_ylabel("Number of anomalies")
    ax1.legend(title="Severity")
    ax1.tick_params(axis="x", labelrotation=15)
    ax1.set_ylim(0, max(bottoms + [1]) + 1)

    top = report["summary"]["top_ips"]
    ips = [r["ip"] for r in top][::-1]
    vals = [r["anomalies"] for r in top][::-1]
    ax2.barh(ips, vals, color="#5B6CFF")
    ax2.set_title("Top offending IPs")
    ax2.set_xlabel("Anomalies")
    ax2.set_xlim(0, max(vals + [1]) + 1)

    s = report["summary"]
    fig.suptitle(f"Server Log Anomaly Finder - {s['total_anomalies']} anomalies "
                 f"in {s['total_lines_scanned']} lines", fontweight="bold")
    fig.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
