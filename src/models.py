"""Shared data contract between the scanner (detection) and the reporting layer.

Every detector must return a list of `Anomaly` objects. The report generator
and the chart code only depend on this module, so the team can work in parallel.
"""
from dataclasses import dataclass, field, asdict
from typing import List

# The four anomaly categories required by the project.
DIRECTORY_SCANNING = "Directory Scanning"
FAILED_LOGIN_FLOOD = "Failed Login Flood"
OFF_HOURS_ACCESS = "Off-Hours Access"
SUSPICIOUS_USER_AGENT = "Suspicious User-Agent"

ANOMALY_TYPES = [
    DIRECTORY_SCANNING,
    FAILED_LOGIN_FLOOD,
    OFF_HOURS_ACCESS,
    SUSPICIOUS_USER_AGENT,
]

# Severity levels, lowest to highest.
SEVERITIES = ["LOW", "MEDIUM", "HIGH"]


@dataclass
class Anomaly:
    type: str                      # one of ANOMALY_TYPES
    severity: str                  # one of SEVERITIES
    ip: str                        # source IP address
    start_time: str                # "HH:MM:SS" of first matching entry
    end_time: str                  # "HH:MM:SS" of last matching entry
    line_numbers: List[int]        # 1-based line numbers in the log file
    description: str               # human-readable explanation
    evidence: List[str] = field(default_factory=list)  # raw log lines (optional)

    def to_dict(self) -> dict:
        return asdict(self)
