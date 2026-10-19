                evidence=[item.raw for item in window],
            ))
            # Reset after an alert to avoid emitting duplicates for the same burst.
            states[rec.ip] = []
    return anomalies


def detect_failed_login_flood(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Detect five failed login attempts from an IP within 60 seconds."""
    anomalies: List[Anomaly] = []
    states = defaultdict(lambda: [])

    for rec in records:
        window = states[rec.ip]
        is_failed_login = rec.status in FAILED_LOGIN_CODES and _is_login_path(rec.path)
        if not is_failed_login:
            states[rec.ip] = []
            continue

        window = _within_window(window, rec, LOGIN_WINDOW_SEC)
        window.append(rec)
        states[rec.ip] = window
        if len(window) >= LOGIN_MIN_FAILS:
            anomalies.append(Anomaly(
                type=FAILED_LOGIN_FLOOD,
                severity="HIGH",
                ip=rec.ip,
                start_time=window[0].time,
                end_time=rec.time,
                line_numbers=[item.line_no for item in window],
                description=(
                    f"{rec.ip} made {len(window)} failed login attempts "
                    f"within {LOGIN_WINDOW_SEC}s — possible brute-force attack."
                ),
                evidence=[item.raw for item in window],
            ))
            states[rec.ip] = []
    return anomalies


def detect_off_hours(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Flag requests before 09:00 or at/after 18:00."""
    anomalies: List[Anomaly] = []
    for rec in records:
        try:
            hour = int(rec.time.split(":", 1)[0])
        except (ValueError, AttributeError):
            continue
        if not (0 <= hour <= 23):
            continue
        if hour < BUSINESS_START or hour >= BUSINESS_END:
            severity = "MEDIUM" if (6 <= hour < 9 or 18 <= hour < 20) else "LOW"
            anomalies.append(Anomaly(
                type=OFF_HOURS_ACCESS,
                severity=severity,
                ip=rec.ip,
                start_time=rec.time,
                end_time=rec.time,
                line_numbers=[rec.line_no],
                description=(
                    f"{rec.ip} accessed {rec.path} at {rec.time} "
                    f"(hour={hour:02d}) — outside business hours "
                    f"({BUSINESS_START:02d}:00–{BUSINESS_END:02d}:00)."
                ),
                evidence=[rec.raw],
            ))
    return anomalies


def detect_suspicious_user_agent(records: Iterable[LogRecord]) -> List[Anomaly]:
    """Flag known scanning tools (HIGH) and empty/missing user agents (MEDIUM)."""
    anomalies: List[Anomaly] = []
    for rec in records:
        ua = (rec.user_agent or "").strip()
        if ua in _EMPTY_UA:
            anomalies.append(Anomaly(
                type=SUSPICIOUS_USER_AGENT,
                severity="MEDIUM",
                ip=rec.ip,
                start_time=rec.time,
                end_time=rec.time,
                line_numbers=[rec.line_no],
                description=(
                    f"{rec.ip} sent a request with empty/missing user-agent "
                    f"at {rec.time} — identity concealment suspected."
                ),
                evidence=[rec.raw],
            ))
            continue

        match = _UA_RE.search(ua)
        if match:
            anomalies.append(Anomaly(
                type=SUSPICIOUS_USER_AGENT,
                severity="HIGH",
                ip=rec.ip,
                start_time=rec.time,
                end_time=rec.time,
                line_numbers=[rec.line_no],
                description=(
                    f"{rec.ip} used known attack tool '{match.group()}' "
                    f"as user-agent at {rec.time}."
                ),
                evidence=[rec.raw],
            ))
    return anomalies


def scan_file(path: str) -> List[Anomaly]:
    """Parse a log file, run all detectors, and sort anomalies by source line."""
    records: List[LogRecord] = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            record = parse_line(line_no, line)
            if record is not None:
                records.append(record)

    # Chronological processing is needed for date-aware detection windows.
    records.sort(key=lambda record: (_timestamp(record) or datetime.min, record.line_no))
    anomalies: List[Anomaly] = []
    for detector in (
        detect_directory_scanning,
        detect_failed_login_flood,
        detect_off_hours,
        detect_suspicious_user_agent,
    ):
        anomalies.extend(detector(records))

    anomalies.sort(key=lambda anomaly: anomaly.line_numbers[0] if anomaly.line_numbers else 0)
    return anomalies
