from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from .parsers import LogEvent

@dataclass
class Alert:
    severity: str   # LOW / MEDIUM / HIGH
    rule: str
    ts: datetime
    ip: str
    user: str
    details: str

def detect_bruteforce(events: List[LogEvent], window_minutes: int = 10, threshold: int = 8) -> List[Alert]:
    """
    Many FAILED logins from same IP in a time window.
    """
    alerts: List[Alert] = []
    events_sorted = sorted(events, key=lambda e: e.ts)

    # Sliding window per IP
    failed_by_ip: Dict[str, List[datetime]] = {}

    window = timedelta(minutes=window_minutes)

    for e in events_sorted:
        if e.event_type != "FAILED_LOGIN":
            continue
        ip = e.ip
        failed_by_ip.setdefault(ip, []).append(e.ts)

        # prune old timestamps
        cutoff = e.ts - window
        failed_by_ip[ip] = [t for t in failed_by_ip[ip] if t >= cutoff]

        if len(failed_by_ip[ip]) == threshold:
            alerts.append(Alert(
                severity="HIGH",
                rule="BRUTE_FORCE_IP",
                ts=e.ts,
                ip=ip,
                user="*",
                details=f"{threshold}+ failed logins from {ip} within {window_minutes} minutes"
            ))
    return alerts

def detect_password_spray(events: List[LogEvent], window_minutes: int = 15, user_threshold: int = 6) -> List[Alert]:
    """
    One IP failing across many distinct users (spray).
    """
    alerts: List[Alert] = []
    events_sorted = sorted(events, key=lambda e: e.ts)
    window = timedelta(minutes=window_minutes)

    # per IP store list of (ts, user) failed attempts
    failed: Dict[str, List[Tuple[datetime, str]]] = {}

    for e in events_sorted:
        if e.event_type != "FAILED_LOGIN":
            continue
        ip = e.ip
        failed.setdefault(ip, []).append((e.ts, e.user))

        cutoff = e.ts - window
        failed[ip] = [(t, u) for (t, u) in failed[ip] if t >= cutoff]

        distinct_users = {u for (_, u) in failed[ip]}
        if len(distinct_users) == user_threshold:
            alerts.append(Alert(
                severity="HIGH",
                rule="PASSWORD_SPRAY",
                ts=e.ts,
                ip=ip,
                user="*",
                details=f"Failed logins across {user_threshold}+ distinct users from {ip} within {window_minutes} minutes"
            ))
    return alerts

def detect_success_after_failures(events: List[LogEvent], lookback_minutes: int = 30, fail_threshold: int = 3) -> List[Alert]:
    """
    Success for a user+ip after multiple failures recently (possible compromise).
    """
    alerts: List[Alert] = []
    events_sorted = sorted(events, key=lambda e: e.ts)
    lookback = timedelta(minutes=lookback_minutes)

    # Track recent failures by (ip,user)
    recent_failures: Dict[Tuple[str, str], List[datetime]] = {}

    for e in events_sorted:
        key = (e.ip, e.user)

        if e.event_type == "FAILED_LOGIN":
            recent_failures.setdefault(key, []).append(e.ts)
            cutoff = e.ts - lookback
            recent_failures[key] = [t for t in recent_failures[key] if t >= cutoff]

        elif e.event_type == "SUCCESS_LOGIN":
            failures = recent_failures.get(key, [])
            cutoff = e.ts - lookback
            failures = [t for t in failures if t >= cutoff]
            if len(failures) >= fail_threshold:
                alerts.append(Alert(
                    severity="MEDIUM",
                    rule="SUCCESS_AFTER_FAILURES",
                    ts=e.ts,
                    ip=e.ip,
                    user=e.user,
                    details=f"Successful login after {len(failures)} failures within {lookback_minutes} minutes"
                ))
            # reset after success
            recent_failures[key] = []
    return alerts

def detect_offhours_success(events: List[LogEvent], start_hour: int = 8, end_hour: int = 18) -> List[Alert]:
    """
    Successful logins outside normal hours.
    """
    alerts: List[Alert] = []
    for e in events:
        if e.event_type != "SUCCESS_LOGIN":
            continue
        hr = e.ts.hour
        if hr < start_hour or hr >= end_hour:
            alerts.append(Alert(
                severity="LOW",
                rule="OFF_HOURS_LOGIN",
                ts=e.ts,
                ip=e.ip,
                user=e.user,
                details=f"Successful login at {e.ts.strftime('%H:%M:%S')} outside {start_hour:02d}:00–{end_hour:02d}:00"
            ))
    return alerts
