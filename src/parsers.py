import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

# Example Linux auth log line formats (Ubuntu/Debian)
# Dec 19 10:03:12 myhost sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 53522 ssh2
# Dec 19 10:05:44 myhost sshd[1234]: Accepted password for rahul from 10.0.0.5 port 53589 ssh2

SSH_FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user )?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted \S+ for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

@dataclass(frozen=True)
class LogEvent:
    ts: datetime
    event_type: str   # "FAILED_LOGIN" / "SUCCESS_LOGIN"
    user: str
    ip: str
    raw: str

def _parse_ts(mon: str, day: str, t: str, year: int) -> datetime:
    return datetime(year, MONTHS[mon], int(day),
                    int(t[0:2]), int(t[3:5]), int(t[6:8]))

def parse_linux_auth_log(lines: Iterator[str], year: int) -> Iterator[LogEvent]:
    """
    Yields LogEvent objects from /var/log/auth.log style logs.
    """
    for raw in lines:
        raw = raw.rstrip("\n")
        m = SSH_FAILED_RE.match(raw)
        if m:
            ts = _parse_ts(m["mon"], m["day"], m["time"], year)
            yield LogEvent(ts=ts, event_type="FAILED_LOGIN", user=m["user"], ip=m["ip"], raw=raw)
            continue

        m = SSH_ACCEPTED_RE.match(raw)
        if m:
            ts = _parse_ts(m["mon"], m["day"], m["time"], year)
            yield LogEvent(ts=ts, event_type="SUCCESS_LOGIN", user=m["user"], ip=m["ip"], raw=raw)
            continue
