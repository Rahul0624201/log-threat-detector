import argparse
from pathlib import Path
from typing import List

from .parsers import parse_linux_auth_log, LogEvent
from .rules import (
    detect_bruteforce,
    detect_password_spray,
    detect_success_after_failures,
    detect_offhours_success,
)
from .report import write_csv, write_json

def load_events(path: Path, year: int) -> List[LogEvent]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return list(parse_linux_auth_log(f, year=year))

def main() -> int:
    ap = argparse.ArgumentParser(description="Log Analyzer + Threat Detector (defensive use)")
    ap.add_argument("--log", required=True, help="Path to auth.log file")
    ap.add_argument("--year", type=int, required=True, help="Year for timestamps (auth.log usually omits year)")
    ap.add_argument("--outdir", default="output", help="Output directory")
    ap.add_argument("--bf-window", type=int, default=10)
    ap.add_argument("--bf-threshold", type=int, default=8)
    ap.add_argument("--spray-window", type=int, default=15)
    ap.add_argument("--spray-users", type=int, default=6)
    ap.add_argument("--saf-lookback", type=int, default=30)
    ap.add_argument("--saf-threshold", type=int, default=3)
    ap.add_argument("--work-start", type=int, default=8)
    ap.add_argument("--work-end", type=int, default=18)

    args = ap.parse_args()
    log_path = Path(args.log)
    outdir = Path(args.outdir)

    events = load_events(log_path, year=args.year)

    alerts = []
    alerts += detect_bruteforce(events, window_minutes=args.bf_window, threshold=args.bf_threshold)
    alerts += detect_password_spray(events, window_minutes=args.spray_window, user_threshold=args.spray_users)
    alerts += detect_success_after_failures(events, lookback_minutes=args.saf_lookback, fail_threshold=args.saf_threshold)
    alerts += detect_offhours_success(events, start_hour=args.work_start, end_hour=args.work_end)

    # Sort by time, then severity
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts = sorted(alerts, key=lambda a: (a.ts, severity_rank.get(a.severity, 9)))

    # Print summary
    print(f"Parsed events: {len(events)}")
    print(f"Alerts: {len(alerts)}")
    by_rule = {}
    for a in alerts:
        by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
    for rule, count in sorted(by_rule.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {rule}: {count}")

    # Save reports
    write_json(alerts, outdir / "alerts.json")
    write_csv(alerts, outdir / "alerts.csv")
    print(f"Saved: {outdir/'alerts.json'}")
    print(f"Saved: {outdir/'alerts.csv'}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
