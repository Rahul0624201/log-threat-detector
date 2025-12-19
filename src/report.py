import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import List
from .rules import Alert

def write_json(alerts: List[Alert], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(a) | {"ts": a.ts.isoformat()} for a in alerts]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

def write_csv(alerts: List[Alert], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "severity", "rule", "ip", "user", "details"])
        w.writeheader()
        for a in alerts:
            w.writerow({
                "ts": a.ts.isoformat(),
                "severity": a.severity,
                "rule": a.rule,
                "ip": a.ip,
                "user": a.user,
                "details": a.details
            })
