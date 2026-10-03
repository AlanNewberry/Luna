import json
import time
from dataclasses import asdict
from typing import Optional

from luna import __version__
from luna.core.findings import Finding


def generate_json_report(
    findings: list,
    url: str,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    modules_used: Optional[list] = None,
) -> str:
    now = time.time()
    report = {
        "scanner": "Luna",
        "version": __version__,
        "target": url,
        "scan_start": start_time or now,
        "scan_end": end_time or now,
        "duration_seconds": round((end_time or now) - (start_time or now), 3),
        "modules_used": modules_used or [],
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(report, indent=2)
