import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Tuple

from securepy_ai.models import ScanReport, VulnerabilityFinding


def finding_fingerprint(finding: VulnerabilityFinding) -> str:
    """
    Creates a stable fingerprint for a finding.

    The fingerprint is based on:
        - Rule ID
        - File path
        - Vulnerable code snippet

    Line number is intentionally avoided because line numbers
    can shift during normal development.
    """
    payload = "|".join(
        [
            finding.rule_id,
            finding.file_path,
            finding.code_snippet.strip(),
        ]
    )

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_baseline(path: str) -> Set[str]:
    """
    Loads baseline fingerprints from a JSON file.
    """
    baseline_path = Path(path)

    if not baseline_path.exists():
        return set()

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        return set(data.get("findings", []))
    except json.JSONDecodeError:
        return set()


def save_baseline(report: ScanReport, path: str) -> Path:
    """
    Saves current findings as a baseline JSON file.
    """
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    fingerprints = sorted(
        {
            finding_fingerprint(finding)
            for finding in report.findings
        }
    )

    payload = {
        "tool": "SecurePy AI",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings": fingerprints,
    }

    baseline_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    return baseline_path


def filter_baseline(
    report: ScanReport,
    baseline_fingerprints: Set[str],
) -> Tuple[ScanReport, int]:
    """
    Removes findings that already exist in the baseline.

    Returns:
        - Updated report containing only new findings
        - Number of ignored baseline findings
    """
    new_findings = []
    ignored_count = 0

    for finding in report.findings:
        fingerprint = finding_fingerprint(finding)

        if fingerprint in baseline_fingerprints:
            ignored_count += 1
        else:
            new_findings.append(finding)

    report.findings = new_findings

    return report, ignored_count
