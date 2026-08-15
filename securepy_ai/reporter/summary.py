from typing import Any, Dict

from securepy_ai.models import ScanReport


def build_summary(report: ScanReport) -> Dict[str, Any]:
    """
    Builds a summary of the scan report.

    Includes:
        - Severity counts
        - CWE counts
        - Rule counts
        - Patch statistics
        - Average confidence score
    """
    severity_counts: Dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    cwe_counts: Dict[str, int] = {}
    rule_counts: Dict[str, int] = {}

    patch_stats: Dict[str, int] = {
        "generated": 0,
        "success": 0,
        "failed": 0,
        "valid": 0,
        "review": 0,
        "rejected": 0,
    }

    confidences = []

    for finding in report.findings:
        severity_counts[finding.severity.value] += 1

        cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1
        rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1

        patch = finding.patch

        if patch is None:
            continue

        patch_stats["generated"] += 1

        if not patch.success:
            patch_stats["failed"] += 1
            continue

        patch_stats["success"] += 1

        if patch.validation is None:
            continue

        confidences.append(patch.validation.confidence_score)

        if patch.validation.passed:
            if patch.validation.decision.startswith("Auto Apply"):
                patch_stats["valid"] += 1
            else:
                patch_stats["review"] += 1
        else:
            patch_stats["rejected"] += 1

    average_confidence = 0.0

    if confidences:
        average_confidence = round(sum(confidences) / len(confidences), 2)

    return {
        "files_scanned": report.files_scanned,
        "total_findings": len(report.findings),
        "errors_count": len(report.errors),
        "severity_counts": severity_counts,
        "cwe_counts": cwe_counts,
        "rule_counts": rule_counts,
        "patch_stats": patch_stats,
        "average_patch_confidence": average_confidence,
    }
