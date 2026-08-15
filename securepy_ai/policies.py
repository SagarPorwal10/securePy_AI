from securepy_ai.models import ScanReport


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity_value: str) -> int:
    """
    Converts severity text into a numeric rank.
    """
    return SEVERITY_ORDER.get(severity_value.lower(), 0)


def has_findings_at_or_above(report: ScanReport, threshold: str) -> bool:
    """
    Checks whether the report contains findings at or above
    the given severity threshold.
    """
    if threshold.lower() in {"none", "off"}:
        return False

    threshold_rank = SEVERITY_ORDER.get(threshold.lower())

    if threshold_rank is None:
        return False

    for finding in report.findings:
        if _severity_rank(finding.severity.value) >= threshold_rank:
            return True

    return False


def determine_exit_code(
    report: ScanReport,
    fail_on: str = "high",
    has_scanner_errors: bool = False,
) -> int:
    """
    Determines CI-friendly exit codes.

    Exit codes:
        0 → success / no blocking findings
        1 → blocking findings detected
        2 → scanner/tool error
    """
    if has_scanner_errors and not report.findings:
        return 2

    if fail_on.lower() in {"none", "off"}:
        return 0

    if has_findings_at_or_above(report, fail_on):
        return 1

    return 0
