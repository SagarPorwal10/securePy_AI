from securepy_ai.models import (
    ScanReport,
    Severity,
    VulnerabilityFinding,
)
from securepy_ai.policies import (
    determine_exit_code,
    has_findings_at_or_above,
)


def make_report(severity):
    finding = VulnerabilityFinding(
        rule_id="SEC101",
        vuln_type="Hardcoded Secret",
        cwe_id="CWE-798",
        severity=severity,
        file_path="app.py",
        line_number=1,
        code_snippet='password = "admin123"',
        description="Possible hardcoded secret.",
    )

    return ScanReport(
        files_scanned=1,
        findings=[finding],
        errors=[],
    )


def test_critical_finding_fails_critical_threshold():
    report = make_report(Severity.CRITICAL)

    assert has_findings_at_or_above(report, "critical") is True
    assert determine_exit_code(report, fail_on="critical") == 1


def test_high_finding_does_not_fail_critical_threshold():
    report = make_report(Severity.HIGH)

    assert has_findings_at_or_above(report, "critical") is False
    assert determine_exit_code(report, fail_on="critical") == 0


def test_high_finding_fails_high_threshold():
    report = make_report(Severity.HIGH)

    assert determine_exit_code(report, fail_on="high") == 1


def test_medium_finding_does_not_fail_high_threshold():
    report = make_report(Severity.MEDIUM)

    assert determine_exit_code(report, fail_on="high") == 0


def test_fail_on_none_always_returns_zero():
    report = make_report(Severity.CRITICAL)

    assert determine_exit_code(report, fail_on="none") == 0


def test_scanner_error_with_no_findings_returns_two():
    report = ScanReport(
        files_scanned=1,
        findings=[],
        errors=["Syntax error in file.py"],
    )

    assert determine_exit_code(report, fail_on="high", has_scanner_errors=True) == 2
