from securepy_ai.baseline import (
    filter_baseline,
    finding_fingerprint,
    load_baseline,
    save_baseline,
)
from securepy_ai.models import (
    ScanReport,
    Severity,
    VulnerabilityFinding,
)


def make_finding(
    rule_id="SEC101",
    file_path="app.py",
    code_snippet='password = "admin123"',
):
    return VulnerabilityFinding(
        rule_id=rule_id,
        vuln_type="Hardcoded Secret",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=1,
        code_snippet=code_snippet,
        description="Possible hardcoded secret.",
    )


def test_fingerprint_is_stable():
    finding_one = make_finding()
    finding_two = make_finding()

    assert finding_fingerprint(finding_one) == finding_fingerprint(finding_two)


def test_fingerprint_changes_with_code():
    finding_one = make_finding(code_snippet='password = "admin123"')
    finding_two = make_finding(code_snippet='password = "hunter22"')

    assert finding_fingerprint(finding_one) != finding_fingerprint(finding_two)


def test_save_and_load_baseline(tmp_path):
    report = ScanReport(
        files_scanned=1,
        findings=[make_finding()],
        errors=[],
    )

    baseline_path = tmp_path / "baseline.json"

    save_baseline(report, str(baseline_path))
    loaded = load_baseline(str(baseline_path))

    assert finding_fingerprint(make_finding()) in loaded


def test_filter_baseline_removes_known_findings():
    known_finding = make_finding(
        code_snippet='password = "admin123"',
    )

    new_finding = make_finding(
        code_snippet='api_key = "AKIA1234567890"',
    )

    report = ScanReport(
        files_scanned=1,
        findings=[known_finding, new_finding],
        errors=[],
    )

    baseline = {
        finding_fingerprint(known_finding),
    }

    filtered_report, ignored_count = filter_baseline(report, baseline)

    assert ignored_count == 1
    assert len(filtered_report.findings) == 1
    assert filtered_report.findings[0].code_snippet == 'api_key = "AKIA1234567890"'
