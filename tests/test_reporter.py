"""
Phase 7 — Reporter tests.

Covers:
    - Summary aggregation
    - JSON report generation
    - HTML report generation
    - SARIF report generation
    - All-formats generation
"""

import json

from securepy_ai.models import (
    PatchCandidate,
    PatchValidation,
    ScanReport,
    Severity,
    VulnerabilityFinding,
)
from securepy_ai.reporter import build_summary, write_reports


def _make_validation(
    passed: bool = True,
    confidence_score: float = 100.0,
    decision: str = "Auto Apply Recommended",
) -> PatchValidation:
    return PatchValidation(
        syntax_valid=True,
        logic_preserved=True,
        vuln_fixed=passed,
        no_new_vulns=True,
        confidence_score=confidence_score,
        passed=passed,
        decision=decision,
    )


def _make_patch(validation: PatchValidation | None = None) -> PatchCandidate:
    return PatchCandidate(
        model="test-model",
        prompt_used="test prompt",
        original_code='query = f"SELECT * FROM users WHERE id = {user_id}"',
        patched_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        raw_response="patched code",
        latency_ms=12.0,
        success=True,
        validation=validation,
    )


def _make_report(
    *,
    with_validation: bool = True,
    decision: str = "Auto Apply Recommended",
    confidence: float = 100.0,
    passed: bool = True,
) -> ScanReport:
    validation = (
        _make_validation(passed=passed, confidence_score=confidence, decision=decision)
        if with_validation
        else None
    )

    patch = _make_patch(validation=validation)

    finding = VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=24,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
        patch=patch,
    )

    return ScanReport(
        files_scanned=1,
        findings=[finding],
        errors=[],
    )


# ------------------------------------------------------------------
# Summary tests
# ------------------------------------------------------------------


def test_summary_basic_counts():
    report = _make_report()
    summary = build_summary(report)

    assert summary["files_scanned"] == 1
    assert summary["total_findings"] == 1
    assert summary["errors_count"] == 0


def test_summary_severity_counts():
    report = _make_report()
    summary = build_summary(report)

    assert summary["severity_counts"]["Critical"] == 1
    assert summary["severity_counts"]["High"] == 0


def test_summary_cwe_and_rule_counts():
    report = _make_report()
    summary = build_summary(report)

    assert summary["cwe_counts"]["CWE-89"] == 1
    assert summary["rule_counts"]["SEC102"] == 1


def test_summary_patch_stats_auto_apply():
    report = _make_report(decision="Auto Apply Recommended", confidence=100.0, passed=True)
    summary = build_summary(report)

    assert summary["patch_stats"]["generated"] == 1
    assert summary["patch_stats"]["success"] == 1
    assert summary["patch_stats"]["auto_apply"] == 1
    assert summary["patch_stats"]["review"] == 0
    assert summary["patch_stats"]["rejected"] == 0


def test_summary_patch_stats_rejected():
    report = _make_report(decision="Reject / Manual Remediation", confidence=50.0, passed=False)
    summary = build_summary(report)

    assert summary["patch_stats"]["rejected"] == 1
    assert summary["patch_stats"]["auto_apply"] == 0


def test_summary_average_confidence():
    report = _make_report(confidence=80.0)
    summary = build_summary(report)

    assert summary["average_patch_confidence"] == 80.0


def test_summary_no_patch():
    finding = VulnerabilityFinding(
        rule_id="SEC101",
        vuln_type="Hardcoded Secret",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        file_path="app.py",
        line_number=7,
        code_snippet='password = "admin123"',
        description="Hardcoded secret.",
    )

    report = ScanReport(files_scanned=1, findings=[finding])
    summary = build_summary(report)

    assert summary["patch_stats"]["generated"] == 0
    assert summary["average_patch_confidence"] == 0.0


# ------------------------------------------------------------------
# JSON report tests
# ------------------------------------------------------------------


def test_json_report_generation(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="json", target="app.py")

    assert "json" in paths
    assert paths["json"].exists()

    data = json.loads(paths["json"].read_text(encoding="utf-8"))

    assert data["tool"]["name"] == "SecurePy AI"
    assert data["target"] == "app.py"
    assert data["summary"]["total_findings"] == 1
    assert data["scan"]["files_scanned"] == 1


def test_json_report_contains_findings(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="json", target="app.py")
    data = json.loads(paths["json"].read_text(encoding="utf-8"))

    finding = data["scan"]["findings"][0]
    assert finding["rule_id"] == "SEC102"
    assert finding["cwe_id"] == "CWE-89"
    assert finding["severity"] == "Critical"


# ------------------------------------------------------------------
# HTML report tests
# ------------------------------------------------------------------


def test_html_report_generation(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="html", target="app.py")

    assert "html" in paths
    assert paths["html"].exists()

    content = paths["html"].read_text(encoding="utf-8")

    assert "SecurePy AI" in content
    assert "SQL Injection" in content
    assert "CWE-89" in content


def test_html_report_contains_severity(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="html", target="app.py")
    content = paths["html"].read_text(encoding="utf-8")

    assert "Critical" in content


def test_html_report_is_valid_html(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="html", target="app.py")
    content = paths["html"].read_text(encoding="utf-8")

    assert content.startswith("<!DOCTYPE html>")
    assert "</html>" in content


# ------------------------------------------------------------------
# SARIF report tests
# ------------------------------------------------------------------


def test_sarif_report_generation(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="sarif", target="app.py")

    assert "sarif" in paths
    assert paths["sarif"].exists()

    data = json.loads(paths["sarif"].read_text(encoding="utf-8"))

    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "SecurePy AI"


def test_sarif_report_results(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="sarif", target="app.py")
    data = json.loads(paths["sarif"].read_text(encoding="utf-8"))

    result = data["runs"][0]["results"][0]
    assert result["ruleId"] == "SEC102"
    assert result["level"] == "error"
    assert result["properties"]["cwe"] == "CWE-89"
    assert result["properties"]["severity"] == "Critical"


def test_sarif_rules_deduplication(tmp_path):
    """Two findings with the same rule_id should produce only one rule entry."""
    finding1 = VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="a.py",
        line_number=10,
        code_snippet="...",
        description="SQL injection.",
    )

    finding2 = VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="b.py",
        line_number=20,
        code_snippet="...",
        description="Another SQL injection.",
    )

    report = ScanReport(files_scanned=2, findings=[finding1, finding2])
    paths = write_reports(report=report, output_dir=tmp_path, report_type="sarif", target=".")
    data = json.loads(paths["sarif"].read_text(encoding="utf-8"))

    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]

    assert rule_ids.count("SEC102") == 1
    assert len(data["runs"][0]["results"]) == 2


# ------------------------------------------------------------------
# All-formats test
# ------------------------------------------------------------------


def test_all_reports_generation(tmp_path):
    report = _make_report()
    paths = write_reports(report=report, output_dir=tmp_path, report_type="all", target="app.py")

    assert "json" in paths
    assert "html" in paths
    assert "sarif" in paths

    assert paths["json"].exists()
    assert paths["html"].exists()
    assert paths["sarif"].exists()
