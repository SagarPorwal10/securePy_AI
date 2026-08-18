Excellent, Sagar. Since **Phase 6 is done**, now we move to:

# Phase 7 — Reporting and Confidence Summary Engine

Phase 7 makes SecurePy AI feel like a real product and also prepares it for:

```text
CI/CD integration
GitHub Actions
Thesis evaluation
Publication experiments
Developer dashboards
```

After Phase 7, SecurePy AI can generate:

```text
JSON report
HTML report
SARIF report
Confidence summary
Patch summary
Severity summary
CWE summary
```

---

# Phase 7 Goal

After scanning, SecurePy AI should be able to run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --report all --output-dir reports
```

And generate:

```text
reports/securepy-ai-report.json
reports/securepy-ai-report.html
reports/securepy-ai-report.sarif
```

---

# Phase 7 Files

We will create:

```text
securepy_ai/
└── reporter/
    ├── __init__.py
    ├── summary.py
    ├── json_report.py
    ├── html_report.py
    └── sarif_report.py

tests/
└── test_reporter.py
```

We will also update:

```text
securepy_ai/cli.py
```

---

# 1. Create Reporter Package

Create folder:

```bash
mkdir -p securepy_ai/reporter
```

---

# 2. Create Summary Engine

Create:

```text
securepy_ai/reporter/summary.py
```

This builds the report summary.

```python
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
        - Validation statistics
    """
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    cwe_counts: Dict[str, int] = {}
    rule_counts: Dict[str, int] = {}

    patch_stats = {
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

        if patch.validation.is_valid:
            patch_stats["valid"] += 1
        elif patch.validation.decision.startswith("Developer Review"):
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
```

---

# 3. Create JSON Report Generator

Create:

```text
securepy_ai/reporter/json_report.py
```

```python
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from securepy_ai import __version__
from securepy_ai.models import ScanReport, Severity
from securepy_ai.reporter.summary import build_summary


class SecurePyJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for SecurePy AI models.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Severity):
            return obj.value

        return super().default(obj)


def build_report_dict(report: ScanReport, target: str = "") -> Dict[str, Any]:
    """
    Builds a complete JSON-serializable report dictionary.
    """
    return {
        "tool": {
            "name": "SecurePy AI",
            "version": __version__,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": build_summary(report),
        "scan": asdict(report),
    }


def write_json_report(
    report: ScanReport,
    output_path: Path,
    target: str = "",
) -> Path:
    """
    Writes a JSON report to disk.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = build_report_dict(report, target)

    output_path.write_text(
        json.dumps(
            payload,
            indent=2,
            cls=SecurePyJSONEncoder,
        ),
        encoding="utf-8",
    )

    return output_path
```

---

# 4. Create HTML Report Generator

Create:

```text
securepy_ai/reporter/html_report.py
```

This creates a clean standalone HTML report.

```python
from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path

from securepy_ai import __version__
from securepy_ai.models import ScanReport, VulnerabilityFinding
from securepy_ai.reporter.summary import build_summary


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecurePy AI Report</title>
<style>
body {
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #0f172a;
    color: #e2e8f0;
}

h1 {
    color: #67e8f9;
}

h2 {
    color: #93c5fd;
    margin-top: 32px;
}

.cards {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 16px 0;
}

.card {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 14px 18px;
    min-width: 160px;
}

.card strong {
    display: block;
    font-size: 28px;
    margin-bottom: 4px;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 16px;
}

th,
td {
    border: 1px solid #334155;
    padding: 8px;
    font-size: 13px;
    vertical-align: top;
}

th {
    background: #111827;
    color: #93c5fd;
}

.critical {
    color: #fda4af;
    font-weight: bold;
}

.high {
    color: #fdba74;
    font-weight: bold;
}

.medium {
    color: #fde68a;
    font-weight: bold;
}

.low,
.info {
    color: #86efac;
    font-weight: bold;
}
</style>
</head>
<body>
<h1>SecurePy AI Report</h1>
<p>Generated: {{GENERATED_AT}}</p>
<p>Target: {{TARGET}}</p>
<p>Tool version: {{VERSION}}</p>

<div class="cards">
{{SUMMARY_CARDS}}
</div>

<h2>Findings</h2>
<table>
<thead>
<tr>
<th>Severity</th>
<th>Rule</th>
<th>CWE</th>
<th>File</th>
<th>Line</th>
<th>Vulnerability</th>
<th>Patch Status</th>
<th>Confidence</th>
<th>Decision</th>
</tr>
</thead>
<tbody>
{{FINDINGS_ROWS}}
</tbody>
</table>
</body>
</html>
"""


def _summary_cards(summary: dict) -> str:
    """
    Builds summary cards for the HTML report.
    """
    cards = [
        ("Files Scanned", summary["files_scanned"]),
        ("Findings", summary["total_findings"]),
        ("Valid Patches", summary["patch_stats"]["valid"]),
        ("Review Patches", summary["patch_stats"]["review"]),
        ("Rejected Patches", summary["patch_stats"]["rejected"]),
        ("Average Confidence", summary["average_patch_confidence"]),
    ]

    html_parts = []

    for label, value in cards:
        html_parts.append(
            f'<div class="card">'
            f"<strong>{html_escape(str(value))}</strong>"
            f"{html_escape(label)}"
            f"</div>"
        )

    return "".join(html_parts)


def _patch_status(finding: VulnerabilityFinding) -> tuple:
    """
    Returns patch status, confidence, and decision for a finding.
    """
    patch = finding.patch

    if patch is None:
        return "No patch", "-", "-"

    if not patch.success:
        return "Failed", "-", "-"

    if patch.validation is None:
        return "Generated", "-", "-"

    validation = patch.validation

    if validation.is_valid:
        status = "Valid"
    elif validation.decision.startswith("Developer Review"):
        status = "Review"
    else:
        status = "Rejected"

    return (
        status,
        f"{validation.confidence_score:.2f}",
        validation.decision,
    )


def _finding_rows(report: ScanReport) -> str:
    """
    Builds finding rows for the HTML table.
    """
    if not report.findings:
        return '<tr><td colspan="9">No findings detected.</td></tr>'

    rows = []

    for finding in report.findings:
        status, confidence, decision = _patch_status(finding)
        severity_class = finding.severity.value.lower()

        rows.append(
            "<tr>"
            f'<td class="{severity_class}">{html_escape(finding.severity.value)}</td>'
            f"<td>{html_escape(finding.rule_id)}</td>"
            f"<td>{html_escape(finding.cwe_id)}</td>"
            f"<td>{html_escape(finding.file_path)}</td>"
            f"<td>{html_escape(str(finding.line_number))}</td>"
            f"<td>{html_escape(finding.vuln_type)}<br><br>{html_escape(finding.description)}</td>"
            f"<td>{html_escape(status)}</td>"
            f"<td>{html_escape(confidence)}</td>"
            f"<td>{html_escape(decision)}</td>"
            "</tr>"
        )

    return "".join(rows)


def write_html_report(
    report: ScanReport,
    output_path: Path,
    target: str = "",
) -> Path:
    """
    Writes an HTML report to disk.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = build_summary(report)

    html = HTML_TEMPLATE
    html = html.replace(
        "{{GENERATED_AT}}",
        html_escape(datetime.now(timezone.utc).isoformat()),
    )
    html = html.replace("{{TARGET}}", html_escape(target))
    html = html.replace("{{VERSION}}", html_escape(__version__))
    html = html.replace("{{SUMMARY_CARDS}}", _summary_cards(summary))
    html = html.replace("{{FINDINGS_ROWS}}", _finding_rows(report))

    output_path.write_text(html, encoding="utf-8")

    return output_path
```

---

# 5. Create SARIF Report Generator

Create:

```text
securepy_ai/reporter/sarif_report.py
```

SARIF is important because GitHub Code Scanning can use it later.

```python
import json
from pathlib import Path
from typing import Any, Dict, List

from securepy_ai import __version__
from securepy_ai.models import ScanReport


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _sarif_level(severity_value: str) -> str:
    """
    Maps SecurePy AI severity to SARIF level.
    """
    mapping = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
        "Info": "note",
    }

    return mapping.get(severity_value, "warning")


def build_sarif(report: ScanReport) -> Dict[str, Any]:
    """
    Builds a SARIF 2.1.0 report dictionary.
    """
    rules: List[Dict[str, Any]] = []
    seen_rule_ids = set()
    results: List[Dict[str, Any]] = []

    for finding in report.findings:
        if finding.rule_id not in seen_rule_ids:
            seen_rule_ids.add(finding.rule_id)

            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.vuln_type,
                    "shortDescription": {
                        "text": f"{finding.vuln_type} ({finding.cwe_id})"
                    },
                }
            )

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.value),
                "message": {
                    "text": f"{finding.vuln_type}: {finding.description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(finding.file_path).as_posix()
                            },
                            "region": {
                                "startLine": finding.line_number
                            },
                        }
                    }
                ],
                "properties": {
                    "cwe": finding.cwe_id,
                    "severity": finding.severity.value,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecurePy AI",
                        "version": __version__,
                        "informationUri": "https://github.com/SagarPorwal10/securepy-ai",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(
    report: ScanReport,
    output_path: Path,
    target: str = "",
) -> Path:
    """
    Writes a SARIF report to disk.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = build_sarif(report)

    output_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    return output_path
```

---

# 6. Create Reporter Package Init

Create:

```text
securepy_ai/reporter/__init__.py
```

```python
from pathlib import Path
from typing import Dict

from securepy_ai.models import ScanReport

from securepy_ai.reporter.summary import build_summary
from securepy_ai.reporter.json_report import (
    build_report_dict,
    write_json_report,
)
from securepy_ai.reporter.html_report import write_html_report
from securepy_ai.reporter.sarif_report import write_sarif_report


def write_reports(
    report: ScanReport,
    output_dir: str,
    report_type: str = "json",
    target: str = "",
) -> Dict[str, Path]:
    """
    Writes one or more report types.

    report_type can be:
        - json
        - html
        - sarif
        - all
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, Path] = {}

    if report_type in {"json", "all"}:
        paths["json"] = write_json_report(
            report,
            output_path / "securepy-ai-report.json",
            target=target,
        )

    if report_type in {"html", "all"}:
        paths["html"] = write_html_report(
            report,
            output_path / "securepy-ai-report.html",
            target=target,
        )

    if report_type in {"sarif", "all"}:
        paths["sarif"] = write_sarif_report(
            report,
            output_path / "securepy-ai-report.sarif",
            target=target,
        )

    return paths


__all__ = [
    "build_summary",
    "build_report_dict",
    "write_json_report",
    "write_html_report",
    "write_sarif_report",
    "write_reports",
]
```

---

# 7. Update CLI

Open:

```text
securepy_ai/cli.py
```

You need to make three changes.

---

## Change 1: Add Reporter Import

Near the other imports, add:

```python
from securepy_ai.reporter import write_reports
```

Your imports should now include:

```python
from securepy_ai.reporter import write_reports
```

---

## Change 2: Add Report Flags

Inside `main()`, inside the `scan_parser` section, add these arguments:

```python
    scan_parser.add_argument(
        "--report",
        choices=["json", "html", "sarif", "all"],
        help="Generate report output",
    )

    scan_parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to store generated reports",
    )
```

Add them after this block:

```python
    scan_parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip patch validation",
    )
```

So it becomes:

```python
    scan_parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip patch validation",
    )

    scan_parser.add_argument(
        "--report",
        choices=["json", "html", "sarif", "all"],
        help="Generate report output",
    )

    scan_parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to store generated reports",
    )
```

---

## Change 3: Generate Reports

Inside `scan_command`, add this near the end, before:

```python
    console.print(
        f"\n[bold red]Total findings: {len(report.findings)}[/bold red]"
    )
```

Add this block:

```python
    if args.report:
        report_paths = write_reports(
            report=report,
            output_dir=args.output_dir,
            report_type=args.report,
            target=args.target,
        )

        console.print("\n[bold cyan]Reports Generated[/bold cyan]")

        for report_type, report_path in report_paths.items():
            console.print(
                f"[green]{report_type.upper()} report saved:[/green] {report_path}"
            )
```

So the final part of `scan_command` becomes:

```python
    if args.report:
        report_paths = write_reports(
            report=report,
            output_dir=args.output_dir,
            report_type=args.report,
            target=args.target,
        )

        console.print("\n[bold cyan]Reports Generated[/bold cyan]")

        for report_type, report_path in report_paths.items():
            console.print(
                f"[green]{report_type.upper()} report saved:[/green] {report_path}"
            )

    console.print(
        f"\n[bold red]Total findings: {len(report.findings)}[/bold red]"
    )

    # Exit code 1 is useful later for CI/CD security gates.
    return 1
```

---

# 8. Add Reporter Tests

Create:

```text
tests/test_reporter.py
```

```python
import json

from securepy_ai.models import (
    PatchCandidate,
    PatchValidation,
    ScanReport,
    Severity,
    VulnerabilityFinding,
)
from securepy_ai.reporter import build_summary, write_reports


def make_report():
    validation = PatchValidation(
        is_valid=True,
        syntax_valid=True,
        ast_logic_preserved=True,
        vulnerability_fixed=True,
        no_new_vulnerabilities=True,
        tests_passed=None,
        confidence_score=1.0,
        decision="Auto Apply Recommended",
        checks=[],
    )

    patch = PatchCandidate(
        model="test-model",
        prompt_used="test prompt",
        original_code='query = f"SELECT * FROM users WHERE id = {user_id}"',
        patched_code='query = "SELECT * FROM users WHERE id = ?"',
        raw_response="patched code",
        latency_ms=12.0,
        success=True,
        validation=validation,
    )

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


def test_summary_counts():
    report = make_report()
    summary = build_summary(report)

    assert summary["files_scanned"] == 1
    assert summary["total_findings"] == 1
    assert summary["severity_counts"]["Critical"] == 1
    assert summary["cwe_counts"]["CWE-89"] == 1
    assert summary["rule_counts"]["SEC102"] == 1
    assert summary["patch_stats"]["generated"] == 1
    assert summary["patch_stats"]["valid"] == 1
    assert summary["average_patch_confidence"] == 1.0


def test_json_report_generation(tmp_path):
    report = make_report()

    paths = write_reports(
        report=report,
        output_dir=tmp_path,
        report_type="json",
        target="app.py",
    )

    assert "json" in paths
    assert paths["json"].exists()

    data = json.loads(paths["json"].read_text(encoding="utf-8"))

    assert data["tool"]["name"] == "SecurePy AI"
    assert data["target"] == "app.py"
    assert data["summary"]["total_findings"] == 1
    assert data["scan"]["files_scanned"] == 1


def test_html_report_generation(tmp_path):
    report = make_report()

    paths = write_reports(
        report=report,
        output_dir=tmp_path,
        report_type="html",
        target="app.py",
    )

    assert "html" in paths
    assert paths["html"].exists()

    content = paths["html"].read_text(encoding="utf-8")

    assert "SecurePy AI Report" in content
    assert "SQL Injection" in content
    assert "CWE-89" in content


def test_sarif_report_generation(tmp_path):
    report = make_report()

    paths = write_reports(
        report=report,
        output_dir=tmp_path,
        report_type="sarif",
        target="app.py",
    )

    assert "sarif" in paths
    assert paths["sarif"].exists()

    data = json.loads(paths["sarif"].read_text(encoding="utf-8"))

    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "SecurePy AI"
    assert data["runs"][0]["results"][0]["ruleId"] == "SEC102"
    assert data["runs"][0]["results"][0]["properties"]["cwe"] == "CWE-89"


def test_all_reports_generation(tmp_path):
    report = make_report()

    paths = write_reports(
        report=report,
        output_dir=tmp_path,
        report_type="all",
        target="app.py",
    )

    assert "json" in paths
    assert "html" in paths
    assert "sarif" in paths

    assert paths["json"].exists()
    assert paths["html"].exists()
    assert paths["sarif"].exists()
```

---

# 9. Run Phase 7

Make sure you are in the project root:

```bash
cd securepy-ai
```

Generate JSON report:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --report json
```

Expected:

```text
JSON report saved: reports/securepy-ai-report.json
```

Generate HTML report:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --report html
```

Open:

```text
reports/securepy-ai-report.html
```

Generate SARIF report:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --report sarif
```

Generate all reports:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --report all
```

Expected files:

```text
reports/securepy-ai-report.json
reports/securepy-ai-report.html
reports/securepy-ai-report.sarif
```

---

# 10. Run With Fix + Validation + Reports

Example with mock LLM:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2 --report all
```

Example with real Ollama:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b --max-patches 1 --report all
```

This will produce a report containing:

```text
Findings
Context
Patch candidates
Validation results
Confidence scores
Summary statistics
```

This is very useful for:

```text
Thesis screenshots
Publication evaluation
CI artifacts
Project demo
```

---

# 11. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run only reporter tests:

```bash
pytest tests/test_reporter.py -v
```

Expected reporter tests:

```text
tests/test_reporter.py::test_summary_counts PASSED
tests/test_reporter.py::test_json_report_generation PASSED
tests/test_reporter.py::test_html_report_generation PASSED
tests/test_reporter.py::test_sarif_report_generation PASSED
tests/test_reporter.py::test_all_reports_generation PASSED
```

---

# 12. Add Reports Folder to `.gitignore`

You may not want to commit generated reports.

Add to `.gitignore`:

```text
reports/
```

If you do not have a `.gitignore`, create one:

```bash
touch .gitignore
```

Add:

```text
__pycache__/
*.pyc
.venv/
venv/
.pytest_cache/
reports/
```

---

# 13. Phase 7 Acceptance Checklist

Phase 7 is complete when:

```text
✅ reporter package is created
✅ summary.py builds scan summary
✅ json_report.py generates JSON report
✅ html_report.py generates HTML report
✅ sarif_report.py generates SARIF report
✅ write_reports supports json, html, sarif, all
✅ CLI supports --report
✅ CLI supports --output-dir
✅ Reports include severity counts
✅ Reports include CWE counts
✅ Reports include patch statistics
✅ Reports include confidence summary
✅ Reporter tests pass
✅ Code is committed to GitHub
```

---

# 14. Commit Phase 7

Run:

```bash
git add .
git commit -m "feat(phase-7): add JSON, HTML, and SARIF reporting engine"
```

Push:

```bash
git push
```

If using a feature branch:

```bash
git push origin securepy-ai-phase-7
```

---

# 15. Why Phase 7 Is Important for Your Publication

Phase 7 gives you the output format needed for evaluation.

For your paper, you can now collect:

```text
Total findings
Severity distribution
CWE distribution
Patch generation count
Valid patch count
Rejected patch count
Average confidence
```

This will help you create tables like:

```text
Table 1: Vulnerability Detection Results
Table 2: Patch Validation Results
Table 3: Confidence Score Distribution
Table 4: CWE-wise Remediation Success Rate
```

It also prepares SecurePy AI for GitHub Actions because SARIF can later be uploaded to GitHub Code Scanning.

---

# 16. What Comes in Phase 8

Phase 8 is:

```text
Developer Experience and Advanced CLI
```

We will add:

```text
--fail-on severity threshold
--quiet mode
--format stdout output
--baseline mode
CI-friendly exit behavior
```

This will make SecurePy AI feel more like a real security product.

---

Once you complete Phase 7, reply:

```text
Phase 7 done
```

Then I will give you **Phase 8 complete code**, where we build the **Advanced CLI and CI-Friendly Developer Experience**.