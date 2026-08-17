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
* { box-sizing: border-box; }

body {
    font-family: 'Segoe UI', Arial, sans-serif;
    margin: 0;
    padding: 24px 32px;
    background: #0f172a;
    color: #e2e8f0;
}

h1 { color: #67e8f9; margin-bottom: 4px; }
h2 { color: #93c5fd; margin-top: 32px; border-bottom: 1px solid #334155; padding-bottom: 8px; }

.meta { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }

.cards {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 16px 0 24px;
}

.card {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 14px 20px;
    min-width: 140px;
    text-align: center;
}

.card strong {
    display: block;
    font-size: 30px;
    font-weight: 700;
    color: #67e8f9;
    margin-bottom: 4px;
}

.card span { font-size: 12px; color: #94a3b8; }

table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 16px;
    font-size: 13px;
}

th, td {
    border: 1px solid #1e293b;
    padding: 9px 11px;
    vertical-align: top;
}

th {
    background: #111827;
    color: #93c5fd;
    text-align: left;
}

tr:nth-child(even) td { background: #111827; }

.critical { color: #fda4af; font-weight: 700; }
.high     { color: #fdba74; font-weight: 700; }
.medium   { color: #fde68a; font-weight: 700; }
.low      { color: #86efac; font-weight: 700; }
.info     { color: #a5f3fc; font-weight: 700; }

.badge-valid    { background: #166534; color: #86efac; padding: 2px 8px; border-radius: 999px; font-size: 11px; }
.badge-review   { background: #713f12; color: #fde68a; padding: 2px 8px; border-radius: 999px; font-size: 11px; }
.badge-rejected { background: #7f1d1d; color: #fca5a5; padding: 2px 8px; border-radius: 999px; font-size: 11px; }
.badge-none     { color: #64748b; font-size: 11px; }
</style>
</head>
<body>
<h1>SecurePy AI Security Report</h1>
<div class="meta">
  Generated: {{GENERATED_AT}} &nbsp;|&nbsp;
  Target: <strong>{{TARGET}}</strong> &nbsp;|&nbsp;
  Tool: SecurePy AI v{{VERSION}}
</div>

<h2>Summary</h2>
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
<th>File:Line</th>
<th>Vulnerability</th>
<th>Patch</th>
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
    cards = [
        ("Files Scanned",        summary["files_scanned"]),
        ("Total Findings",       summary["total_findings"]),
        ("Patches Generated",    summary["patch_stats"]["generated"]),
        ("Auto Apply",           summary["patch_stats"]["auto_apply"]),
        ("Review Needed",        summary["patch_stats"]["review"]),
        ("Rejected",             summary["patch_stats"]["rejected"]),
        ("Avg Confidence",       summary["average_patch_confidence"]),
    ]

    parts = []

    for label, value in cards:
        parts.append(
            f'<div class="card">'
            f"<strong>{html_escape(str(value))}</strong>"
            f"<span>{html_escape(label)}</span>"
            f"</div>"
        )

    return "\n".join(parts)


def _patch_status(finding: VulnerabilityFinding) -> tuple:
    patch = finding.patch

    if patch is None:
        return "No patch", "-", "-", "none"

    if not patch.success:
        return "Failed", "-", "-", "rejected"

    if patch.validation is None:
        return "Generated", "-", "-", "none"

    v = patch.validation

    if v.passed and v.decision.startswith("Auto Apply"):
        badge = "valid"
        label = "Auto Apply"
    elif v.passed:
        badge = "review"
        label = "Review"
    else:
        badge = "rejected"
        label = "Rejected"

    return label, f"{v.confidence_score:.0f}/100", v.decision, badge


def _finding_rows(report: ScanReport) -> str:
    if not report.findings:
        return '<tr><td colspan="8" style="text-align:center;color:#64748b;">No findings detected.</td></tr>'

    rows = []

    for finding in report.findings:
        label, confidence, decision, badge = _patch_status(finding)
        sev = finding.severity.value.lower()

        rows.append(
            "<tr>"
            f'<td class="{sev}">{html_escape(finding.severity.value)}</td>'
            f"<td>{html_escape(finding.rule_id)}</td>"
            f"<td>{html_escape(finding.cwe_id)}</td>"
            f"<td>{html_escape(finding.file_path)}:{html_escape(str(finding.line_number))}</td>"
            f"<td><strong>{html_escape(finding.vuln_type)}</strong><br>"
            f"<small>{html_escape(finding.description)}</small></td>"
            f'<td><span class="badge-{badge}">{html_escape(label)}</span></td>'
            f"<td>{html_escape(confidence)}</td>"
            f"<td><small>{html_escape(decision)}</small></td>"
            "</tr>"
        )

    return "\n".join(rows)


def write_html_report(
    report: ScanReport,
    output_path: Path,
    target: str = "",
) -> Path:
    """
    Renders a standalone dark-themed HTML report and writes it to disk.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary = build_summary(report)

    html = HTML_TEMPLATE
    html = html.replace("{{GENERATED_AT}}", html_escape(datetime.now(timezone.utc).isoformat()))
    html = html.replace("{{TARGET}}", html_escape(target or "—"))
    html = html.replace("{{VERSION}}", html_escape(__version__))
    html = html.replace("{{SUMMARY_CARDS}}", _summary_cards(summary))
    html = html.replace("{{FINDINGS_ROWS}}", _finding_rows(report))

    output_path.write_text(html, encoding="utf-8")

    return output_path
