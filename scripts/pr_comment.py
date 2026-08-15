#!/usr/bin/env python3
"""
Builds a Markdown pull request comment from a SecurePy AI JSON report.

Usage:
    python scripts/pr_comment.py reports/securepy-ai-report.json
"""

import json
import sys

# Ensure UTF-8 output on all platforms (Windows cmd/PowerShell may default to cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


SEVERITY_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "🔵",
}


def format_report(data: dict) -> str:
    summary = data.get("summary", {})
    scan = data.get("scan", {})
    findings = scan.get("findings", [])
    patch_stats = summary.get("patch_stats", {})
    severity_counts = summary.get("severity_counts", {})

    lines = []
    lines.append("## 🛡️ SecurePy AI Security Scan")
    lines.append("")

    # Scan summary table
    lines.append("### Scan Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Files scanned | {summary.get('files_scanned', 0)} |")
    lines.append(f"| Total findings | {summary.get('total_findings', 0)} |")
    lines.append(f"| Baseline ignored | {data.get('baseline_ignored', 0)} |")
    lines.append(f"| Patches generated | {patch_stats.get('generated', 0)} |")
    lines.append(f"| Valid patches | {patch_stats.get('valid', 0)} |")
    lines.append(f"| Review patches | {patch_stats.get('review', 0)} |")
    lines.append(f"| Rejected patches | {patch_stats.get('rejected', 0)} |")
    lines.append("")

    # Severity breakdown
    lines.append("### Severity Breakdown")
    lines.append("")
    for severity, count in severity_counts.items():
        if count > 0:
            icon = SEVERITY_ICON.get(severity, "⚪")
            lines.append(f"- {icon} **{severity}**: {count}")
    lines.append("")

    # Findings table
    if findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Rule | CWE | File | Line | Vulnerability | Patch Status |")
        lines.append("|---|---|---|---|---:|---|---|")

        for finding in findings:
            severity = finding.get("severity", "Info")
            icon = SEVERITY_ICON.get(severity, "⚪")
            rule_id = finding.get("rule_id", "")
            cwe = finding.get("cwe_id", "")
            file_path = finding.get("file_path", "")
            line_number = finding.get("line_number", 0)
            vuln_type = finding.get("vuln_type", "")

            patch = finding.get("patch") or {}
            validation = patch.get("validation") or {}

            if not patch:
                patch_status = "No patch"
            elif not patch.get("success", False):
                patch_status = "Failed"
            elif validation.get("is_valid", False):
                patch_status = f"✅ Valid ({validation.get('confidence_score', 0):.2f})"
            elif validation.get("decision", "").startswith("Developer Review"):
                patch_status = f"👀 Review ({validation.get('confidence_score', 0):.2f})"
            else:
                patch_status = "❌ Rejected"

            lines.append(
                f"| {icon} {severity} | {rule_id} | {cwe} | `{file_path}` | {line_number} | {vuln_type} | {patch_status} |"
            )

        lines.append("")
    else:
        lines.append("✅ **No new vulnerabilities found.**")
        lines.append("")

    lines.append("---")
    lines.append("*SecurePy AI — AST-aware SAST with LLM-assisted remediation*")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/pr_comment.py <report.json>")
        sys.exit(1)

    report_path = sys.argv[1]

    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Report file not found: {report_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON report: {report_path}")
        sys.exit(1)

    print(format_report(data))


if __name__ == "__main__":
    main()
