import json
from pathlib import Path
from typing import Any, Dict, List

from securepy_ai import __version__
from securepy_ai.models import ScanReport


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _sarif_level(severity_value: str) -> str:
    """
    Maps SecurePy AI severity to a SARIF 2.1.0 level string.
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
    Builds a SARIF 2.1.0 report dictionary suitable for GitHub Code Scanning.
    """
    rules: List[Dict[str, Any]] = []
    seen_rule_ids: set = set()
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
    Writes a SARIF 2.1.0 report to disk and returns the path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = build_sarif(report)

    output_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    return output_path
