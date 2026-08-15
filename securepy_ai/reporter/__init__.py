from pathlib import Path
from typing import Dict

from securepy_ai.models import ScanReport
from securepy_ai.reporter.summary import build_summary
from securepy_ai.reporter.json_report import build_report_dict, write_json_report
from securepy_ai.reporter.html_report import write_html_report
from securepy_ai.reporter.sarif_report import write_sarif_report


def write_reports(
    report: ScanReport,
    output_dir: str,
    report_type: str = "json",
    target: str = "",
) -> Dict[str, Path]:
    """
    Writes one or more report types to *output_dir*.

    report_type:
        "json"  → securepy-ai-report.json
        "html"  → securepy-ai-report.html
        "sarif" → securepy-ai-report.sarif
        "all"   → all three formats
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
