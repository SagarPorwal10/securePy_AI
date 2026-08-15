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

    Handles Severity enum serialisation so the full report can be dumped
    to JSON without manual conversion of every dataclass field.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Severity):
            return obj.value

        return super().default(obj)


def build_report_dict(report: ScanReport, target: str = "") -> Dict[str, Any]:
    """
    Builds a complete JSON-serialisable report dictionary.
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
    Serialises the full scan report to a JSON file and returns the path.
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
