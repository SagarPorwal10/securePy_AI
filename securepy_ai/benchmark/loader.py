import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class BenchCase:
    case_id: str
    cwe: str
    rule_id: str
    severity: str
    vuln_type: str
    directory: Path
    vulnerable_code: str
    fixed_code: str
    bad_code: Optional[str] = None
    metadata: dict = field(default_factory=dict)


def load_dataset(dataset_dir: str) -> List[BenchCase]:
    root = Path(dataset_dir)
    cases: List[BenchCase] = []

    for meta_path in sorted(root.rglob("metadata.json")):
        case_dir = meta_path.parent
        vulnerable_path = case_dir / "vulnerable.py"
        fixed_path = case_dir / "expected_fix.py"

        if not vulnerable_path.exists() or not fixed_path.exists():
            continue

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        bad_path = case_dir / "bad_fix.py"

        cases.append(
            BenchCase(
                case_id=meta.get("id", case_dir.name),
                cwe=meta.get("cwe", "CWE-000"),
                rule_id=meta.get("rule_id", ""),
                severity=meta.get("severity", "High"),
                vuln_type=meta.get("vuln_type", ""),
                directory=case_dir,
                vulnerable_code=vulnerable_path.read_text(encoding="utf-8"),
                fixed_code=fixed_path.read_text(encoding="utf-8"),
                bad_code=bad_path.read_text(encoding="utf-8") if bad_path.exists() else None,
                metadata=meta,
            )
        )

    return cases
