import ast
from pathlib import Path
from typing import List, Optional, Type

from securepy_ai.models import ScanReport
from securepy_ai.scanner.rules.base_rule import BaseRule


EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "build",
    "dist",
    ".tox",
}


class SecurePyParser:
    """
    Core SecurePy AI AST scanner.

    It accepts a list of rule classes, parses Python files into AST,
    and runs each rule over the AST.
    """

    def __init__(self, rules: Optional[List[Type[BaseRule]]] = None):
        self.rules = rules or []

    def scan_path(self, target: str) -> ScanReport:
        """
        Scans a file or directory recursively.
        """
        report = ScanReport()
        target_path = Path(target)

        if not target_path.exists():
            report.errors.append(f"Target not found: {target}")
            return report

        if target_path.is_file():
            python_files = [target_path]
        else:
            python_files = [
                file_path
                for file_path in target_path.rglob("*.py")
                if not self._is_excluded(file_path)
            ]

        for file_path in python_files:
            report.files_scanned += 1

            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(file_path))

                for rule_class in self.rules:
                    rule = rule_class()
                    findings = rule.scan(tree, str(file_path), source)
                    report.findings.extend(findings)

            except SyntaxError as exc:
                report.errors.append(
                    f"Syntax error in {file_path}:{exc.lineno}: {exc.msg}"
                )
            except Exception as exc:
                report.errors.append(f"Scan error in {file_path}: {exc}")

        return report

    def _is_excluded(self, file_path: Path) -> bool:
        """
        Checks whether the file is inside an excluded directory.
        """
        return any(part in EXCLUDED_DIRECTORIES for part in file_path.parts)
