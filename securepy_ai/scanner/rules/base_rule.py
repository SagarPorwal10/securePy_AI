from abc import ABC, abstractmethod
import ast
from typing import List

from securepy_ai.models import VulnerabilityFinding, Severity


class BaseRule(ABC):
    """
    Base class for all SecurePy AI detection rules.

    Each rule receives the AST tree and scans nodes for suspicious patterns.
    """

    rule_id: str = "BASE000"
    vuln_type: str = "Base Rule"
    cwe_id: str = "CWE-000"
    severity: Severity = Severity.INFO

    def __init__(self):
        self.findings: List[VulnerabilityFinding] = []
        self.file_path: str = ""
        self.source: str = ""
        self.lines: List[str] = []

    def scan(self, tree: ast.AST, file_path: str, source: str) -> List[VulnerabilityFinding]:
        """
        Main entry point for scanning an AST tree.
        """
        self.findings = []
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()

        for node in ast.walk(tree):
            self.visit(node)

        return self.findings

    @abstractmethod
    def visit(self, node: ast.AST) -> None:
        """
        Each rule must implement its own node inspection logic.
        """
        pass

    def add_finding(self, node: ast.AST, description: str) -> None:
        """
        Helper method to add a finding.
        """
        line_number = getattr(node, "lineno", 0)

        self.findings.append(
            VulnerabilityFinding(
                rule_id=self.rule_id,
                vuln_type=self.vuln_type,
                cwe_id=self.cwe_id,
                severity=self.severity,
                file_path=self.file_path,
                line_number=line_number,
                code_snippet=self.get_line(line_number),
                description=description,
            )
        )

    def get_line(self, line_number: int) -> str:
        """
        Returns the source code line for a given line number.
        """
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].strip()
        return ""
