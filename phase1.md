Absolutely Sagar. Let’s build **Phase 1: Core AST Scanner** properly.

This phase is the foundation of **SecurePy AI**. By the end of Phase 1, your tool should be able to:

```text
1. Accept a Python file or folder as input
2. Parse Python code into AST
3. Apply at least one security rule
4. Detect a hardcoded secret
5. Show findings in a clean terminal output
```

This is the MVP scanner.

---

# Phase 1 Goal

Build this command:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

Expected result:

```text
SecurePy AI v0.1.0
Target: examples/vulnerable.py
Files scanned: 1

Findings:
- Hardcoded Secret | CWE-798 | examples/vulnerable.py:1
- Hardcoded Secret | CWE-798 | examples/vulnerable.py:2
- Hardcoded Secret | CWE-798 | examples/vulnerable.py:3
```

---

# 1. Phase 1 Folder Structure

Create a new project folder:

```bash
mkdir securepy-ai
cd securepy-ai
```

If you already have your old SecurePy repo, create a new branch:

```bash
git checkout -b securepy-ai-phase-1
```

Create this structure:

```text
securepy-ai/
│
├── securepy_ai/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   │
│   └── scanner/
│       ├── __init__.py
│       ├── ast_parser.py
│       │
│       └── rules/
│           ├── __init__.py
│           ├── base_rule.py
│           └── hardcoded_secret.py
│
├── examples/
│   └── vulnerable.py
│
├── tests/
│   ├── __init__.py
│   └── test_scanner.py
│
├── requirements.txt
└── README.md
```

You can create folders manually or using commands.

### Linux / macOS

```bash
mkdir -p securepy_ai/scanner/rules
mkdir -p examples
mkdir -p tests

touch securepy_ai/__init__.py
touch securepy_ai/cli.py
touch securepy_ai/models.py
touch securepy_ai/scanner/__init__.py
touch securepy_ai/scanner/ast_parser.py
touch securepy_ai/scanner/rules/__init__.py
touch securepy_ai/scanner/rules/base_rule.py
touch securepy_ai/scanner/rules/hardcoded_secret.py
touch examples/vulnerable.py
touch tests/__init__.py
touch tests/test_scanner.py
touch requirements.txt
touch README.md
```

### Windows PowerShell

```powershell
mkdir securepy_ai\scanner\rules
mkdir examples
mkdir tests

ni securepy_ai\__init__.py
ni securepy_ai\cli.py
ni securepy_ai\models.py
ni securepy_ai\scanner\__init__.py
ni securepy_ai\scanner\ast_parser.py
ni securepy_ai\scanner\rules\__init__.py
ni securepy_ai\scanner\rules\base_rule.py
ni securepy_ai\scanner\rules\hardcoded_secret.py
ni examples\vulnerable.py
ni tests\__init__.py
ni tests\test_scanner.py
ni requirements.txt
ni README.md
```

---

# 2. Create Virtual Environment

Inside `securepy-ai` folder:

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install rich pytest
```

Create `requirements.txt`:

```text
rich>=13.7.0
pytest>=8.0.0
```

---

# 3. Create Core Files

Now copy the following code into the files.

---

# File 1: `securepy_ai/__init__.py`

```python
__version__ = "0.1.0"
```

---

# File 2: `securepy_ai/models.py`

This file defines the data structures used across SecurePy AI.

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class VulnerabilityFinding:
    """
    Represents a single security finding produced by SecurePy AI.
    """
    rule_id: str
    vuln_type: str
    cwe_id: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str


@dataclass
class ScanReport:
    """
    Represents the result of a complete scan.
    """
    files_scanned: int = 0
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
```

---

# File 3: `securepy_ai/scanner/rules/base_rule.py`

This is the base class for all security rules.

```python
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
```

---

# File 4: `securepy_ai/scanner/rules/hardcoded_secret.py`

This is your first working security rule.

It detects things like:

```python
password = "admin123"
api_key = "AKIA923848239482394"
secret_token = "abcd1234"
```

```python
import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule


class HardcodedSecretRule(BaseRule):
    """
    Detects hardcoded secrets such as passwords, API keys, tokens, and credentials.
    """

    rule_id = "SEC101"
    vuln_type = "Hardcoded Secret"
    cwe_id = "CWE-798"
    severity = Severity.HIGH

    SECRET_NAME_PARTS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "accesskey",
        "token",
        "auth",
        "credential",
        "private_key",
        "client_secret",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Looks for assignment statements where the variable name looks secret-like
        and the assigned value is a hardcoded string.
        """
        if not isinstance(node, ast.Assign):
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            variable_name = target.id

            if not self._is_secret_name(variable_name):
                continue

            if not self._is_string_constant(node.value):
                continue

            value = node.value.value

            if self._is_likely_secret(value):
                self.add_finding(
                    node,
                    f"Possible hardcoded secret assigned to variable '{variable_name}'.",
                )

    def _is_secret_name(self, name: str) -> bool:
        """
        Checks whether the variable name contains secret-like keywords.
        """
        lowered_name = name.lower()

        return any(
            secret_part in lowered_name
            for secret_part in self.SECRET_NAME_PARTS
        )

    def _is_string_constant(self, node: ast.AST) -> bool:
        """
        Checks whether the assigned value is a hardcoded string.
        """
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def _is_likely_secret(self, value: str) -> bool:
        """
        Basic filter to ignore obvious placeholder values.
        """
        value = value.strip()

        if len(value) < 6:
            return False

        placeholder_values = {
            "your_password_here",
            "your_api_key_here",
            "your_secret_here",
            "changeme",
            "password",
            "secret",
            "xxxxxx",
            "placeholder",
            "dummy",
            "example",
            "sample",
            "test123",
        }

        return value.lower() not in placeholder_values
```

---

# File 5: `securepy_ai/scanner/ast_parser.py`

This is the main scanner engine.

```python
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
```

---

# File 6: `securepy_ai/cli.py`

This gives you a clean terminal interface.

```python
import argparse

from rich.console import Console
from rich.table import Table

from securepy_ai import __version__
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules.hardcoded_secret import HardcodedSecretRule


console = Console()


SEVERITY_STYLES = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "bold green",
    "Info": "bold cyan",
}


def scan_command(args):
    """
    Handles:
        python -m securepy_ai.cli scan <target>
    """
    rules = [
        HardcodedSecretRule,
    ]

    scanner = SecurePyParser(rules=rules)
    report = scanner.scan_path(args.target)

    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 1 Scan")
    console.print(f"Target: [bold]{args.target}[/bold]")
    console.print(f"Files scanned: [bold]{report.files_scanned}[/bold]")

    if report.errors:
        console.print("\n[bold yellow]Errors:[/bold yellow]")
        for error in report.errors:
            console.print(f"[yellow]{error}[/yellow]")

    if not report.findings:
        console.print("\n[bold green]No vulnerabilities found.[/bold green]")
        return 0

    table = Table(title="SecurePy AI Findings")

    table.add_column("Severity", justify="left")
    table.add_column("Rule", justify="left")
    table.add_column("CWE", justify="left")
    table.add_column("File", justify="left")
    table.add_column("Line", justify="right")
    table.add_column("Description", justify="left")

    for finding in report.findings:
        severity_style = SEVERITY_STYLES.get(finding.severity.value, "white")

        table.add_row(
            f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
            finding.rule_id,
            finding.cwe_id,
            finding.file_path,
            str(finding.line_number),
            finding.description,
        )

    console.print("\n")
    console.print(table)

    console.print("\n[bold]Detailed Findings[/bold]")

    for finding in report.findings:
        console.print(
            f"\n[bold cyan]{finding.file_path}:{finding.line_number}[/bold cyan]"
        )
        console.print(f"[dim]{finding.code_snippet}[/dim]")
        console.print(f"[yellow]{finding.description}[/yellow]")

    console.print(
        f"\n[bold red]Total findings: {len(report.findings)}[/bold red]"
    )

    # Exit code 1 is useful later for CI/CD security gates.
    return 1


def main():
    parser = argparse.ArgumentParser(
        prog="securepy-ai",
        description="SecurePy AI — AST-aware SAST scanner for Python",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SecurePy AI {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Python file or directory",
    )

    scan_parser.add_argument(
        "target",
        help="Path to Python file or directory",
    )

    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(scan_command(args))


if __name__ == "__main__":
    main()
```

---

# File 7: `examples/vulnerable.py`

This is a sample vulnerable file for testing.

```python
password = "admin123"
api_key = "AKIA923848239482394"
db_secret = "supersecret123"

username = "sagar"


def get_user(user_id):
    # This SQL injection pattern will be detected in Phase 2.
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
```

---

# File 8: `tests/test_scanner.py`

This adds basic automated tests.

```python
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules.hardcoded_secret import HardcodedSecretRule


def test_detect_hardcoded_secret(tmp_path):
    code = '''
password = "admin123"
'''

    file_path = tmp_path / "vulnerable.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(file_path))

    assert report.files_scanned == 1
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.rule_id == "SEC101"
    assert finding.cwe_id == "CWE-798"
    assert finding.line_number == 2


def test_ignore_normal_variable(tmp_path):
    code = '''
username = "sagar"
'''

    file_path = tmp_path / "safe.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(file_path))

    assert len(report.findings) == 0


def test_scan_directory(tmp_path):
    vulnerable_file = tmp_path / "vulnerable.py"
    safe_file = tmp_path / "safe.py"

    vulnerable_file.write_text(
        'api_key = "AKIA923848239482394"',
        encoding="utf-8",
    )

    safe_file.write_text(
        'username = "sagar"',
        encoding="utf-8",
    )

    scanner = SecurePyParser(rules=[HardcodedSecretRule])
    report = scanner.scan_path(str(tmp_path))

    assert report.files_scanned == 2
    assert len(report.findings) == 1
    assert report.findings[0].file_path.endswith("vulnerable.py")
```

---

# File 9: `README.md`

Add a basic README.

```markdown
# SecurePy AI

SecurePy AI is an AST-aware SAST scanner for Python.

This repository is being developed in phases:

- Phase 1: Core AST scanner
- Phase 2: Security rules engine
- Phase 3: Context extraction
- Phase 4: Local LLM integration
- Phase 5: Prompt builder
- Phase 6: Patch validator
- Phase 7: Reporting engine
- Phase 8: CLI enhancements
- Phase 9: GitHub Action integration
- Phase 10: Dashboard visualization

## Phase 1 Usage

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

## Run Tests

```bash
pytest tests/ -v
```
```

---

# 4. Run Phase 1

Make sure you are inside the root folder:

```bash
cd securepy-ai
```

Your folder should contain:

```text
securepy_ai/
examples/
tests/
requirements.txt
README.md
```

Run the scanner:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

You should see findings for:

```text
password
api_key
db_secret
```

---

# 5. Run Tests

Run:

```bash
pytest tests/ -v
```

Expected output:

```text
test_scanner.py::test_detect_hardcoded_secret PASSED
test_scanner.py::test_ignore_normal_variable PASSED
test_scanner.py::test_scan_directory PASSED
```

---

# 6. Phase 1 Acceptance Checklist

Phase 1 is complete when all of these are true:

```text
✅ Project structure is created
✅ Virtual environment is working
✅ rich and pytest are installed
✅ python -m securepy_ai.cli scan examples/vulnerable.py works
✅ The scanner detects hardcoded secrets
✅ The scanner ignores normal variables like username
✅ pytest tests pass
✅ Code is committed to GitHub
```

---

# 7. Commit Phase 1 to GitHub

Run:

```bash
git add .
git commit -m "feat(phase-1): add core AST scanner and hardcoded secret rule"
```

If this is a new repository:

```bash
git remote add origin https://github.com/SagarPorwal10/securepy-ai.git
git branch -M main
git push -u origin main
```

If you are using a feature branch:

```bash
git push origin securepy-ai-phase-1
```

---

# 8. Common Errors and Fixes

## Error 1: `ModuleNotFoundError: No module named 'securepy_ai'`

### Cause

You are not running the command from the project root.

### Fix

Make sure you are inside:

```bash
securepy-ai/
```

Then run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

---

## Error 2: `ModuleNotFoundError: No module named 'rich'`

### Fix

```bash
pip install rich
```

---

## Error 3: `pytest: command not found`

### Fix

```bash
pip install pytest
```

Then run:

```bash
pytest tests/ -v
```

---

# 9. What You Just Built

You now have a proper SAST foundation:

```text
Python Source Code
        ↓
AST Parser
        ↓
Rule Engine
        ↓
Hardcoded Secret Rule
        ↓
Findings
        ↓
Rich CLI Output
```

This is enough for Phase 1.

---

# 10. What Comes in Phase 2

After this works, Phase 2 will add more detection rules:

```text
SEC101 → Hardcoded Secret
SEC102 → SQL Injection
SEC103 → Command Injection
SEC104 → Insecure Deserialization
SEC105 → Unsafe eval/exec
```

Your next main rule should be:

```text
SQL Injection using f-strings
```

Example vulnerable code:

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

---

# Your Next Task

Complete Phase 1 first.

Do only this today:

```text
1. Create folder structure
2. Add all files above
3. Install rich and pytest
4. Run scan command
5. Run pytest
6. Commit to GitHub
```

Once this works, tell me:

```text
Phase 1 done
```

Then I will give you **Phase 2 complete code**, where we add:

1. SQL Injection detection  
2. Command Injection detection  
3. Insecure deserialization detection  
4. Unsafe `eval()` / `exec()` detection