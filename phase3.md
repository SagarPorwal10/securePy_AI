Excellent, Sagar. Since **Phase 2 is done**, now we move to:

# Phase 3 — Context Extraction Engine

This is one of the most important phases for your project because this is what makes SecurePy AI different from a normal SAST tool.

A normal SAST tool says:

```text
SQL Injection found at app.py:24
```

SecurePy AI will now understand:

```text
Which function is vulnerable?
What variables are involved?
Where is the data coming from?
Where is it going?
What imports are present?
What secure guidance should be sent to the LLM?
```

This context will later be used in Phase 4 and Phase 5 to generate high-quality LLM prompts.

---

# Phase 3 Goal

After Phase 3, SecurePy AI will be able to run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --context
```

And for each finding, it will show:

```text
Finding ID: SEC102
CWE: CWE-89
Function: get_user
Data Flow: user_id -> dynamic SQL construction -> query
Imports: import flask
Variables in scope: user_id, query
Function Scope:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
```

---

# Files We Will Add or Update in Phase 3

```text
securepy_ai/
├── models.py                         # UPDATE
├── cli.py                            # UPDATE
│
└── scanner/
    ├── context_extractor.py          # NEW
    ├── ast_parser.py                 # SAME
    ├── utils.py                      # SAME
    │
    └── rules/
        ├── base_rule.py              # SAME
        ├── hardcoded_secret.py       # SAME
        ├── sql_injection.py          # SAME
        ├── command_injection.py      # SAME
        ├── insecure_deserialization.py # SAME
        └── unsafe_exec_eval.py       # SAME

tests/
└── test_context.py                   # NEW
```

---

# 1. Update `models.py`

Replace the content of:

```text
securepy_ai/models.py
```

with this updated version.

We are adding a new data class:

```python
VulnerabilityContext
```

We are also attaching optional context to each finding.

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class VulnerabilityContext:
    """
    Rich security context extracted for a vulnerability finding.

    This context will later be used to build high-quality prompts
    for the local LLM remediation engine.
    """

    file_path: str
    line_number: int
    function_name: Optional[str]
    function_scope: str
    surrounding_lines: str
    imports: List[str]
    variables_in_scope: List[str]
    data_flow: str
    sink: Optional[str]
    source: Optional[str]
    cwe_guidance: str

    def to_prompt_context(self) -> str:
        """
        Converts the context into a structured text format suitable
        for an LLM prompt.
        """
        imports_text = "\n".join(self.imports) if self.imports else "No imports detected."
        variables_text = ", ".join(self.variables_in_scope) if self.variables_in_scope else "No variables detected."

        return f"""
File: {self.file_path}
Line: {self.line_number}
Function: {self.function_name or "top-level"}

Data Flow:
{self.data_flow}

Source:
{self.source or "unknown"}

Sink:
{self.sink or "unknown"}

Imports:
{imports_text}

Variables in Scope:
{variables_text}

Function Scope:
{self.function_scope or "No parent function found."}

Surrounding Code:
{self.surrounding_lines}

Security Guidance:
{self.cwe_guidance}
""".strip()


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
    context: Optional[VulnerabilityContext] = None


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

# 2. Create Context Extractor

Create this file:

```text
securepy_ai/scanner/context_extractor.py
```

This is the main Phase 3 engine.

```python
import ast
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from securepy_ai.models import (
    ScanReport,
    VulnerabilityContext,
    VulnerabilityFinding,
)
from securepy_ai.scanner import utils


CWE_GUIDANCE = {
    "CWE-798": (
        "Move secrets out of source code. Use environment variables, "
        "secret managers, or secure configuration stores."
    ),
    "CWE-89": (
        "Use parameterized queries or prepared statements. "
        "Do not build SQL strings with user-controlled input."
    ),
    "CWE-78": (
        "Use subprocess with an argument list and avoid shell=True. "
        "Validate and whitelist allowed commands and arguments."
    ),
    "CWE-502": (
        "Avoid deserializing untrusted data. Use safe formats such as JSON "
        "and validate the schema before loading."
    ),
    "CWE-95": (
        "Avoid eval/exec/compile on dynamic input. Use safe parsers or "
        "restricted alternatives."
    ),
}


RULE_TRANSFORM_DESCRIPTIONS = {
    "SEC101": "hardcoded value assignment",
    "SEC102": "dynamic SQL construction",
    "SEC103": "dynamic command construction",
    "SEC104": "unsafe deserialization",
    "SEC105": "dynamic code execution",
}


RULE_SINK_FALLBACKS = {
    "SEC101": "secret assignment",
    "SEC102": "SQL query construction",
    "SEC103": "OS command execution",
    "SEC104": "deserialization sink",
    "SEC105": "dynamic code execution sink",
}


class ContextEnricher:
    """
    Enriches SecurePy AI findings with security context.

    The extracted context includes:
        - Parent function
        - Function source code
        - Surrounding lines
        - Imports
        - Variables in scope
        - Basic source-to-sink data flow
        - CWE-specific secure coding guidance
    """

    def __init__(self):
        self._source_cache: Dict[str, Optional[str]] = {}
        self._tree_cache: Dict[str, Optional[ast.AST]] = {}

    def enrich(self, report: ScanReport) -> ScanReport:
        """
        Attaches VulnerabilityContext objects to all findings in a report.
        """
        for finding in report.findings:
            source = self._get_source(finding.file_path)

            if source is None:
                continue

            finding.context = self.extract(finding, source)

        return report

    def extract(
        self,
        finding: VulnerabilityFinding,
        source: str,
    ) -> VulnerabilityContext:
        """
        Extracts rich context for one finding.
        """
        tree = self._get_tree(finding.file_path, source)
        lines = source.splitlines()

        function_node = None
        if tree is not None:
            function_node = self._get_parent_function(tree, finding.line_number)

        function_name = function_node.name if function_node else None
        function_scope = self._get_function_scope(source, function_node)
        surrounding_lines = self._get_surrounding_lines(lines, finding.line_number)

        imports = self._get_imports(tree) if tree is not None else []
        variables_in_scope = (
            self._get_variables_in_scope(function_node)
            if function_node is not None
            else []
        )

        nodes_on_line = (
            self._get_nodes_on_line(tree, finding.line_number)
            if tree is not None
            else []
        )

        relevant_node = self._choose_relevant_node(nodes_on_line)
        sink = self._extract_sink(relevant_node, finding)
        source_names = self._extract_source_names(relevant_node)

        source_text = (
            ", ".join(source_names)
            if source_names
            else self._default_source(finding)
        )

        data_flow = self._build_data_flow(finding, source_text, sink)

        return VulnerabilityContext(
            file_path=finding.file_path,
            line_number=finding.line_number,
            function_name=function_name,
            function_scope=function_scope,
            surrounding_lines=surrounding_lines,
            imports=imports,
            variables_in_scope=variables_in_scope,
            data_flow=data_flow,
            sink=sink,
            source=source_text,
            cwe_guidance=CWE_GUIDANCE.get(
                finding.cwe_id,
                "Apply secure coding best practices.",
            ),
        )

    def _get_source(self, file_path: str) -> Optional[str]:
        """
        Reads and caches source code for a file.
        """
        if file_path not in self._source_cache:
            try:
                self._source_cache[file_path] = Path(file_path).read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                self._source_cache[file_path] = None

        return self._source_cache[file_path]

    def _get_tree(self, file_path: str, source: str) -> Optional[ast.AST]:
        """
        Parses and caches the AST for a file.
        """
        if file_path not in self._tree_cache:
            try:
                self._tree_cache[file_path] = ast.parse(source)
            except Exception:
                self._tree_cache[file_path] = None

        return self._tree_cache[file_path]

    def _get_parent_function(
        self,
        tree: ast.AST,
        line_number: int,
    ) -> Optional[ast.AST]:
        """
        Finds the innermost parent function containing the target line.
        """
        best_match = None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start_line = getattr(node, "lineno", 0)
                end_line = getattr(node, "end_lineno", 0)

                if start_line <= line_number <= end_line:
                    if best_match is None or node.lineno > best_match.lineno:
                        best_match = node

        return best_match

    def _get_function_scope(
        self,
        source: str,
        function_node: Optional[ast.AST],
    ) -> str:
        """
        Returns the source code of the parent function.
        """
        if function_node is None:
            return ""

        try:
            return ast.get_source_segment(source, function_node) or ""
        except Exception:
            return ""

    def _get_surrounding_lines(
        self,
        lines: List[str],
        line_number: int,
        window: int = 8,
    ) -> str:
        """
        Returns surrounding lines with line numbers.
        """
        if not lines:
            return ""

        start = max(0, line_number - 1 - window)
        end = min(len(lines), line_number + window)

        numbered_lines = []

        for index in range(start, end):
            current_line_number = index + 1
            marker = ">" if current_line_number == line_number else " "
            numbered_lines.append(
                f"{marker} {current_line_number:4d} | {lines[index]}"
            )

        return "\n".join(numbered_lines)

    def _get_imports(self, tree: ast.AST) -> List[str]:
        """
        Extracts import statements from the AST.
        """
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        imports.append(f"import {alias.name} as {alias.asname}")
                    else:
                        imports.append(f"import {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = []

                for alias in node.names:
                    if alias.asname:
                        names.append(f"{alias.name} as {alias.asname}")
                    else:
                        names.append(alias.name)

                imports.append(f"from {module} import {', '.join(names)}")

        return sorted(set(imports))

    def _get_variables_in_scope(self, function_node: ast.AST) -> List[str]:
        """
        Extracts variables available inside the parent function scope.
        """
        variables = set()

        args = function_node.args

        for arg in getattr(args, "args", []):
            variables.add(arg.arg)

        for arg in getattr(args, "posonlyargs", []):
            variables.add(arg.arg)

        for arg in getattr(args, "kwonlyargs", []):
            variables.add(arg.arg)

        if getattr(args, "vararg", None) is not None:
            variables.add(args.vararg.arg)

        if getattr(args, "kwarg", None) is not None:
            variables.add(args.kwarg.arg)

        for node in ast.walk(function_node):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variables.add(node.id)

        return sorted(variables)

    def _get_nodes_on_line(self, tree: ast.AST, line_number: int) -> List[ast.AST]:
        """
        Returns AST nodes located on the target line.
        """
        nodes = []

        for node in ast.walk(tree):
            if getattr(node, "lineno", None) == line_number:
                nodes.append(node)

        return nodes

    def _choose_relevant_node(
        self,
        nodes: List[ast.AST],
    ) -> Optional[ast.AST]:
        """
        Chooses the most relevant AST node on the vulnerable line.
        """
        if not nodes:
            return None

        for node in nodes:
            if isinstance(node, ast.Call):
                return node

        for node in nodes:
            if isinstance(node, ast.Assign):
                return node

        for node in nodes:
            if isinstance(node, (ast.JoinedStr, ast.BinOp)):
                return node

        return nodes[0]

    def _find_first_call(self, node: Optional[ast.AST]) -> Optional[ast.Call]:
        """
        Finds the first Call node inside a given node.
        """
        if node is None:
            return None

        if isinstance(node, ast.Call):
            return node

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                return child

        return None

    def _get_assignment_target(self, node: ast.AST) -> Optional[str]:
        """
        Returns the target name of an assignment statement.
        """
        if not isinstance(node, ast.Assign):
            return None

        targets = []

        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)

            elif isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    if isinstance(element, ast.Name):
                        targets.append(element.id)

        if not targets:
            return None

        return ", ".join(targets)

    def _extract_sink(
        self,
        node: Optional[ast.AST],
        finding: VulnerabilityFinding,
    ) -> Optional[str]:
        """
        Extracts the dangerous sink associated with the finding.
        """
        call = self._find_first_call(node)

        if call is not None:
            call_name = utils.get_call_name(call)

            if call_name:
                return call_name

            if isinstance(call.func, ast.Attribute):
                return call.func.attr

        assignment_target = self._get_assignment_target(node)

        if assignment_target:
            return assignment_target

        if isinstance(node, ast.Name):
            return node.id

        return RULE_SINK_FALLBACKS.get(finding.rule_id)

    def _iter_data_nodes(self, node: Optional[ast.AST]) -> Iterator[ast.AST]:
        """
        Yields AST nodes that are relevant for data-flow extraction.

        For calls, only arguments and keyword values are considered.
        This avoids treating the called function name as data input.
        """
        if node is None:
            return

        if isinstance(node, ast.Call):
            for arg in node.args:
                yield from ast.walk(arg)

            for keyword in node.keywords:
                yield from ast.walk(keyword.value)

            return

        if isinstance(node, ast.Assign):
            yield from ast.walk(node.value)
            return

        if isinstance(node, ast.Expr):
            yield from ast.walk(node.value)
            return

        yield from ast.walk(node)

    def _extract_source_names(self, node: Optional[ast.AST]) -> List[str]:
        """
        Extracts variable names that appear to flow into the vulnerable sink.
        """
        if node is None:
            return []

        names = []

        for data_node in self._iter_data_nodes(node):
            if isinstance(data_node, ast.Name) and isinstance(data_node.ctx, ast.Load):
                names.append(data_node.id)

        return sorted(set(names))

    def _default_source(self, finding: VulnerabilityFinding) -> str:
        """
        Returns a default source description when no variable names are found.
        """
        if finding.rule_id == "SEC101":
            return "hardcoded literal"

        return "dynamic expression"

    def _build_data_flow(
        self,
        finding: VulnerabilityFinding,
        source_text: str,
        sink: Optional[str],
    ) -> str:
        """
        Builds a simple source-to-sink data-flow string.
        """
        transform = RULE_TRANSFORM_DESCRIPTIONS.get(
            finding.rule_id,
            "suspicious data flow",
        )

        source_part = source_text or "unknown source"
        sink_part = sink or "dangerous sink"

        return f"{source_part} -> {transform} -> {sink_part}"
```

---

# 3. Update CLI

Replace the content of:

```text
securepy_ai/cli.py
```

with this updated version.

This adds:

```bash
--context
```

flag.

```python
import argparse

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from securepy_ai import __version__
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import ALL_RULES


console = Console()


SEVERITY_STYLES = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "bold green",
    "Info": "bold cyan",
}


def print_context(report):
    """
    Prints extracted context for each finding.
    """
    console.print("\n[bold cyan]Extracted Security Context[/bold cyan]")

    for finding in report.findings:
        context = finding.context

        if context is None:
            continue

        title = f"{finding.file_path}:{finding.line_number} — {finding.rule_id}"

        body = f"""
[bold]Rule:[/bold] {escape(finding.rule_id)}
[bold]Vulnerability:[/bold] {escape(finding.vuln_type)}
[bold]CWE:[/bold] {escape(finding.cwe_id)}
[bold]Severity:[/bold] {escape(finding.severity.value)}

[bold]Function:[/bold] {escape(context.function_name or "top-level")}
[bold]Data Flow:[/bold] {escape(context.data_flow)}
[bold]Source:[/bold] {escape(context.source or "unknown")}
[bold]Sink:[/bold] {escape(context.sink or "unknown")}

[bold]Imports:[/bold]
{escape(chr(10).join(context.imports) if context.imports else "No imports detected.")}

[bold]Variables in Scope:[/bold]
{escape(", ".join(context.variables_in_scope) if context.variables_in_scope else "No variables detected.")}

[bold]Function Scope:[/bold]
{escape(context.function_scope) if context.function_scope else "No parent function found."}

[bold]Surrounding Lines:[/bold]
{escape(context.surrounding_lines)}

[bold]Security Guidance:[/bold]
{escape(context.cwe_guidance)}
"""

        console.print(
            Panel(
                body,
                title=title,
                border_style="cyan",
                expand=False,
            )
        )


def scan_command(args):
    """
    Handles:
        python -m securepy_ai.cli scan <target>
    """
    scanner = SecurePyParser(rules=ALL_RULES)
    report = scanner.scan_path(args.target)

    enricher = ContextEnricher()
    enricher.enrich(report)

    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 3 Scan")
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

    if args.context:
        print_context(report)

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

    scan_parser.add_argument(
        "--context",
        action="store_true",
        help="Show extracted security context for each finding",
    )

    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(scan_command(args))


if __name__ == "__main__":
    main()
```

---

# 4. Add Context Tests

Create this file:

```text
tests/test_context.py
```

```python
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import (
    CommandInjectionRule,
    HardcodedSecretRule,
    SQLInjectionRule,
)


def scan_and_enrich(tmp_path, code, rule):
    """
    Helper function to scan and enrich code using one rule.
    """
    file_path = tmp_path / "sample.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[rule])
    report = scanner.scan_path(str(file_path))

    enricher = ContextEnricher()
    enricher.enrich(report)

    return report


def test_sql_injection_context(tmp_path):
    code = '''
import flask


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name == "get_user"
    assert "user_id" in context.variables_in_scope
    assert "SELECT" in context.function_scope
    assert "user_id" in context.data_flow
    assert "dynamic SQL construction" in context.data_flow
    assert context.sink == "query"
    assert any("import flask" in imported for imported in context.imports)


def test_command_injection_context(tmp_path):
    code = '''
import os


def run_ping(host):
    os.system("ping -c 1 " + host)
'''

    report = scan_and_enrich(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name == "run_ping"
    assert "host" in context.variables_in_scope
    assert "host" in context.data_flow
    assert "dynamic command construction" in context.data_flow
    assert context.sink == "os.system"
    assert any("import os" in imported for imported in context.imports)


def test_hardcoded_secret_context(tmp_path):
    code = '''
password = "admin123"
'''

    report = scan_and_enrich(tmp_path, code, HardcodedSecretRule)

    assert len(report.findings) == 1

    finding = report.findings[0]
    context = finding.context

    assert context is not None
    assert context.function_name is None
    assert context.sink == "password"
    assert "hardcoded literal" in context.data_flow
    assert "hardcoded value assignment" in context.data_flow


def test_context_contains_surrounding_lines(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    context = report.findings[0].context

    assert context is not None
    assert "SELECT" in context.surrounding_lines
    assert "def get_user" in context.surrounding_lines


def test_context_contains_cwe_guidance(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_and_enrich(tmp_path, code, SQLInjectionRule)

    context = report.findings[0].context

    assert context is not None
    assert "parameterized" in context.cwe_guidance.lower()
```

---

# 5. Run Phase 3

Make sure you are in the project root:

```bash
cd securepy-ai
```

Run normal scan:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

Run scan with context:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --context
```

You should now see:

```text
SecurePy AI Findings table
Detailed Findings
Extracted Security Context panels
Total findings: 10
```

For the SQL injection finding, you should see something similar to:

```text
Rule: SEC102
Vulnerability: SQL Injection
CWE: CWE-89
Severity: Critical

Function: get_user
Data Flow: user_id -> dynamic SQL construction -> query
Source: user_id
Sink: query

Function Scope:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

Security Guidance:
Use parameterized queries or prepared statements.
Do not build SQL strings with user-controlled input.
```

---

# 6. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run only Phase 3 tests:

```bash
pytest tests/test_context.py -v
```

Expected Phase 3 tests:

```text
tests/test_context.py::test_sql_injection_context PASSED
tests/test_context.py::test_command_injection_context PASSED
tests/test_context.py::test_hardcoded_secret_context PASSED
tests/test_context.py::test_context_contains_surrounding_lines PASSED
tests/test_context.py::test_context_contains_cwe_guidance PASSED
```

---

# 7. Phase 3 Acceptance Checklist

Phase 3 is complete when:

```text
✅ models.py includes VulnerabilityContext
✅ VulnerabilityFinding has optional context field
✅ context_extractor.py is implemented
✅ ContextEnricher can attach context to findings
✅ Function scope is extracted
✅ Surrounding lines are extracted
✅ Imports are extracted
✅ Variables in scope are extracted
✅ Basic data flow is extracted
✅ CWE guidance is attached
✅ CLI supports --context
✅ Phase 3 tests pass
✅ Code is committed to GitHub
```

---

# 8. Commit Phase 3

Run:

```bash
git add .
git commit -m "feat(phase-3): add context extraction engine for LLM-ready vulnerability context"
```

Push:

```bash
git push
```

If using a feature branch:

```bash
git push origin securepy-ai-phase-3
```

---

# 9. What You Built in Phase 3

You now have:

```text
Vulnerability Finding
        ↓
Context Extraction Engine
        ↓
Function Scope
Surrounding Code
Imports
Variables
Data Flow
Sink
Source
CWE Guidance
```

This is very important because in the next phase, this context will be sent to the local LLM.

Without this phase, the LLM would only see:

```text
Fix SQL Injection.
```

With this phase, the LLM will see:

```text
Fix SQL Injection in this function.
This is the function.
This is the vulnerable variable.
This is the data flow.
This is the secure coding requirement.
```

That is what makes your project research-grade.

---

# 10. What Comes in Phase 4

Phase 4 is:

```text
Local LLM Integration
```

You will connect SecurePy AI to:

```text
Ollama
CodeLlama
DeepSeek Coder
```

Phase 4 will allow:

```bash
securepy-ai scan examples/vulnerable.py --fix
```

The LLM will use the context from Phase 3 to generate patches.

---

Once you complete Phase 3, reply:

```text
Phase 3 done
```

Then I will give you **Phase 4 complete code**, where we integrate the **local LLM remediation engine**.