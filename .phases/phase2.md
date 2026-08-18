# Phase 2 — Complete Code in Detail

Sagar, Phase 2 is where SecurePy AI becomes a real SAST engine.

In Phase 1, we built:

```text
AST Parser + Hardcoded Secret Rule + CLI
```

In Phase 2, we will build:

```text
Security Rules Engine
```

After Phase 2, SecurePy AI will detect:

```text
SEC101 → Hardcoded Secret
SEC102 → SQL Injection
SEC103 → Command Injection
SEC104 → Insecure Deserialization
SEC105 → Unsafe eval/exec
```

---

# Phase 2 Objective

By the end of Phase 2, this command:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

should detect multiple vulnerability types.

---

# Files We Will Add or Update in Phase 2

```text
securepy_ai/
│
├── cli.py                                  # UPDATE
│
└── scanner/
    ├── utils.py                            # NEW
    │
    └── rules/
        ├── __init__.py                     # UPDATE
        ├── base_rule.py                    # SAME AS PHASE 1
        ├── hardcoded_secret.py             # SAME AS PHASE 1
        ├── sql_injection.py                # NEW
        ├── command_injection.py            # NEW
        ├── insecure_deserialization.py     # NEW
        └── unsafe_exec_eval.py             # NEW

examples/
└── vulnerable.py                           # UPDATE

tests/
└── test_rules.py                           # NEW
```

Keep these Phase 1 files unchanged:

```text
securepy_ai/models.py
securepy_ai/scanner/ast_parser.py
securepy_ai/scanner/rules/base_rule.py
securepy_ai/scanner/rules/hardcoded_secret.py
```

If you do not have them, complete Phase 1 first.

---

# 1. Create Utility Helpers

Create this file:

```text
securepy_ai/scanner/utils.py
```

This file contains reusable AST helper functions.

```python
import ast
import re
from typing import Optional


SQL_KEYWORD_PATTERN = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE|UNION)\b",
    re.IGNORECASE,
)


def get_call_name(call: ast.Call) -> str:
    """
    Returns the dotted name of a function call.

    Examples:
        os.system(...)       -> "os.system"
        subprocess.run(...)  -> "subprocess.run"
        pickle.loads(...)    -> "pickle.loads"
        eval(...)            -> "eval"
    """
    parts = []
    func = call.func

    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value

    if isinstance(func, ast.Name):
        parts.append(func.id)

    return ".".join(reversed(parts))


def is_static_string(node: Optional[ast.AST]) -> bool:
    """
    Checks whether a node is a plain string constant.
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def extract_static_string(node: Optional[ast.AST]) -> str:
    """
    Extracts static string content from an AST node.

    This is useful for f-strings, concatenations, and constant strings.
    """
    if node is None:
        return ""

    if is_static_string(node):
        return node.value

    if isinstance(node, ast.JoinedStr):
        return "".join(extract_static_string(value) for value in node.values)

    if isinstance(node, ast.FormattedValue):
        return ""

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return extract_static_string(node.left) + extract_static_string(node.right)

    return ""


def has_formatted_value(node: Optional[ast.AST]) -> bool:
    """
    Checks whether an f-string contains dynamic interpolated values.
    """
    return isinstance(node, ast.JoinedStr) and any(
        isinstance(value, ast.FormattedValue)
        for value in node.values
    )


def contains_sql_keyword(text: str) -> bool:
    """
    Checks whether a string contains SQL keywords.
    """
    return bool(SQL_KEYWORD_PATTERN.search(text or ""))


def is_dynamic_expression(node: Optional[ast.AST]) -> bool:
    """
    Checks whether an expression appears dynamic.

    Constants are considered static.
    Names, calls, attributes, formatted f-strings, and non-constant
    binary operations are considered dynamic.
    """
    if node is None:
        return False

    if isinstance(node, ast.Constant):
        return False

    if isinstance(node, ast.JoinedStr):
        return has_formatted_value(node)

    if isinstance(node, ast.BinOp):
        return is_dynamic_expression(node.left) or is_dynamic_expression(node.right)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(is_dynamic_expression(element) for element in node.elts)

    if isinstance(node, ast.Dict):
        dict_parts = []

        for key in node.keys:
            if key is not None:
                dict_parts.append(key)

        for value in node.values:
            if value is not None:
                dict_parts.append(value)

        return any(is_dynamic_expression(part) for part in dict_parts)

    return True


def has_shell_true(call: ast.Call) -> bool:
    """
    Checks whether a subprocess-style call uses shell=True.
    """
    for keyword in call.keywords:
        if keyword.arg == "shell":
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return True

    return False


def get_keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    """
    Returns the value of a keyword argument from a Call node.
    """
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value

    return None
```

---

# 2. Update Rules Package

Update this file:

```text
securepy_ai/scanner/rules/__init__.py
```

Replace its content with:

```python
from securepy_ai.scanner.rules.hardcoded_secret import HardcodedSecretRule
from securepy_ai.scanner.rules.sql_injection import SQLInjectionRule
from securepy_ai.scanner.rules.command_injection import CommandInjectionRule
from securepy_ai.scanner.rules.insecure_deserialization import InsecureDeserializationRule
from securepy_ai.scanner.rules.unsafe_exec_eval import UnsafeExecEvalRule


ALL_RULES = [
    HardcodedSecretRule,
    SQLInjectionRule,
    CommandInjectionRule,
    InsecureDeserializationRule,
    UnsafeExecEvalRule,
]
```

---

# 3. SQL Injection Rule

Create this file:

```text
securepy_ai/scanner/rules/sql_injection.py
```

This rule detects dynamic SQL construction using:

```text
f-strings
string concatenation
% formatting
.format()
direct dynamic execute() calls
```

```python
import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class SQLInjectionRule(BaseRule):
    """
    Detects possible SQL injection vulnerabilities.

    Detected patterns include:
        query = f"SELECT * FROM users WHERE id = {user_id}"
        query = "SELECT * FROM users WHERE id = " + user_id
        query = "SELECT * FROM users WHERE id = %s" % user_id
        query = "SELECT * FROM users WHERE id = {}".format(user_id)
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    """

    rule_id = "SEC102"
    vuln_type = "SQL Injection"
    cwe_id = "CWE-89"
    severity = Severity.CRITICAL

    def visit(self, node: ast.AST) -> None:
        """
        Visits assignments and calls to detect dynamic SQL construction.
        """
        if isinstance(node, ast.Assign):
            if self._is_dynamic_sql(node.value):
                self.add_finding(
                    node,
                    "Dynamic SQL query construction detected. Use parameterized queries.",
                )

        elif isinstance(node, ast.Call):
            if self._is_execute_call(node) and node.args:
                if self._is_dynamic_sql(node.args[0]):
                    self.add_finding(
                        node,
                        "Dynamic SQL query passed to database execute method. Use parameterized queries.",
                    )

    def _is_execute_call(self, call: ast.Call) -> bool:
        """
        Checks whether the call looks like a database execute call.
        """
        call_name = utils.get_call_name(call).lower()

        if not call_name:
            return False

        return (
            call_name.endswith(".execute")
            or call_name.endswith(".executemany")
            or call_name in {"execute", "executemany"}
        )

    def _is_dynamic_sql(self, node: ast.AST) -> bool:
        """
        Checks whether an expression looks like a dynamically built SQL query.
        """
        if node is None:
            return False

        # Case 1: f-string SQL query
        # Example:
        # query = f"SELECT * FROM users WHERE id = {user_id}"
        if isinstance(node, ast.JoinedStr):
            return (
                utils.has_formatted_value(node)
                and utils.contains_sql_keyword(utils.extract_static_string(node))
            )

        # Case 2: concatenation or % formatting
        # Example:
        # query = "SELECT * FROM users WHERE id = " + user_id
        # query = "SELECT * FROM users WHERE id = %s" % user_id
        if isinstance(node, ast.BinOp):
            static_text = utils.extract_static_string(node)

            if not utils.contains_sql_keyword(static_text):
                return False

            if isinstance(node.op, (ast.Add, ast.Mod)):
                return utils.is_dynamic_expression(node)

            return False

        # Case 3: .format()
        # Example:
        # query = "SELECT * FROM users WHERE id = {}".format(user_id)
        if isinstance(node, ast.Call):
            call_name = utils.get_call_name(node)

            if call_name == "format" or call_name.endswith(".format"):
                if not isinstance(node.func, ast.Attribute):
                    return False

                base_text = utils.extract_static_string(node.func.value)

                if not utils.contains_sql_keyword(base_text):
                    return False

                return self._has_dynamic_arguments(node)

        return False

    def _has_dynamic_arguments(self, call: ast.Call) -> bool:
        """
        Checks whether a call has dynamic positional or keyword arguments.
        """
        dynamic_positional_args = any(
            utils.is_dynamic_expression(arg)
            for arg in call.args
        )

        dynamic_keyword_args = any(
            utils.is_dynamic_expression(keyword.value)
            for keyword in call.keywords
        )

        return dynamic_positional_args or dynamic_keyword_args
```

---

# 4. Command Injection Rule

Create this file:

```text
securepy_ai/scanner/rules/command_injection.py
```

This rule detects dangerous command execution patterns such as:

```python
os.system("ping -c 1 " + host)
subprocess.call(command, shell=True)
```

```python
import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class CommandInjectionRule(BaseRule):
    """
    Detects possible OS command injection vulnerabilities.

    Detected patterns include:
        os.system("ping -c 1 " + host)
        os.popen(user_input)
        subprocess.call(command, shell=True)
        subprocess.run(f"ls {directory}", shell=True)
    """

    rule_id = "SEC103"
    vuln_type = "Command Injection"
    cwe_id = "CWE-78"
    severity = Severity.HIGH

    OS_COMMAND_CALLS = {
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
    }

    SUBPROCESS_CALLS = {
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }

    SHORT_OS_COMMAND_CALLS = {
        "system",
        "popen",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and checks for dangerous command execution patterns.
        """
        if not isinstance(node, ast.Call):
            return

        if not node.args:
            return

        call_name = utils.get_call_name(node)
        command_argument = node.args[0]

        # Case 1:
        # os.system("ping -c 1 " + host)
        # os.popen(user_input)
        if call_name in self.OS_COMMAND_CALLS or call_name in self.SHORT_OS_COMMAND_CALLS:
            if utils.is_dynamic_expression(command_argument):
                self.add_finding(
                    node,
                    "Dynamic command passed to OS command execution function. "
                    "Avoid shell string construction and use safe argument lists.",
                )

        # Case 2:
        # subprocess.call(command, shell=True)
        # subprocess.run(f"ls {directory}", shell=True)
        elif call_name in self.SUBPROCESS_CALLS:
            if utils.has_shell_true(node) and utils.is_dynamic_expression(command_argument):
                self.add_finding(
                    node,
                    "Dynamic command used with subprocess and shell=True. "
                    "Use subprocess with a list of arguments and avoid shell=True.",
                )
```

---

# 5. Insecure Deserialization Rule

Create this file:

```text
securepy_ai/scanner/rules/insecure_deserialization.py
```

This rule detects unsafe deserialization using:

```python
pickle.loads()
pickle.load()
marshal.loads()
shelve.open()
yaml.load()
```

```python
import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class InsecureDeserializationRule(BaseRule):
    """
    Detects insecure deserialization patterns.

    Detected patterns include:
        pickle.loads(user_data)
        pickle.load(file)
        marshal.loads(data)
        shelve.open(filename)
        yaml.load(data)

    Safe pattern:
        yaml.load(data, Loader=yaml.SafeLoader)
    """

    rule_id = "SEC104"
    vuln_type = "Insecure Deserialization"
    cwe_id = "CWE-502"
    severity = Severity.HIGH

    DANGEROUS_CALLS = {
        "pickle.loads",
        "pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "_pickle.loads",
        "_pickle.load",
        "marshal.loads",
        "shelve.open",
        "dill.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "yaml.full_load",
    }

    YAML_CALLS = {
        "yaml.load",
        "yaml.unsafe_load",
        "yaml.full_load",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and detects unsafe deserialization calls.
        """
        if not isinstance(node, ast.Call):
            return

        call_name = utils.get_call_name(node)

        if call_name not in self.DANGEROUS_CALLS:
            return

        if call_name in self.YAML_CALLS and self._has_safe_loader(node):
            return

        self.add_finding(
            node,
            f"Unsafe deserialization using {call_name}. "
            "Use a safe serialization format or a safe loader.",
        )

    def _has_safe_loader(self, call: ast.Call) -> bool:
        """
        Checks whether yaml.load is called with a safe loader.
        """
        loader = utils.get_keyword(call, "Loader")

        if loader is None:
            return False

        loader_name = self._get_loader_name(loader)

        return (
            "SafeLoader" in loader_name
            or "CSafeLoader" in loader_name
        )

    def _get_loader_name(self, node: ast.AST) -> str:
        """
        Extracts a readable name from the Loader keyword value.
        """
        if isinstance(node, ast.Attribute):
            return node.attr

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Call):
            return utils.get_call_name(node)

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        return ""
```

---

# 6. Unsafe eval/exec Rule

Create this file:

```text
securepy_ai/scanner/rules/unsafe_exec_eval.py
```

This rule detects dynamic code execution using:

```python
eval(user_input)
exec(user_code)
compile(user_code, ...)
```

```python
import ast

from securepy_ai.models import Severity
from securepy_ai.scanner.rules.base_rule import BaseRule
from securepy_ai.scanner import utils


class UnsafeExecEvalRule(BaseRule):
    """
    Detects unsafe dynamic code execution.

    Detected patterns include:
        eval(user_input)
        exec(user_code)
        compile(user_code, filename, mode)
    """

    rule_id = "SEC105"
    vuln_type = "Unsafe Dynamic Execution"
    cwe_id = "CWE-95"
    severity = Severity.HIGH

    DANGEROUS_CALLS = {
        "eval",
        "exec",
        "compile",
    }

    def visit(self, node: ast.AST) -> None:
        """
        Visits Call nodes and detects eval/exec/compile usage.
        """
        if not isinstance(node, ast.Call):
            return

        if not node.args:
            return

        call_name = utils.get_call_name(node)

        if call_name not in self.DANGEROUS_CALLS:
            return

        first_argument = node.args[0]

        if utils.is_dynamic_expression(first_argument):
            self.add_finding(
                node,
                f"Dynamic code execution using {call_name}(). "
                "Avoid executing untrusted or dynamically constructed code.",
            )
```

---

# 7. Update CLI

Update this file:

```text
securepy_ai/cli.py
```

Replace its content with this updated version.

```python
import argparse

from rich.console import Console
from rich.table import Table

from securepy_ai import __version__
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules import ALL_RULES


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
    scanner = SecurePyParser(rules=ALL_RULES)
    report = scanner.scan_path(args.target)

    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 2 Scan")
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

# 8. Update Vulnerable Example

Update this file:

```text
examples/vulnerable.py
```

Replace it with this:

```python
import os
import pickle
import subprocess
import yaml


password = "admin123"
api_key = "AKIA923848239482394"
db_secret = "supersecret123"

username = "sagar"


def get_user(user_id):
    # SEC102: SQL injection using f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query


def search_user(name):
    # SEC102: SQL injection using % formatting
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return query


def run_ping(host):
    # SEC103: Command injection using os.system
    os.system("ping -c 1 " + host)


def run_shell_command(command):
    # SEC103: Command injection using subprocess with shell=True
    subprocess.call(command, shell=True)


def load_session(session_blob):
    # SEC104: Insecure deserialization using pickle
    return pickle.loads(session_blob)


def load_yaml_config(config_data):
    # SEC104: Insecure deserialization using yaml.load
    return yaml.load(config_data)


def calculate(expression):
    # SEC105: Unsafe dynamic execution using eval
    return eval(expression)
```

---

# 9. Add Phase 2 Tests

Create this file:

```text
tests/test_rules.py
```

```python
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.rules import (
    HardcodedSecretRule,
    SQLInjectionRule,
    CommandInjectionRule,
    InsecureDeserializationRule,
    UnsafeExecEvalRule,
)


def scan_code(tmp_path, code, rule):
    """
    Helper function to scan code using one rule.
    """
    file_path = tmp_path / "sample.py"
    file_path.write_text(code, encoding="utf-8")

    scanner = SecurePyParser(rules=[rule])
    return scanner.scan_path(str(file_path))


def test_hardcoded_secret(tmp_path):
    code = '''
password = "admin123"
'''

    report = scan_code(tmp_path, code, HardcodedSecretRule)

    assert report.files_scanned == 1
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC101"
    assert report.findings[0].cwe_id == "CWE-798"


def test_sql_injection_fstring(tmp_path):
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC102"
    assert report.findings[0].cwe_id == "CWE-89"


def test_sql_injection_percent_format(tmp_path):
    code = '''
def search_user(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return query
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC102"


def test_sql_injection_safe_parameterized_query(tmp_path):
    code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''

    report = scan_code(tmp_path, code, SQLInjectionRule)

    assert len(report.findings) == 0


def test_command_injection_os_system(tmp_path):
    code = '''
import os

def run_ping(host):
    os.system("ping -c 1 " + host)
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC103"
    assert report.findings[0].cwe_id == "CWE-78"


def test_command_injection_subprocess_shell_true(tmp_path):
    code = '''
import subprocess

def run(command):
    subprocess.call(command, shell=True)
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC103"


def test_command_injection_safe_constant_command(tmp_path):
    code = '''
import os

def list_files():
    os.system("ls -la")
'''

    report = scan_code(tmp_path, code, CommandInjectionRule)

    assert len(report.findings) == 0


def test_insecure_deserialization_pickle(tmp_path):
    code = '''
import pickle

def load_session(session_blob):
    return pickle.loads(session_blob)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC104"
    assert report.findings[0].cwe_id == "CWE-502"


def test_yaml_load_safe_loader(tmp_path):
    code = '''
import yaml

def load_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 0


def test_safe_json_loads(tmp_path):
    code = '''
import json

def load(data):
    return json.loads(data)
'''

    report = scan_code(tmp_path, code, InsecureDeserializationRule)

    assert len(report.findings) == 0


def test_unsafe_eval(tmp_path):
    code = '''
def calculate(expression):
    return eval(expression)
'''

    report = scan_code(tmp_path, code, UnsafeExecEvalRule)

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "SEC105"
    assert report.findings[0].cwe_id == "CWE-95"


def test_safe_eval_constant(tmp_path):
    code = '''
def calculate():
    return eval("1 + 1")
'''

    report = scan_code(tmp_path, code, UnsafeExecEvalRule)

    assert len(report.findings) == 0
```

---

# 10. Run the Scanner

Make sure you are in the project root:

```bash
cd securepy-ai
```

Run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

You should see findings similar to:

```text
SecurePy AI v0.1.0 — Phase 2 Scan
Target: examples/vulnerable.py
Files scanned: 1

Findings:
SEC101 | CWE-798 | Hardcoded Secret
SEC101 | CWE-798 | Hardcoded Secret
SEC101 | CWE-798 | Hardcoded Secret
SEC102 | CWE-89  | SQL Injection
SEC102 | CWE-89  | SQL Injection
SEC103 | CWE-78  | Command Injection
SEC103 | CWE-78  | Command Injection
SEC104 | CWE-502 | Insecure Deserialization
SEC104 | CWE-502 | Insecure Deserialization
SEC105 | CWE-95  | Unsafe Dynamic Execution
```

Expected total:

```text
Total findings: 10
```

---

# 11. Run Tests

Run:

```bash
pytest tests/ -v
```

Expected result:

```text
tests/test_rules.py::test_hardcoded_secret PASSED
tests/test_rules.py::test_sql_injection_fstring PASSED
tests/test_rules.py::test_sql_injection_percent_format PASSED
tests/test_rules.py::test_sql_injection_safe_parameterized_query PASSED
tests/test_rules.py::test_command_injection_os_system PASSED
tests/test_rules.py::test_command_injection_subprocess_shell_true PASSED
tests/test_rules.py::test_command_injection_safe_constant_command PASSED
tests/test_rules.py::test_insecure_deserialization_pickle PASSED
tests/test_rules.py::test_yaml_load_safe_loader PASSED
tests/test_rules.py::test_safe_json_loads PASSED
tests/test_rules.py::test_unsafe_eval PASSED
tests/test_rules.py::test_safe_eval_constant PASSED
```

---

# 12. Phase 2 Acceptance Checklist

Phase 2 is complete when:

```text
✅ utils.py is added
✅ SQLInjectionRule works
✅ CommandInjectionRule works
✅ InsecureDeserializationRule works
✅ UnsafeExecEvalRule works
✅ ALL_RULES is exported from rules/__init__.py
✅ CLI uses ALL_RULES
✅ examples/vulnerable.py produces multiple findings
✅ pytest tests pass
✅ Code is committed to GitHub
```

---

# 13. Commit Phase 2

Run:

```bash
git add .
git commit -m "feat(phase-2): add security rules engine for SQLi, command injection, deserialization, and eval/exec"
```

Push:

```bash
git push
```

If you are using a feature branch:

```bash
git push origin securepy-ai-phase-2
```

---

# 14. What You Built in Phase 2

You now have a proper rule-based SAST engine:

```text
Python Code
    ↓
AST Parser
    ↓
Rule Engine
    ↓
SEC101 Hardcoded Secret
SEC102 SQL Injection
SEC103 Command Injection
SEC104 Insecure Deserialization
SEC105 Unsafe eval/exec
    ↓
Findings
    ↓
Rich CLI Report
```

This is a strong foundation for your resume.

---

# 15. Known Limitations After Phase 2

This is important for your thesis and viva.

SecurePy AI currently does:

```text
✅ Pattern-based AST detection
✅ CWE classification
✅ Severity classification
✅ Multi-rule scanning
```

But it does not yet do:

```text
❌ Full taint tracking
❌ Inter-procedural data-flow analysis
❌ LLM remediation
❌ Patch validation
❌ Context-aware prompt generation
```

Those will come in later phases.

---

# 16. What Comes in Phase 3

Phase 3 is:

```text
Context Extraction Engine
```

It will extract:

```text
Parent function
Surrounding code
Imports
Data flow
Sink/source relationship
CWE-aware context
```

This context will later be sent to the local LLM.

Example Phase 3 output:

```text
Vulnerability Type: SQL Injection
CWE: CWE-89
Severity: Critical
File: examples/vulnerable.py
Line: 15

Function Scope:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

Data Flow:
user_id -> f-string -> SQL query
```

---

# Your Next Task

Complete Phase 2:

```text
1. Add utils.py
2. Add SQLInjectionRule
3. Add CommandInjectionRule
4. Add InsecureDeserializationRule
5. Add UnsafeExecEvalRule
6. Update rules/__init__.py
7. Update cli.py
8. Update examples/vulnerable.py
9. Run scan
10. Run pytest
11. Commit
```

Once done, reply:

```text
Phase 2 done
```

Then I will give you **Phase 3 complete code**, where we build the **Context Extraction Engine**.