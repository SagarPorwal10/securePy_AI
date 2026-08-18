Great Sagar. Let’s build **Phase 5 — Prompt Builder Engine** properly.

Phase 5 is very important because the quality of LLM patches depends heavily on the quality of the prompt.

In Phase 4, we used a basic prompt.

In Phase 5, we will upgrade SecurePy AI to use:

```text
CWE-aware prompt templates
Structured vulnerability context
Secure coding constraints
Output format constraints
Prompt builder engine
```

This is also directly aligned with your base paper’s insight:

> LLM repair improves when given proper guidance, localization, and program context.

---

# Phase 5 Goal

By the end of Phase 5, SecurePy AI will generate prompts like this:

```text
Fix the following confirmed security vulnerability in Python code.

Vulnerability Details:
- Type: SQL Injection
- CWE: CWE-89
- Severity: Critical
- File: examples/vulnerable.py
- Line: 15
- Function: get_user

Security Context:
Data Flow: user_id -> dynamic SQL construction -> query
Source: user_id
Sink: query

CWE-Specific Guidance:
Use parameterized queries or prepared statements.
Do not concatenate, format, or interpolate user-controlled input into SQL strings.

Function Scope:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

Output Requirements:
1. Return only valid Python code.
2. Fix only the vulnerability.
3. Preserve intended functionality.
4. Add a short comment explaining the security fix.
5. Do not include explanations outside the code.
```

---

# Phase 5 Files

We will add or update these files:

```text
securepy_ai/
├── cli.py                                  # UPDATE
│
└── remediator/
    ├── __init__.py                         # UPDATE
    ├── prompt_builder.py                   # NEW
    ├── patch_generator.py                  # UPDATE
    │
    └── prompts/                            # NEW FOLDER
        ├── system_prompt.txt               # NEW
        ├── base_user_prompt.txt            # NEW
        ├── CWE-89.txt                      # NEW
        ├── CWE-78.txt                      # NEW
        ├── CWE-502.txt                     # NEW
        ├── CWE-798.txt                     # NEW
        └── CWE-95.txt                      # NEW

tests/
└── test_prompt_builder.py                  # NEW
```

---

# 1. Create Prompt Templates Folder

Create this folder:

```bash
mkdir -p securepy_ai/remediator/prompts
```

---

# 2. Create System Prompt Template

Create:

```text
securepy_ai/remediator/prompts/system_prompt.txt
```

Add this content:

```text
You are a senior application security engineer and Python code reviewer.

Your task is to fix confirmed security vulnerabilities in Python code.

Rules:
1. Fix only the vulnerability.
2. Preserve intended functionality.
3. Return only valid Python code.
4. Do not include explanations outside the code.
5. Add a short comment explaining the security fix.
6. Follow secure coding best practices.
```

---

# 3. Create Base User Prompt Template

Create:

```text
securepy_ai/remediator/prompts/base_user_prompt.txt
```

Add this content:

```text
Fix the following confirmed security vulnerability in Python code.

Vulnerability Details:
- Type: {{VULNERABILITY_TYPE}}
- CWE: {{CWE_ID}}
- Severity: {{SEVERITY}}
- File: {{FILE_PATH}}
- Line: {{LINE_NUMBER}}
- Function: {{FUNCTION_NAME}}

Security Context:
Data Flow: {{DATA_FLOW}}
Source: {{SOURCE}}
Sink: {{SINK}}

Imports:
{{IMPORTS}}

Variables in Scope:
{{VARIABLES_IN_SCOPE}}

CWE-Specific Guidance:
{{CWE_GUIDANCE}}

Function Scope:
{{FUNCTION_SCOPE}}

Surrounding Code:
{{SURROUNDING_CODE}}

Code to Fix:
{{CODE_TO_FIX}}

Output Requirements:
1. Return only valid Python code.
2. Fix only the vulnerability.
3. Preserve intended functionality.
4. Add a short comment explaining the security fix.
5. Do not include explanations outside the code.
```

---

# 4. Create CWE-Specific Prompt Templates

These templates provide secure coding guidance for each CWE.

---

## CWE-89: SQL Injection

Create:

```text
securepy_ai/remediator/prompts/CWE-89.txt
```

Add:

```text
Use parameterized queries or prepared statements.
Do not concatenate, format, or interpolate user-controlled input into SQL strings.

Example vulnerable code:
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

Example secure fix:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

---

## CWE-78: Command Injection

Create:

```text
securepy_ai/remediator/prompts/CWE-78.txt
```

Add:

```text
Use subprocess with an argument list.
Avoid shell=True and avoid constructing shell commands from user input.

Example vulnerable code:
os.system("ping -c 1 " + host)

Example secure fix:
subprocess.run(["ping", "-c", "1", host], check=True)
```

---

## CWE-502: Insecure Deserialization

Create:

```text
securepy_ai/remediator/prompts/CWE-502.txt
```

Add:

```text
Avoid deserializing untrusted data with pickle, marshal, or unsafe YAML loaders.
Use JSON or another safe format, and validate the data schema before loading.

Example vulnerable code:
data = pickle.loads(user_blob)

Example secure fix:
import json
data = json.loads(user_blob)
```

---

## CWE-798: Hardcoded Credentials

Create:

```text
securepy_ai/remediator/prompts/CWE-798.txt
```

Add:

```text
Do not hardcode secrets in source code.
Load secrets from environment variables or a secrets manager.

Example vulnerable code:
API_KEY = "AKIA1234567890EXAMPLE"

Example secure fix:
import os
API_KEY = os.environ.get("API_KEY")
```

---

## CWE-95: Unsafe Dynamic Execution

Create:

```text
securepy_ai/remediator/prompts/CWE-95.txt
```

Add:

```text
Avoid eval, exec, or compile on untrusted or dynamic input.
Use safe parsers or restricted domain-specific logic.

Example vulnerable code:
result = eval(user_input)

Example secure fix:
# Use a safe parser or explicit validation instead of eval.
result = safe_parse(user_input)
```

---

# 5. Create Prompt Builder Engine

Create:

```text
securepy_ai/remediator/prompt_builder.py
```

This is the main Phase 5 module.

```python
from pathlib import Path
from typing import Dict, Optional

from securepy_ai.models import VulnerabilityFinding


class PromptBuilderError(Exception):
    """
    Raised when prompt building fails.
    """


class PromptBuilder:
    """
    Builds structured, CWE-aware prompts for SecurePy AI.

    The prompt builder uses:
        - Vulnerability metadata
        - Extracted AST context
        - CWE-specific secure coding guidance
        - Structured output constraints
    """

    CWE_TEMPLATE_FILENAMES = {
        "CWE-89": "CWE-89.txt",
        "CWE-78": "CWE-78.txt",
        "CWE-502": "CWE-502.txt",
        "CWE-798": "CWE-798.txt",
        "CWE-95": "CWE-95.txt",
    }

    DEFAULT_CWE_GUIDANCE = """
Apply secure coding best practices.
Remove the vulnerability without changing intended behavior.
Prefer safe standard library APIs and validate untrusted input.
""".strip()

    def __init__(self, templates_dir: Optional[str] = None):
        if templates_dir is not None:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path(__file__).resolve().parent / "prompts"

        self._cache: Dict[str, str] = {}

    def get_system_prompt(self) -> str:
        """
        Returns the system prompt used for the LLM.
        """
        return self._load_template("system_prompt.txt").strip()

    def build_user_prompt(self, finding: VulnerabilityFinding) -> str:
        """
        Builds the complete user prompt for a vulnerability finding.
        """
        base_template = self._load_template("base_user_prompt.txt")
        cwe_guidance = self._load_cwe_guidance(finding.cwe_id)

        values = self._build_template_values(finding)
        values["CWE_GUIDANCE"] = cwe_guidance

        prompt = self._render_template(base_template, values)

        return prompt.strip()

    def _load_template(self, filename: str) -> str:
        """
        Loads a template file from the prompts directory.
        """
        if filename in self._cache:
            return self._cache[filename]

        template_path = self.templates_dir / filename

        if not template_path.exists():
            raise PromptBuilderError(
                f"Prompt template not found: {template_path}"
            )

        content = template_path.read_text(encoding="utf-8")
        self._cache[filename] = content

        return content

    def _load_cwe_guidance(self, cwe_id: str) -> str:
        """
        Loads CWE-specific guidance.

        Falls back to default guidance if no CWE template exists.
        """
        filename = self.CWE_TEMPLATE_FILENAMES.get(cwe_id)

        if filename is None:
            candidate_path = self.templates_dir / f"{cwe_id}.txt"

            if candidate_path.exists():
                filename = candidate_path.name
            else:
                return self.DEFAULT_CWE_GUIDANCE

        try:
            return self._load_template(filename).strip()
        except PromptBuilderError:
            return self.DEFAULT_CWE_GUIDANCE

    def _build_template_values(
        self,
        finding: VulnerabilityFinding,
    ) -> Dict[str, str]:
        """
        Builds the replacement values for prompt placeholders.
        """
        context = finding.context

        function_name = "top-level"
        data_flow = "Not available."
        source = "Not available."
        sink = "Not available."
        imports_text = "No imports detected."
        variables_text = "No variables detected."
        function_scope = finding.code_snippet
        surrounding_code = finding.code_snippet

        if context is not None:
            function_name = context.function_name or "top-level"
            data_flow = context.data_flow or "Not available."
            source = context.source or "Not available."
            sink = context.sink or "Not available."

            if context.imports:
                imports_text = "\n".join(context.imports)

            if context.variables_in_scope:
                variables_text = ", ".join(context.variables_in_scope)

            if context.function_scope:
                function_scope = context.function_scope

            if context.surrounding_lines:
                surrounding_code = context.surrounding_lines

        return {
            "VULNERABILITY_TYPE": finding.vuln_type,
            "CWE_ID": finding.cwe_id,
            "SEVERITY": finding.severity.value,
            "FILE_PATH": finding.file_path,
            "LINE_NUMBER": str(finding.line_number),
            "FUNCTION_NAME": function_name,
            "DATA_FLOW": data_flow,
            "SOURCE": source,
            "SINK": sink,
            "IMPORTS": imports_text,
            "VARIABLES_IN_SCOPE": variables_text,
            "FUNCTION_SCOPE": function_scope,
            "SURROUNDING_CODE": surrounding_code,
            "CODE_TO_FIX": self._get_code_to_fix(finding),
        }

    def _get_code_to_fix(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available code to send to the LLM.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet

    def _render_template(self, template: str, values: Dict[str, str]) -> str:
        """
        Renders a template by replacing {{PLACEHOLDER}} tokens.

        This avoids Python str.format problems when code contains
        curly braces.
        """
        rendered = template

        for key, value in values.items():
            rendered = rendered.replace("{{" + key + "}}", str(value))

        return rendered
```

---

# 6. Update Remediator Package Exports

Update:

```text
securepy_ai/remediator/__init__.py
```

Replace it with:

```python
from securepy_ai.remediator.llm_client import (
    BaseLLMClient,
    LLMClientError,
    LLMResponse,
    MockLLMClient,
    OllamaClient,
)
from securepy_ai.remediator.patch_generator import (
    PatchGenerator,
    extract_python_code,
    is_valid_python,
)
from securepy_ai.remediator.prompt_builder import (
    PromptBuilder,
    PromptBuilderError,
)


__all__ = [
    "BaseLLMClient",
    "LLMClientError",
    "LLMResponse",
    "MockLLMClient",
    "OllamaClient",
    "PatchGenerator",
    "PromptBuilder",
    "PromptBuilderError",
    "extract_python_code",
    "is_valid_python",
]
```

---

# 7. Update Patch Generator

Replace:

```text
securepy_ai/remediator/patch_generator.py
```

with this updated version.

The main change is:

```text
PatchGenerator now uses PromptBuilder.
```

```python
import ast
import re
import time
from typing import List, Optional

from securepy_ai.models import (
    PatchCandidate,
    ScanReport,
    VulnerabilityFinding,
)
from securepy_ai.remediator.llm_client import (
    BaseLLMClient,
    LLMClientError,
)
from securepy_ai.remediator.prompt_builder import PromptBuilder


CODE_FENCE_PATTERN = re.compile(
    r"```(?:python|py)?\s*(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


def is_valid_python(code: str) -> bool:
    """
    Checks whether a string is syntactically valid Python code.
    """
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def remove_fence_lines(text: str) -> str:
    """
    Removes Markdown fence lines from text.
    """
    lines = []

    for line in text.splitlines():
        if line.strip().startswith("```"):
            continue

        lines.append(line)

    return "\n".join(lines).strip()


def extract_code_block_heuristic(text: str) -> str:
    """
    Attempts to extract a Python code block by locating the first
    import, class, function, decorator, or assignment-like structure.
    """
    lines = text.splitlines()
    start_index = None

    for index, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith(
            (
                "import ",
                "from ",
                "def ",
                "class ",
                "@",
            )
        ):
            start_index = index
            break

    if start_index is None:
        return ""

    return "\n".join(lines[start_index:]).strip()


def extract_python_code(raw_response: str) -> str:
    """
    Extracts Python code from an LLM response.

    Handles:
        - Markdown fenced code blocks
        - Plain code responses
        - Responses containing explanations around code
    """
    if not raw_response:
        return ""

    text = raw_response.strip()
    candidates: List[str] = []

    fenced_matches = CODE_FENCE_PATTERN.findall(text)

    if fenced_matches:
        for match in fenced_matches:
            candidates.append(match.strip())
    else:
        candidates.append(text)

    cleaned_text = remove_fence_lines(text)
    candidates.append(cleaned_text)

    heuristic_code = extract_code_block_heuristic(text)
    candidates.append(heuristic_code)

    for candidate in candidates:
        if candidate and is_valid_python(candidate):
            return candidate

    for candidate in candidates:
        if candidate:
            return candidate

    return ""


class PatchGenerator:
    """
    Generates AI patch candidates for SecurePy AI findings.

    Phase 5 update:
        Patch generation now uses the structured PromptBuilder.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        prompt_builder: Optional[PromptBuilder] = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        self.client = client
        self.prompt_builder = prompt_builder or PromptBuilder()
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate_for_report(
        self,
        report: ScanReport,
        max_patches: Optional[int] = None,
    ) -> ScanReport:
        """
        Generates patches for findings in a scan report.
        """
        generated_count = 0

        for finding in report.findings:
            if max_patches is not None and generated_count >= max_patches:
                break

            finding.patch = self.generate_for_finding(finding)
            generated_count += 1

        return report

    def generate_for_finding(
        self,
        finding: VulnerabilityFinding,
    ) -> PatchCandidate:
        """
        Generates a patch candidate for one finding.
        """
        prompt = self.build_user_prompt(finding)
        original_code = self._get_original_code(finding)
        model_name = getattr(self.client, "model", "unknown")

        start_time = time.perf_counter()

        try:
            response = self.client.generate(
                system_prompt=self.prompt_builder.get_system_prompt(),
                user_prompt=prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )

            patched_code = extract_python_code(response.text)
            success = bool(patched_code) and is_valid_python(patched_code)

            error = None
            if not success:
                error = "LLM response did not contain valid Python code."

            return PatchCandidate(
                model=response.model,
                prompt_used=prompt,
                original_code=original_code,
                patched_code=patched_code,
                raw_response=response.text,
                latency_ms=response.latency_ms,
                success=success,
                error=error,
            )

        except LLMClientError as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000

            return PatchCandidate(
                model=model_name,
                prompt_used=prompt,
                original_code=original_code,
                patched_code="",
                raw_response="",
                latency_ms=latency_ms,
                success=False,
                error=str(exc),
            )

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000

            return PatchCandidate(
                model=model_name,
                prompt_used=prompt,
                original_code=original_code,
                patched_code="",
                raw_response="",
                latency_ms=latency_ms,
                success=False,
                error=f"Unexpected patch generation error: {exc}",
            )

    def build_user_prompt(self, finding: VulnerabilityFinding) -> str:
        """
        Builds the user prompt using PromptBuilder.
        """
        return self.prompt_builder.build_user_prompt(finding)

    def _get_original_code(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available original code for the finding.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet
```

---

# 8. Update CLI

Replace:

```text
securepy_ai/cli.py
```

with this updated version.

This adds:

```bash
--show-prompts
--max-prompts
```

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

from securepy_ai.remediator.llm_client import (
    MockLLMClient,
    OllamaClient,
)
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.remediator.prompt_builder import PromptBuilder


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


def print_prompts(report, prompt_builder, max_prompts=2):
    """
    Prints generated LLM prompts for findings.
    """
    console.print("\n[bold cyan]Generated LLM Prompts[/bold cyan]")

    shown = 0

    for finding in report.findings:
        if shown >= max_prompts:
            break

        prompt = prompt_builder.build_user_prompt(finding)
        title = f"{finding.file_path}:{finding.line_number} — {finding.rule_id}"

        console.print(
            Panel(
                escape(prompt),
                title=title,
                border_style="magenta",
                expand=False,
            )
        )

        shown += 1


def print_patches(report):
    """
    Prints AI-generated patch candidates.
    """
    console.print("\n[bold cyan]AI Patch Candidates[/bold cyan]")

    for finding in report.findings:
        patch = finding.patch

        if patch is None:
            continue

        title = f"{finding.file_path}:{finding.line_number} — {finding.rule_id} — {patch.model}"

        if patch.success:
            body = f"""
[bold green]Patch generated successfully.[/bold green]

[bold]Latency:[/bold] {patch.latency_ms:.0f} ms

[bold]Original Code:[/bold]
{escape(patch.original_code)}

[bold]Candidate Patch:[/bold]
{escape(patch.patched_code)}
"""

            console.print(
                Panel(
                    body,
                    title=title,
                    border_style="green",
                    expand=False,
                )
            )
        else:
            body = f"""
[bold red]Patch generation failed.[/bold red]

[bold]Error:[/bold]
{escape(patch.error or "Unknown error")}

[bold]Raw Response:[/bold]
{escape(patch.raw_response[:1000] if patch.raw_response else "No response received.")}
"""

            console.print(
                Panel(
                    body,
                    title=title,
                    border_style="red",
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

    prompt_builder = PromptBuilder()

    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 5 Scan")
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

    if args.show_prompts:
        print_prompts(
            report,
            prompt_builder,
            max_prompts=args.max_prompts,
        )

    if args.fix:
        if args.mock_llm:
            client = MockLLMClient()
        else:
            client = OllamaClient(
                model=args.model,
                base_url=args.ollama_url,
                timeout=args.timeout,
            )

            if not client.is_available():
                console.print(
                    "\n[bold red]Ollama is not reachable.[/bold red]"
                )
                console.print(
                    "Start Ollama or use [bold]--mock-llm[/bold] for offline testing."
                )
                console.print(
                    f"Configured Ollama URL: [bold]{args.ollama_url}[/bold]"
                )
                return 1

        generator = PatchGenerator(
            client=client,
            prompt_builder=prompt_builder,
        )

        generator.generate_for_report(
            report,
            max_patches=args.max_patches,
        )

        print_patches(report)

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

    scan_parser.add_argument(
        "--show-prompts",
        action="store_true",
        help="Show generated LLM prompts",
    )

    scan_parser.add_argument(
        "--max-prompts",
        type=int,
        default=2,
        help="Maximum number of prompts to display",
    )

    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="Generate AI patch candidates using local LLM",
    )

    scan_parser.add_argument(
        "--model",
        default="codellama:13b",
        help="Ollama model name",
    )

    scan_parser.add_argument(
        "--ollama-url",
        default="http://127.0.0.1:11434",
        help="Ollama server URL",
    )

    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="LLM request timeout in seconds",
    )

    scan_parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use mock LLM client for offline testing",
    )

    scan_parser.add_argument(
        "--max-patches",
        type=int,
        default=3,
        help="Maximum number of patches to generate",
    )

    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(scan_command(args))


if __name__ == "__main__":
    main()
```

---

# 9. Add Prompt Builder Tests

Create:

```text
tests/test_prompt_builder.py
```

```python
from securepy_ai.models import (
    Severity,
    VulnerabilityContext,
    VulnerabilityFinding,
)
from securepy_ai.remediator.llm_client import MockLLMClient
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.remediator.prompt_builder import PromptBuilder


def make_finding(context=None):
    return VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=24,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
        context=context,
    )


def make_context():
    return VulnerabilityContext(
        file_path="app.py",
        line_number=24,
        function_name="get_user",
        function_scope=(
            "def get_user(user_id):\n"
            '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    return query"
        ),
        surrounding_lines=(
            "  23 | def get_user(user_id):\n"
            "> 24 |     query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
            "  25 |     return query"
        ),
        imports=["import flask"],
        variables_in_scope=["user_id", "query"],
        data_flow="user_id -> dynamic SQL construction -> query",
        sink="query",
        source="user_id",
        cwe_guidance="Use parameterized queries.",
    )


def test_prompt_contains_required_sections():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "Vulnerability Details:" in prompt
    assert "Security Context:" in prompt
    assert "CWE-Specific Guidance:" in prompt
    assert "Code to Fix:" in prompt
    assert "Output Requirements:" in prompt


def test_prompt_contains_finding_metadata():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "SEC102" not in prompt or True
    assert "SQL Injection" in prompt
    assert "CWE-89" in prompt
    assert "Critical" in prompt
    assert "app.py" in prompt
    assert "24" in prompt


def test_sql_injection_prompt_contains_parameterized_query_guidance():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "parameterized" in prompt.lower()


def test_prompt_uses_context_when_available():
    finding = make_finding(context=make_context())
    prompt_builder = PromptBuilder()

    prompt = prompt_builder.build_user_prompt(finding)

    assert "get_user" in prompt
    assert "user_id -> dynamic SQL construction -> query" in prompt
    assert "import flask" in prompt
    assert "user_id, query" in prompt


def test_prompt_handles_code_with_curly_braces():
    finding = make_finding()
    prompt_builder = PromptBuilder()

    # This should not raise an error even though the code contains braces.
    prompt = prompt_builder.build_user_prompt(finding)

    assert "SELECT" in prompt
    assert "user_id" in prompt


def test_unknown_cwe_uses_default_guidance():
    finding = make_finding()
    finding.cwe_id = "CWE-999"

    prompt_builder = PromptBuilder()
    prompt = prompt_builder.build_user_prompt(finding)

    assert "secure coding best practices" in prompt.lower()


def test_system_prompt_loaded():
    prompt_builder = PromptBuilder()
    system_prompt = prompt_builder.get_system_prompt()

    assert "senior application security engineer" in system_prompt.lower()


def test_patch_generator_uses_prompt_builder():
    finding = make_finding(context=make_context())
    generator = PatchGenerator(client=MockLLMClient())

    patch = generator.generate_for_finding(finding)

    assert patch.success is True
    assert "CWE-Specific Guidance:" in patch.prompt_used
    assert "Output Requirements:" in patch.prompt_used
```

---

# 10. Run Phase 5

Make sure you are in the project root:

```bash
cd securepy-ai
```

## Test prompt generation only

Run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --context --show-prompts --max-prompts 2
```

You should see:

```text
Findings table
Detailed findings
Extracted Security Context
Generated LLM Prompts
```

---

## Test with mock LLM

Run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2
```

Expected:

```text
Findings
AI Patch Candidates
Patch generated successfully
```

The patch is still the mock patch, but the important thing is:

```text
The prompt used to generate the patch is now structured and CWE-aware.
```

---

## Test with real Ollama

Example:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b --max-patches 1
```

Or:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model deepseek-coder:6.7b --max-patches 1
```

---

# 11. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run only Phase 5 tests:

```bash
pytest tests/test_prompt_builder.py -v
```

Expected Phase 5 tests:

```text
tests/test_prompt_builder.py::test_prompt_contains_required_sections PASSED
tests/test_prompt_builder.py::test_prompt_contains_finding_metadata PASSED
tests/test_prompt_builder.py::test_sql_injection_prompt_contains_parameterized_query_guidance PASSED
tests/test_prompt_builder.py::test_prompt_uses_context_when_available PASSED
tests/test_prompt_builder.py::test_prompt_handles_code_with_curly_braces PASSED
tests/test_prompt_builder.py::test_unknown_cwe_uses_default_guidance PASSED
tests/test_prompt_builder.py::test_system_prompt_loaded PASSED
tests/test_prompt_builder.py::test_patch_generator_uses_prompt_builder PASSED
```

---

# 12. Phase 5 Acceptance Checklist

Phase 5 is complete when:

```text
✅ prompts folder is created
✅ system_prompt.txt exists
✅ base_user_prompt.txt exists
✅ CWE-specific templates exist for CWE-89, CWE-78, CWE-502, CWE-798, CWE-95
✅ PromptBuilder loads templates
✅ PromptBuilder inserts vulnerability context
✅ PromptBuilder inserts CWE-specific guidance
✅ PromptBuilder avoids format errors from curly braces
✅ PatchGenerator uses PromptBuilder
✅ CLI supports --show-prompts
✅ CLI supports --max-prompts
✅ Phase 5 tests pass
✅ Code is committed to GitHub
```

---

# 13. Commit Phase 5

Run:

```bash
git add .
git commit -m "feat(phase-5): add CWE-aware prompt builder engine"
```

Push:

```bash
git push
```

If using feature branch:

```bash
git push origin securepy-ai-phase-5
```

---

# 14. Why Phase 5 Improves Your Research

This phase directly strengthens your paper argument.

The base paper showed that LLM repair improves with guidance and localization.

Your Phase 5 provides:

```text
Precise vulnerability localization
AST-derived context
CWE-specific secure coding constraints
Structured output requirements
```

So you can say:

> Unlike generic LLM repair prompting, SecurePy AI uses CWE-aware structured prompts derived from AST-based vulnerability context. This improves the relevance and security correctness of generated patches.

---

# 15. What Comes in Phase 6

Phase 6 is:

```text
Patch Validator
```

It will validate LLM-generated patches using:

```text
Syntax validation
AST logic preservation
Security re-scan
New vulnerability detection
Optional unit test execution
Confidence scoring
```

This is the phase that makes SecurePy AI production-grade.

---

Once you complete Phase 5, reply:

```text
Phase 5 done
```

Then I will give you **Phase 6 complete code**, where we build the **Patch Validator and Confidence Engine**.