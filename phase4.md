Excellent, Sagar. Since **Phase 3 is done**, now we build:

# Phase 4 — Local LLM Integration

This is where SecurePy AI starts becoming an **AI-powered remediation engine**, not just a scanner.

After Phase 4, SecurePy AI will be able to:

```text
1. Detect vulnerabilities
2. Extract security context
3. Send context to a local LLM
4. Receive a candidate patch
5. Display the patch in CLI
```

At the end of Phase 4, you will run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm
```

and later with Ollama:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b
```

---

# Phase 4 Goal

Build these components:

```text
LLM Client
    ↓
Ollama Client
    ↓
Mock LLM Client
    ↓
Patch Generator
    ↓
Patch Candidate Model
    ↓
CLI --fix mode
```

---

# Files We Will Add or Update in Phase 4

```text
securepy_ai/
├── models.py                         # UPDATE
├── cli.py                            # UPDATE
│
└── remediator/                       # NEW PACKAGE
    ├── __init__.py                   # NEW
    ├── llm_client.py                 # NEW
    └── patch_generator.py            # NEW

tests/
└── test_llm.py                       # NEW
```

Keep these unchanged:

```text
securepy_ai/scanner/ast_parser.py
securepy_ai/scanner/utils.py
securepy_ai/scanner/context_extractor.py
securepy_ai/scanner/rules/
examples/vulnerable.py
```

---

# 1. Install Ollama

Ollama lets you run LLMs locally.

This is important because SecurePy AI must not send source code to a cloud API.

## Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

## Windows

Download Ollama from:

```text
https://ollama.com/download
```

Install it normally.

---

# 2. Pull a Local Code Model

For Phase 4, start with one model.

Recommended:

```bash
ollama pull codellama:13b
```

If your system has low RAM, use:

```bash
ollama pull deepseek-coder:6.7b
```

or:

```bash
ollama pull qwen2.5-coder:7b
```

Check installed models:

```bash
ollama list
```

Expected output should include something like:

```text
NAME                 ID              SIZE
codellama:13b        xxxxxxxxxxxx    7.4 GB
```

Test Ollama API:

```bash
curl http://localhost:11434/api/tags
```

If you see JSON output, Ollama is running.

---

# 3. Update `models.py`

Replace the content of:

```text
securepy_ai/models.py
```

with this updated version.

We are adding:

```python
PatchCandidate
```

and attaching an optional patch to each finding.

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

    This context is used to build high-quality prompts for the LLM.
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
        Converts the context into structured text for an LLM prompt.
        """
        imports_text = "\n".join(self.imports) if self.imports else "No imports detected."
        variables_text = (
            ", ".join(self.variables_in_scope)
            if self.variables_in_scope
            else "No variables detected."
        )

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
class PatchCandidate:
    """
    Represents an AI-generated patch candidate.

    In Phase 4, patches are generated but not yet validated.
    Validation is introduced in Phase 6.
    """

    model: str
    prompt_used: str
    original_code: str
    patched_code: str
    raw_response: str
    latency_ms: float
    success: bool
    error: Optional[str] = None


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
    patch: Optional[PatchCandidate] = None


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

# 4. Create Remediator Package

Create folder:

```bash
mkdir -p securepy_ai/remediator
```

Create:

```text
securepy_ai/remediator/__init__.py
```

Add:

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


__all__ = [
    "BaseLLMClient",
    "LLMClientError",
    "LLMResponse",
    "MockLLMClient",
    "OllamaClient",
    "PatchGenerator",
    "extract_python_code",
    "is_valid_python",
]
```

---

# 5. Create LLM Client

Create:

```text
securepy_ai/remediator/llm_client.py
```

This file contains:

```text
BaseLLMClient
OllamaClient
MockLLMClient
LLMClientError
LLMResponse
```

```python
import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict


class LLMClientError(Exception):
    """
    Raised when the LLM client fails to generate a response.
    """


@dataclass
class LLMResponse:
    """
    Represents a response from an LLM.
    """

    model: str
    text: str
    latency_ms: float
    raw: Dict[str, Any]


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    """

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        pass

    def is_available(self) -> bool:
        return True


class OllamaClient(BaseLLMClient):
    """
    Client for interacting with a local Ollama server.

    Default endpoint:
        http://127.0.0.1:11434
    """

    def __init__(
        self,
        model: str = "codellama:13b",
        base_url: str = "http://127.0.0.1:11434",
        timeout: int = 180,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        """
        Checks whether the Ollama server is reachable.
        """
        url = f"{self.base_url}/api/tags"

        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status == 200
        except Exception:
            return False

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """
        Sends a chat completion request to Ollama.
        """
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=f"{self.base_url}/api/chat",
            data=data,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        start_time = time.perf_counter()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise LLMClientError(
                f"Ollama HTTP error {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise LLMClientError(
                f"Cannot connect to Ollama at {self.base_url}. "
                f"Is Ollama running? Details: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise LLMClientError(
                f"Ollama request timed out after {self.timeout} seconds."
            ) from exc

        latency_ms = (time.perf_counter() - start_time) * 1000

        try:
            response_json = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LLMClientError("Ollama returned invalid JSON.") from exc

        text = response_json.get("message", {}).get("content", "")

        if not text:
            raise LLMClientError("Ollama returned an empty response.")

        return LLMResponse(
            model=self.model,
            text=text,
            latency_ms=latency_ms,
            raw=response_json,
        )


class MockLLMClient(BaseLLMClient):
    """
    Mock LLM client for offline testing and CI demos.

    This allows SecurePy AI to be tested without installing Ollama
    or downloading large models.
    """

    def __init__(self, model: str = "mock-llm"):
        self.model = model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        start_time = time.perf_counter()

        text = """```python
# SecurePy AI mock patch
def securepy_mock_fix():
    # Replace with validated secure implementation.
    return None
```"""

        latency_ms = (time.perf_counter() - start_time) * 1000

        return LLMResponse(
            model=self.model,
            text=text,
            latency_ms=latency_ms,
            raw={
                "mock": True,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
```

---

# 6. Create Patch Generator

Create:

```text
securepy_ai/remediator/patch_generator.py
```

This file:

```text
1. Builds a prompt from the finding and context
2. Sends it to the LLM
3. Extracts Python code from the response
4. Stores the patch candidate in the finding
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


CODE_FENCE_PATTERN = re.compile(
    r"```(?:python|py)?\s*(.*?)```",
    re.IGNORECASE | re.DOTALL,
)


SYSTEM_PROMPT = """
You are a senior application security engineer.

Your task is to fix confirmed security vulnerabilities in Python code.

Rules:
1. Fix only the vulnerability.
2. Preserve the intended functionality.
3. Return only valid Python code.
4. Do not include explanations outside the code.
5. Add a short comment explaining the security fix.
6. Follow secure coding best practices.
""".strip()


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
    """

    def __init__(
        self,
        client: BaseLLMClient,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ):
        self.client = client
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
                system_prompt=SYSTEM_PROMPT,
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
        Builds the user prompt sent to the LLM.
        """
        parts = [
            "Fix the following confirmed security vulnerability.",
            "",
            f"Rule ID: {finding.rule_id}",
            f"Vulnerability Type: {finding.vuln_type}",
            f"CWE: {finding.cwe_id}",
            f"Severity: {finding.severity.value}",
            f"File: {finding.file_path}",
            f"Line: {finding.line_number}",
            "",
            "Requirements:",
            "1. Fix only the vulnerability.",
            "2. Preserve intended functionality.",
            "3. Return only valid Python code.",
            "4. Do not include explanations outside code.",
            "5. Add a brief security-fix comment.",
        ]

        if finding.context is not None:
            parts.extend(
                [
                    "",
                    "Security Context:",
                    finding.context.to_prompt_context(),
                ]
            )
        else:
            parts.extend(
                [
                    "",
                    "Vulnerable Code:",
                    finding.code_snippet,
                ]
            )

        original_code = self._get_original_code(finding)

        parts.extend(
            [
                "",
                "Code to fix:",
                original_code,
            ]
        )

        return "\n".join(parts)

    def _get_original_code(self, finding: VulnerabilityFinding) -> str:
        """
        Returns the best available original code for the finding.
        """
        if finding.context is not None and finding.context.function_scope:
            return finding.context.function_scope

        return finding.code_snippet
```

---

# 7. Update CLI

Replace the content of:

```text
securepy_ai/cli.py
```

with this updated version.

This adds:

```bash
--fix
--model
--ollama-url
--timeout
--mock-llm
--max-patches
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

    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 4 Scan")
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

        generator = PatchGenerator(client=client)
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

# 8. Add Phase 4 Tests

Create:

```text
tests/test_llm.py
```

```python
from securepy_ai.models import Severity, VulnerabilityFinding
from securepy_ai.remediator.llm_client import MockLLMClient
from securepy_ai.remediator.patch_generator import (
    PatchGenerator,
    extract_python_code,
    is_valid_python,
)


def make_finding():
    return VulnerabilityFinding(
        rule_id="SEC102",
        vuln_type="SQL Injection",
        cwe_id="CWE-89",
        severity=Severity.CRITICAL,
        file_path="app.py",
        line_number=24,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query construction detected.",
    )


def test_extract_python_code_from_markdown():
    raw_response = """
Here is the fixed code:

```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,)).fetchone()
```

This uses parameterized queries.
"""

    code = extract_python_code(raw_response)

    assert is_valid_python(code)
    assert "def get_user" in code
    assert "parameterized" not in code


def test_extract_invalid_python_code():
    raw_response = """
```python
def broken(:
    return True
```
"""

    code = extract_python_code(raw_response)

    assert not is_valid_python(code)


def test_patch_generator_with_mock_llm():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    patch = generator.generate_for_finding(finding)

    assert patch.success is True
    assert patch.model == "mock-llm"
    assert patch.latency_ms >= 0
    assert is_valid_python(patch.patched_code)
    assert "securepy_mock_fix" in patch.patched_code


def test_prompt_contains_finding_details():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    prompt = generator.build_user_prompt(finding)

    assert "SEC102" in prompt
    assert "SQL Injection" in prompt
    assert "CWE-89" in prompt
    assert "app.py" in prompt
    assert "24" in prompt


def test_prompt_includes_code_to_fix():
    finding = make_finding()
    generator = PatchGenerator(client=MockLLMClient())

    prompt = generator.build_user_prompt(finding)

    assert "Code to fix:" in prompt
    assert "SELECT" in prompt
```

---

# 9. Run Phase 4 With Mock LLM

This is the easiest way to test without Ollama.

Run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm
```

Expected:

```text
Findings table
Detailed findings
AI Patch Candidates
Patch generated successfully
```

The mock patch will look like:

```python
# SecurePy AI mock patch
def securepy_mock_fix():
    # Replace with validated secure implementation.
    return None
```

This is expected.

The purpose of Phase 4 is to prove that:

```text
Finding → Context → Prompt → LLM → Patch Candidate
```

works end to end.

---

# 10. Run Phase 4 With Real Ollama

Make sure Ollama is running.

Then run:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b --max-patches 1
```

Example with SQL injection only:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model codellama:13b --max-patches 1 --context
```

If you are using DeepSeek Coder:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model deepseek-coder:6.7b --max-patches 1
```

If you are using Qwen Coder:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model qwen2.5-coder:7b --max-patches 1
```

---

# 11. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run only Phase 4 tests:

```bash
pytest tests/test_llm.py -v
```

Expected Phase 4 tests:

```text
tests/test_llm.py::test_extract_python_code_from_markdown PASSED
tests/test_llm.py::test_extract_invalid_python_code PASSED
tests/test_llm.py::test_patch_generator_with_mock_llm PASSED
tests/test_llm.py::test_prompt_contains_finding_details PASSED
tests/test_llm.py::test_prompt_includes_code_to_fix PASSED
```

---

# 12. Phase 4 Acceptance Checklist

Phase 4 is complete when:

```text
✅ models.py includes PatchCandidate
✅ VulnerabilityFinding has optional patch field
✅ remediator package is created
✅ OllamaClient can connect to local Ollama
✅ MockLLMClient works without Ollama
✅ PatchGenerator builds prompts
✅ PatchGenerator extracts Python code from LLM response
✅ CLI supports --fix
✅ CLI supports --mock-llm
✅ CLI supports --model
✅ CLI displays patch candidates
✅ Phase 4 tests pass
✅ Code is committed to GitHub
```

---

# 13. Commit Phase 4

Run:

```bash
git add .
git commit -m "feat(phase-4): add local LLM integration and patch candidate generation"
```

Push:

```bash
git push
```

If using feature branch:

```bash
git push origin securepy-ai-phase-4
```

---

# 14. Important Note About Phase 4

Phase 4 generates patches, but it does **not** trust them yet.

Right now SecurePy AI says:

```text
Here is a patch candidate from the LLM.
```

In Phase 6, SecurePy AI will say:

```text
Here is a patch candidate, and I validated it using syntax, AST, re-scan, and logic checks.
```

That validation layer is what makes your project production-grade.

---

# 15. What Comes in Phase 5

Phase 5 is:

```text
Prompt Builder Engine
```

It will improve patch quality by adding:

```text
CWE-specific prompt templates
Secure coding constraints
Output formatting rules
Few-shot examples
Patch style rules
```

Phase 4 uses a basic prompt.

Phase 5 will make the prompts much stronger.

---

Once you complete Phase 4, reply:

```text
Phase 4 done
```

Then I will give you **Phase 5 complete code**, where we build the **CWE-aware Prompt Builder Engine**.
