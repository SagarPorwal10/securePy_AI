Excellent, Sagar. Since **Phase 7 is done**, now we move to:

# Phase 8 — Advanced CLI and CI-Friendly Developer Experience

Phase 7 gave SecurePy AI proper reporting.

Phase 8 makes SecurePy AI behave like a real developer security product.

After Phase 8, SecurePy AI will support:

```text
--fail-on severity threshold
--quiet mode
--format json
--baseline
--create-baseline
CI-friendly exit codes
```

This is very important for your product vision:

> Developers should not be flooded with old findings, and CI should fail only when meaningful security issues appear.

---

# Phase 8 Goal

After Phase 8, SecurePy AI will support commands like:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on critical
```

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --quiet
```

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --format json
```

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --create-baseline baseline.json
```

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --baseline baseline.json --fail-on high
```

---

# Phase 8 Files

We will add:

```text
securepy_ai/
├── baseline.py
└── policies.py

tests/
├── test_baseline.py
└── test_policies.py
```

We will update:

```text
securepy_ai/cli.py
```

---

# 1. Create Baseline Engine

Create:

```text
securepy_ai/baseline.py
```

Baseline mode helps ignore existing known findings and only flag new findings.

This solves a major developer frustration:

```text
I inherited 200 old findings.
Now every pull request fails.
```

```python
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Tuple

from securepy_ai.models import ScanReport, VulnerabilityFinding


def finding_fingerprint(finding: VulnerabilityFinding) -> str:
    """
    Creates a stable fingerprint for a finding.

    The fingerprint is based on:
        - Rule ID
        - File path
        - Vulnerable code snippet

    Line number is intentionally avoided because line numbers
    can shift during normal development.
    """
    payload = "|".join(
        [
            finding.rule_id,
            finding.file_path,
            finding.code_snippet.strip(),
        ]
    )

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_baseline(path: str) -> Set[str]:
    """
    Loads baseline fingerprints from a JSON file.
    """
    baseline_path = Path(path)

    if not baseline_path.exists():
        return set()

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        return set(data.get("findings", []))
    except json.JSONDecodeError:
        return set()


def save_baseline(report: ScanReport, path: str) -> Path:
    """
    Saves current findings as a baseline JSON file.
    """
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    fingerprints = sorted(
        {
            finding_fingerprint(finding)
            for finding in report.findings
        }
    )

    payload = {
        "tool": "SecurePy AI",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings": fingerprints,
    }

    baseline_path.write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    return baseline_path


def filter_baseline(
    report: ScanReport,
    baseline_fingerprints: Set[str],
) -> Tuple[ScanReport, int]:
    """
    Removes findings that already exist in the baseline.

    Returns:
        - Updated report containing only new findings
        - Number of ignored baseline findings
    """
    new_findings = []
    ignored_count = 0

    for finding in report.findings:
        fingerprint = finding_fingerprint(finding)

        if fingerprint in baseline_fingerprints:
            ignored_count += 1
        else:
            new_findings.append(finding)

    report.findings = new_findings

    return report, ignored_count
```

---

# 2. Create CI Policy Engine

Create:

```text
securepy_ai/policies.py
```

This controls exit codes and severity thresholds.

```python
from securepy_ai.models import ScanReport


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity_value: str) -> int:
    """
    Converts severity text into a numeric rank.
    """
    return SEVERITY_ORDER.get(severity_value.lower(), 0)


def has_findings_at_or_above(report: ScanReport, threshold: str) -> bool:
    """
    Checks whether the report contains findings at or above
    the given severity threshold.
    """
    if threshold.lower() in {"none", "off"}:
        return False

    threshold_rank = SEVERITY_ORDER.get(threshold.lower())

    if threshold_rank is None:
        return False

    for finding in report.findings:
        if _severity_rank(finding.severity.value) >= threshold_rank:
            return True

    return False


def determine_exit_code(
    report: ScanReport,
    fail_on: str = "high",
    has_scanner_errors: bool = False,
) -> int:
    """
    Determines CI-friendly exit codes.

    Exit codes:
        0 → success / no blocking findings
        1 → blocking findings detected
        2 → scanner/tool error
    """
    if has_scanner_errors and not report.findings:
        return 2

    if fail_on.lower() in {"none", "off"}:
        return 0

    if has_findings_at_or_above(report, fail_on):
        return 1

    return 0
```

---

# 3. Update CLI

Replace:

```text
securepy_ai/cli.py
```

with this updated version.

This is the Phase 8 CLI.

```python
import argparse
import json

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

from securepy_ai.validator.patch_validator import PatchValidator

from securepy_ai.reporter import (
    build_summary,
    write_reports,
)
from securepy_ai.reporter.json_report import (
    SecurePyJSONEncoder,
    build_report_dict,
)

from securepy_ai.baseline import (
    filter_baseline,
    load_baseline,
    save_baseline,
)
from securepy_ai.policies import determine_exit_code


console = Console()


SEVERITY_STYLES = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "bold green",
    "Info": "bold cyan",
}


def check_icon(status):
    """
    Returns an icon for validation check status.
    """
    icons = {
        "pass": "✅",
        "fail": "❌",
        "warn": "⚠️",
        "skipped": "⏭️",
    }

    return icons.get(status, "•")


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
    Prints AI-generated patch candidates and validation results.
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

            if patch.validation is not None:
                validation_lines = []

                validation_lines.append(
                    f"[bold]Confidence:[/bold] {patch.validation.confidence_score:.2f}"
                )
                validation_lines.append(
                    f"[bold]Decision:[/bold] {escape(patch.validation.decision)}"
                )
                validation_lines.append("")

                for check in patch.validation.checks:
                    validation_lines.append(
                        f"{check_icon(check.status)} {escape(check.name)} — "
                        f"{escape(check.status.upper())} — "
                        f"{escape(check.message)}"
                    )

                body += "\n[bold]Patch Validation:[/bold]\n"
                body += "\n".join(validation_lines)

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


def print_scan_header(report, target, baseline_ignored):
    """
    Prints the main scan header and findings table.
    """
    console.rule(f"[bold cyan]SecurePy AI v{__version__} — Phase 8 Scan")
    console.print(f"Target: [bold]{target}[/bold]")
    console.print(f"Files scanned: [bold]{report.files_scanned}[/bold]")

    if baseline_ignored:
        console.print(
            f"[yellow]Baseline ignored findings: {baseline_ignored}[/yellow]"
        )

    if report.errors:
        console.print("\n[bold yellow]Scanner Errors:[/bold yellow]")

        for error in report.errors:
            console.print(f"[yellow]{error}[/yellow]")

    if not report.findings:
        console.print("\n[bold green]No new vulnerabilities found.[/bold green]")
        return

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


def print_report_paths(report_paths):
    """
    Prints generated report paths.
    """
    console.print("\n[bold cyan]Reports Generated[/bold cyan]")

    for report_type, report_path in report_paths.items():
        console.print(
            f"[green]{report_type.upper()} report saved:[/green] {report_path}"
        )


def print_minimal_summary(report, baseline_ignored, exit_code):
    """
    Prints a minimal CI-friendly summary.
    """
    summary = build_summary(report)

    console.print(
        f"files_scanned={summary['files_scanned']} "
        f"findings={summary['total_findings']} "
        f"baseline_ignored={baseline_ignored} "
        f"errors={summary['errors_count']} "
        f"patches_generated={summary['patch_stats']['generated']} "
        f"valid_patches={summary['patch_stats']['valid']} "
        f"exit_code={exit_code}"
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

    baseline_ignored = 0
    baseline_created = None

    if args.create_baseline:
        baseline_created = save_baseline(report, args.create_baseline)
    elif args.baseline:
        baseline = load_baseline(args.baseline)
        report, baseline_ignored = filter_baseline(report, baseline)

    if args.format == "text" and not args.quiet:
        if baseline_created is not None:
            console.print(
                f"[green]Baseline saved: {baseline_created}[/green]"
            )

        print_scan_header(report, args.target, baseline_ignored)

        if args.context:
            print_context(report)

        if args.show_prompts:
            print_prompts(
                report,
                prompt_builder,
                max_prompts=args.max_prompts,
            )

    if args.fix and report.findings:
        if args.mock_llm:
            client = MockLLMClient()
        else:
            client = OllamaClient(
                model=args.model,
                base_url=args.ollama_url,
                timeout=args.timeout,
            )

            if not client.is_available():
                error_message = (
                    "Ollama is not reachable. Start Ollama or use --mock-llm "
                    "for offline testing."
                )

                if args.format == "json":
                    payload = build_report_dict(report, target=args.target)
                    payload["baseline_ignored"] = baseline_ignored
                    payload["error"] = error_message

                    if baseline_created is not None:
                        payload["baseline_created"] = str(baseline_created)

                    print(
                        json.dumps(
                            payload,
                            indent=2,
                            cls=SecurePyJSONEncoder,
                        )
                    )
                elif args.quiet:
                    console.print("error=ollama_unreachable exit_code=2")
                else:
                    console.print(f"[bold red]{error_message}[/bold red]")

                return 2

        generator = PatchGenerator(
            client=client,
            prompt_builder=prompt_builder,
        )

        generator.generate_for_report(
            report,
            max_patches=args.max_patches,
        )

        if not args.skip_validation:
            validator = PatchValidator()
            validator.validate_report(report)

        if args.format == "text" and not args.quiet:
            print_patches(report)

    report_paths = {}

    if args.report:
        report_paths = write_reports(
            report=report,
            output_dir=args.output_dir,
            report_type=args.report,
            target=args.target,
        )

        if args.format == "text" and not args.quiet:
            print_report_paths(report_paths)

    exit_code = determine_exit_code(
        report=report,
        fail_on=args.fail_on,
        has_scanner_errors=bool(report.errors),
    )

    if baseline_created is not None:
        exit_code = 0

    if args.format == "json":
        payload = build_report_dict(report, target=args.target)
        payload["baseline_ignored"] = baseline_ignored
        payload["exit_code"] = exit_code

        if baseline_created is not None:
            payload["baseline_created"] = str(baseline_created)

        if report_paths:
            payload["reports"] = {
                report_type: str(report_path)
                for report_type, report_path in report_paths.items()
            }

        print(
            json.dumps(
                payload,
                indent=2,
                cls=SecurePyJSONEncoder,
            )
        )
    elif args.quiet:
        print_minimal_summary(report, baseline_ignored, exit_code)
    else:
        summary = build_summary(report)

        if args.fix and not args.skip_validation:
            console.print(
                f"\n[bold cyan]Valid patches: {summary['patch_stats']['valid']}[/bold cyan]"
            )

        console.print(
            f"\n[bold red]Total findings: {summary['total_findings']}[/bold red]"
        )
        console.print(f"[bold]Exit code: {exit_code}[/bold]")

    return exit_code


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

    scan_parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip patch validation",
    )

    scan_parser.add_argument(
        "--report",
        choices=["json", "html", "sarif", "all"],
        help="Generate report output",
    )

    scan_parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to store generated reports",
    )

    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "none"],
        default="high",
        help="Minimum severity that causes a non-zero exit code",
    )

    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print minimal output",
    )

    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )

    scan_parser.add_argument(
        "--baseline",
        help="Path to baseline JSON file",
    )

    scan_parser.add_argument(
        "--create-baseline",
        help="Create a baseline JSON file from current findings",
    )

    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(scan_command(args))


if __name__ == "__main__":
    main()
```

---

# 4. Add Baseline Tests

Create:

```text
tests/test_baseline.py
```

```python
from securepy_ai.baseline import (
    filter_baseline,
    finding_fingerprint,
    load_baseline,
    save_baseline,
)
from securepy_ai.models import (
    ScanReport,
    Severity,
    VulnerabilityFinding,
)


def make_finding(
    rule_id="SEC101",
    file_path="app.py",
    code_snippet='password = "admin123"',
):
    return VulnerabilityFinding(
        rule_id=rule_id,
        vuln_type="Hardcoded Secret",
        cwe_id="CWE-798",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=1,
        code_snippet=code_snippet,
        description="Possible hardcoded secret.",
    )


def test_fingerprint_is_stable():
    finding_one = make_finding()
    finding_two = make_finding()

    assert finding_fingerprint(finding_one) == finding_fingerprint(finding_two)


def test_fingerprint_changes_with_code():
    finding_one = make_finding(code_snippet='password = "admin123"')
    finding_two = make_finding(code_snippet='password = "hunter22"')

    assert finding_fingerprint(finding_one) != finding_fingerprint(finding_two)


def test_save_and_load_baseline(tmp_path):
    report = ScanReport(
        files_scanned=1,
        findings=[make_finding()],
        errors=[],
    )

    baseline_path = tmp_path / "baseline.json"

    save_baseline(report, str(baseline_path))
    loaded = load_baseline(str(baseline_path))

    assert finding_fingerprint(make_finding()) in loaded


def test_filter_baseline_removes_known_findings():
    known_finding = make_finding(
        code_snippet='password = "admin123"',
    )

    new_finding = make_finding(
        code_snippet='api_key = "AKIA1234567890"',
    )

    report = ScanReport(
        files_scanned=1,
        findings=[known_finding, new_finding],
        errors=[],
    )

    baseline = {
        finding_fingerprint(known_finding),
    }

    filtered_report, ignored_count = filter_baseline(report, baseline)

    assert ignored_count == 1
    assert len(filtered_report.findings) == 1
    assert filtered_report.findings[0].code_snippet == 'api_key = "AKIA1234567890"'
```

---

# 5. Add Policy Tests

Create:

```text
tests/test_policies.py
```

```python
from securepy_ai.models import (
    ScanReport,
    Severity,
    VulnerabilityFinding,
)
from securepy_ai.policies import (
    determine_exit_code,
    has_findings_at_or_above,
)


def make_report(severity):
    finding = VulnerabilityFinding(
        rule_id="SEC101",
        vuln_type="Hardcoded Secret",
        cwe_id="CWE-798",
        severity=severity,
        file_path="app.py",
        line_number=1,
        code_snippet='password = "admin123"',
        description="Possible hardcoded secret.",
    )

    return ScanReport(
        files_scanned=1,
        findings=[finding],
        errors=[],
    )


def test_critical_finding_fails_critical_threshold():
    report = make_report(Severity.CRITICAL)

    assert has_findings_at_or_above(report, "critical") is True
    assert determine_exit_code(report, fail_on="critical") == 1


def test_high_finding_does_not_fail_critical_threshold():
    report = make_report(Severity.HIGH)

    assert has_findings_at_or_above(report, "critical") is False
    assert determine_exit_code(report, fail_on="critical") == 0


def test_high_finding_fails_high_threshold():
    report = make_report(Severity.HIGH)

    assert determine_exit_code(report, fail_on="high") == 1


def test_medium_finding_does_not_fail_high_threshold():
    report = make_report(Severity.MEDIUM)

    assert determine_exit_code(report, fail_on="high") == 0


def test_fail_on_none_always_returns_zero():
    report = make_report(Severity.CRITICAL)

    assert determine_exit_code(report, fail_on="none") == 0


def test_scanner_error_with_no_findings_returns_two():
    report = ScanReport(
        files_scanned=1,
        findings=[],
        errors=["Syntax error in file.py"],
    )

    assert determine_exit_code(report, fail_on="high", has_scanner_errors=True) == 2
```

---

# 6. Run Phase 8

Make sure you are in the project root:

```bash
cd securepy-ai
```

## Normal scan

```bash
python -m securepy_ai.cli scan examples/vulnerable.py
```

Default exit policy:

```text
Fail on high or critical findings.
```

---

## Fail only on critical findings

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on critical
```

---

## Do not fail the build

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on none
```

---

## Quiet mode

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --quiet
```

Expected output:

```text
files_scanned=1 findings=10 baseline_ignored=0 errors=0 patches_generated=0 valid_patches=0 exit_code=1
```

---

## JSON output

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --format json
```

To save JSON:

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --format json > scan.json
```

---

## Create baseline

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --create-baseline baseline.json
```

Expected:

```text
Baseline saved: baseline.json
```

---

## Scan using baseline

```bash
python -m securepy_ai.cli scan examples/vulnerable.py --baseline baseline.json
```

Expected:

```text
Baseline ignored findings: 10
No new vulnerabilities found.
```

Exit code should usually be:

```text
0
```

This is very useful for existing projects.

---

# 7. Run Tests

Run all tests:

```bash
pytest tests/ -v
```

Run Phase 8 tests:

```bash
pytest tests/test_baseline.py tests/test_policies.py -v
```

Expected:

```text
tests/test_baseline.py::test_fingerprint_is_stable PASSED
tests/test_baseline.py::test_fingerprint_changes_with_code PASSED
tests/test_baseline.py::test_save_and_load_baseline PASSED
tests/test_baseline.py::test_filter_baseline_removes_known_findings PASSED

tests/test_policies.py::test_critical_finding_fails_critical_threshold PASSED
tests/test_policies.py::test_high_finding_does_not_fail_critical_threshold PASSED
tests/test_policies.py::test_high_finding_fails_high_threshold PASSED
tests/test_policies.py::test_medium_finding_does_not_fail_high_threshold PASSED
tests/test_policies.py::test_fail_on_none_always_returns_zero PASSED
tests/test_policies.py::test_scanner_error_with_no_findings_returns_two PASSED
```

---

# 8. Add Baseline to `.gitignore`, Optional

If you do not want to commit local baselines, add:

```text
baseline.json
```

to `.gitignore`.

But in real projects, baseline files are often committed so CI can use them.

---

# 9. Phase 8 Acceptance Checklist

Phase 8 is complete when:

```text
✅ baseline.py is created
✅ policies.py is created
✅ CLI supports --fail-on
✅ CLI supports --quiet
✅ CLI supports --format json
✅ CLI supports --baseline
✅ CLI supports --create-baseline
✅ Exit code is CI-friendly
✅ Baseline filters known findings
✅ JSON output works
✅ Baseline tests pass
✅ Policy tests pass
✅ Code is committed to GitHub
```

---

# 10. Commit Phase 8

Run:

```bash
git add .
git commit -m "feat(phase-8): add CI-friendly CLI, baseline mode, and severity policies"
```

Push:

```bash
git push
```

If using feature branch:

```bash
git push origin securepy-ai-phase-8
```

---

# 11. Why Phase 8 Matters for Your Product Vision

Phase 8 directly solves developer frustrations with external scanners.

| Frustration | SecurePy AI Feature |
|---|---|
| Too many old findings | `--baseline` |
| CI fails for low-severity issues | `--fail-on` |
| Noisy output | `--quiet` |
| Hard to integrate with automation | `--format json` |
| Unclear build failure behavior | deterministic exit codes |
| Existing codebase has too many issues | baseline mode |

This makes SecurePy AI feel less like a college tool and more like a real security product.

---

# 12. What Comes in Phase 9

Phase 9 is:

```text
GitHub Action Integration
```

We will build:

```text
action.yml
GitHub workflow
PR comment bot
CI artifact upload
SARIF upload, optional
```

After Phase 9, SecurePy AI will run automatically when developers open pull requests.

---

Once you complete Phase 8, reply:

```text
Phase 8 done
```

Then I will give you **Phase 9 complete code**, where we build the **GitHub Action and CI/CD integration**.