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
