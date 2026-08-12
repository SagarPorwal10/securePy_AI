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
