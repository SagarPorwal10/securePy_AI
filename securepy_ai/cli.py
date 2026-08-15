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

from securepy_ai.remediator.patch_validator import PatchValidator

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
from securepy_ai.models import ScanReport


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
        python -m securepy_ai.cli scan --files-from-json '["a.py","b.py"]'
    """
    scanner = SecurePyParser(rules=ALL_RULES)

    if args.files_from_json:
        import json as json_module

        file_list = json_module.loads(args.files_from_json)
        report = ScanReport()

        for file_path in file_list:
            try:
                single_report = scanner.scan_path(file_path)
                report.files_scanned += single_report.files_scanned
                report.findings.extend(single_report.findings)
                report.errors.extend(single_report.errors)
            except Exception as exc:
                report.errors.append(f"Failed to scan {file_path}: {exc}")
    else:
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

        scan_target = "<diff-only: changed files>" if args.files_from_json else args.target
        print_scan_header(report, scan_target, baseline_ignored)

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
        nargs="?",
        default=".",
        help="Path to Python file or directory (default: current directory)",
    )

    scan_parser.add_argument(
        "--files-from-json",
        help="JSON array of file paths to scan (used for diff-only CI scanning)",
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
