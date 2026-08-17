import argparse
import fnmatch
import json
import shutil
import time
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from securepy_ai import __version__

from securepy_ai.benchmark import (
    BenchmarkRunner, ablation_table, aggregate_metrics, load_dataset, write_benchmark_report,
)

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


# Severity ordering for --severity filter
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
        "pass": "[OK]",
        "fail": "[X]",
        "warn": "[!]",
        "skipped": "[-]",
    }

    return icons.get(status, "â€¢")


def print_context(report):
    """
    Prints extracted context for each finding.
    """
    console.print("\n[bold cyan]Extracted Security Context[/bold cyan]")

    for finding in report.findings:
        context = finding.context

        if context is None:
            continue

        title = f"{finding.file_path}:{finding.line_number} â€” {finding.rule_id}"

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
        title = f"{finding.file_path}:{finding.line_number} â€” {finding.rule_id}"

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

        title = f"{finding.file_path}:{finding.line_number} â€” {finding.rule_id} â€” {patch.model}"

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

                checks = [
                    ("Syntax valid", "pass" if patch.validation.syntax_valid else "fail"),
                    ("Logic preserved", "pass" if patch.validation.logic_preserved else "fail"),
                    ("Vulnerability fixed", "pass" if patch.validation.vuln_fixed else "fail"),
                    ("No new vulnerabilities", "pass" if patch.validation.no_new_vulns else "fail"),
                ]

                for name, status in checks:
                    validation_lines.append(
                        f"{check_icon(status)} {escape(name)} â€” {escape(status.upper())}"
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


def print_scan_header(report, target, baseline_ignored, severity_filter=None):
    """
    Prints the main scan header and findings table.
    """
    console.rule(f"[bold cyan]SecurePy AI v{__version__} â€” Scan")
    console.print(f"Target: [bold]{target}[/bold]")
    console.print(f"Files scanned: [bold]{report.files_scanned}[/bold]")

    if severity_filter:
        console.print(f"Severity filter: [bold yellow]{severity_filter.upper()} and above[/bold yellow]")

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


def apply_best_patch(report, dry_run=False):
    """
    Writes the highest-confidence passing patch back to its source file.

    - Makes a .bak backup first.
    - Only applies patches whose validation passed (confidence >= threshold).
    - Returns (applied_count, skipped_count).
    """
    applied = 0
    skipped = 0

    for finding in report.findings:
        patch = finding.patch
        if patch is None or not patch.success:
            skipped += 1
            continue
        if patch.validation is None or not patch.validation.passed:
            skipped += 1
            continue

        target = Path(finding.file_path)
        if not target.exists():
            console.print(f"[yellow]  skip {target}: file not found[/yellow]")
            skipped += 1
            continue

        original_code = patch.original_code or ""
        patched_code = patch.patched_code or ""
        if not patched_code.strip():
            skipped += 1
            continue

        source = target.read_text(encoding="utf-8")
        if original_code not in source:
            console.print(
                f"[yellow]  skip {target}:{finding.line_number}: original snippet no longer "
                f"matches file (stale patch)[/yellow]"
            )
            skipped += 1
            continue

        if dry_run:
            console.print(
                f"[cyan]  [DRY-RUN] would apply {finding.rule_id} fix "
                f"to {target}:{finding.line_number}[/cyan]"
            )
            applied += 1
            continue

        backup = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(target, backup)
        new_source = source.replace(original_code, patched_code, 1)
        target.write_text(new_source, encoding="utf-8")
        console.print(
            f"[green]  ✔ Applied {finding.rule_id} fix to "
            f"{target}:{finding.line_number} (backup: {backup})[/green]"
        )
        applied += 1

    return applied, skipped


def _exclude_match(file_path: str, patterns: list) -> bool:
    """Return True if file_path matches any exclude glob pattern."""
    for pat in patterns:
        if fnmatch.fnmatch(file_path, pat):
            return True
        # also match just the filename portion
        if fnmatch.fnmatch(Path(file_path).name, pat):
            return True
    return False


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
        f"auto_apply_patches={summary['patch_stats']['auto_apply']} "
        f"exit_code={exit_code}"
    )


def print_rich_summary(report, baseline_ignored, exit_code, fix_enabled, skip_validation):
    """
    Prints a rich, actionable summary table showing severity breakdown,
    patch generation stats, and patch success rate.
    """
    summary = build_summary(report)
    ps = summary["patch_stats"]

    sev_table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    sev_table.add_column("Severity",   justify="left",  style="bold")
    sev_table.add_column("Findings",   justify="right")
    sev_table.add_column("Patch Gen",  justify="right")
    sev_table.add_column("Auto-Apply", justify="right")

    sev_counts = summary.get("severity_counts", {})
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        style = SEVERITY_STYLES.get(sev, "white")
        gen = sum(
            1 for f in report.findings
            if f.severity.value == sev and f.patch is not None and f.patch.success
        )
        auto = sum(
            1 for f in report.findings
            if f.severity.value == sev
            and f.patch is not None
            and f.patch.validation is not None
            and f.patch.validation.passed
        )
        sev_table.add_row(
            f"[{style}]{sev}[/{style}]",
            str(count),
            str(gen) if fix_enabled else "—",
            str(auto) if (fix_enabled and not skip_validation) else "—",
        )

    total_gen  = ps.get("generated", 0)
    total_auto = ps.get("auto_apply", 0)
    sev_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{summary['total_findings']}[/bold]",
        f"[bold]{total_gen}[/bold]" if fix_enabled else "—",
        f"[bold]{total_auto}[/bold]" if (fix_enabled and not skip_validation) else "—",
    )

    console.print()
    console.print(sev_table)

    if fix_enabled and total_gen > 0:
        rate = round(total_auto / total_gen * 100)
        console.print(
            f"Patch success rate: [bold cyan]{rate}%[/bold cyan] "
            f"({total_auto}/{total_gen} auto-apply)"
        )

    if baseline_ignored:
        console.print(f"[yellow]Baseline suppressed: {baseline_ignored} findings[/yellow]")

    exit_style = "bold green" if exit_code == 0 else "bold red"
    console.print(f"Exit code: [{exit_style}]{exit_code}[/{exit_style}]")


def apply_best_patch(report, dry_run=False):
    """
    Writes the highest-confidence passing patch back to its source file.
    Makes a .bak backup first. Returns (applied_count, skipped_count).
    """
    applied = 0
    skipped = 0

    for finding in report.findings:
        patch = finding.patch
        if patch is None or not patch.success:
            skipped += 1
            continue
        if patch.validation is None or not patch.validation.passed:
            skipped += 1
            continue

        target = Path(finding.file_path)
        if not target.exists():
            console.print(f"[yellow]  skip {target}: file not found[/yellow]")
            skipped += 1
            continue

        original_code = patch.original_code or ""
        patched_code  = patch.patched_code  or ""
        if not patched_code.strip():
            skipped += 1
            continue

        source = target.read_text(encoding="utf-8")
        if original_code not in source:
            console.print(
                f"[yellow]  skip {target}:{finding.line_number}: original snippet no longer "
                f"matches file (stale patch)[/yellow]"
            )
            skipped += 1
            continue

        if dry_run:
            console.print(
                f"[cyan]  [DRY-RUN] would apply {finding.rule_id} fix "
                f"to {target}:{finding.line_number}[/cyan]"
            )
            applied += 1
            continue

        backup = target.with_suffix(target.suffix + ".bak")
        shutil.copy2(target, backup)
        new_source = source.replace(original_code, patched_code, 1)
        target.write_text(new_source, encoding="utf-8")
        console.print(
            f"[green]  \u2714 Applied {finding.rule_id} fix to "
            f"{target}:{finding.line_number} (backup: {backup})[/green]"
        )
        applied += 1

    return applied, skipped


def _exclude_match(file_path: str, patterns: list) -> bool:
    """Return True if file_path matches any exclude glob pattern."""
    for pat in patterns:
        if fnmatch.fnmatch(file_path, pat):
            return True
        if fnmatch.fnmatch(Path(file_path).name, pat):
            return True
    return False


def print_report_paths(report_paths):
    """
    Prints generated report paths.
    """
    console.print("\n[bold cyan]Reports Generated[/bold cyan]")

    for report_type, report_path in report_paths.items():
        console.print(
            f"[green]{report_type.upper()} report saved:[/green] {report_path}"
        )


def _run_single_scan(args):
    """
    Core scan logic — extracted so it can be called in both normal and --watch mode.
    Returns exit_code.
    """
    scanner = SecurePyParser(rules=ALL_RULES)
    exclude_patterns = getattr(args, "exclude", []) or []
    severity_filter  = getattr(args, "severity", None)
    sev_threshold    = SEVERITY_ORDER.get(severity_filter, 99) if severity_filter else 99

    if args.files_from_json:
        file_list = json.loads(args.files_from_json)
        report = ScanReport()
        for file_path in file_list:
            if exclude_patterns and _exclude_match(file_path, exclude_patterns):
                continue
            try:
                single_report = scanner.scan_path(file_path)
                report.files_scanned += single_report.files_scanned
                report.findings.extend(single_report.findings)
                report.errors.extend(single_report.errors)
            except Exception as exc:
                report.errors.append(f"Failed to scan {file_path}: {exc}")
    else:
        report = scanner.scan_path(args.target)
        if exclude_patterns:
            before = len(report.findings)
            report.findings = [
                f for f in report.findings
                if not _exclude_match(f.file_path, exclude_patterns)
            ]
            excluded = before - len(report.findings)
            if excluded and not args.quiet:
                console.print(f"[dim]Excluded {excluded} findings via --exclude patterns[/dim]")

    if severity_filter:
        before = len(report.findings)
        report.findings = [
            f for f in report.findings
            if SEVERITY_ORDER.get(f.severity.value.lower(), 99) <= sev_threshold
        ]
        dropped = before - len(report.findings)
        if dropped and not args.quiet:
            console.print(
                f"[dim]Severity filter '{severity_filter}': "
                f"dropped {dropped} lower-severity findings[/dim]"
            )

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
            console.print(f"[green]Baseline saved: {baseline_created}[/green]")

        scan_target = "<diff-only: changed files>" if args.files_from_json else args.target
        print_scan_header(report, scan_target, baseline_ignored, severity_filter)

        if args.context:
            print_context(report)

        if args.show_prompts:
            print_prompts(report, prompt_builder, max_prompts=args.max_prompts)

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
                    print(json.dumps(payload, indent=2, cls=SecurePyJSONEncoder))
                elif args.quiet:
                    console.print("error=ollama_unreachable exit_code=2")
                else:
                    console.print(f"[bold red]{error_message}[/bold red]")
                return 2

        generator = PatchGenerator(client=client, prompt_builder=prompt_builder)
        generator.generate_for_report(report, max_patches=args.max_patches)

        # Warn if patch cap was hit silently
        patched = sum(1 for f in report.findings if f.patch is not None)
        total   = len(report.findings)
        if patched < total and not args.quiet:
            console.print(
                f"[yellow]\u26a0 Patch cap reached: generated {patched} of {total} patches "
                f"(increase with --max-patches {total})[/yellow]"
            )

        if not args.skip_validation:
            validator = PatchValidator()
            validator.validate_report(report)

        if args.format == "text" and not args.quiet:
            print_patches(report)

        if getattr(args, "apply", False):
            console.print("\n[bold cyan]Applying patches to working tree\u2026[/bold cyan]")
            dry = getattr(args, "dry_run", False)
            applied, skipped = apply_best_patch(report, dry_run=dry)
            console.print(
                f"Applied: [green]{applied}[/green]  Skipped: [yellow]{skipped}[/yellow]"
            )

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
            payload["reports"] = {k: str(v) for k, v in report_paths.items()}
        print(json.dumps(payload, indent=2, cls=SecurePyJSONEncoder))
    elif args.quiet:
        print_minimal_summary(report, baseline_ignored, exit_code)
    else:
        print_rich_summary(
            report, baseline_ignored, exit_code,
            fix_enabled=args.fix,
            skip_validation=args.skip_validation,
        )

    return exit_code


def scan_command(args):
    """
    Handles:
        python -m securepy_ai.cli scan <target>
        python -m securepy_ai.cli scan --watch <target>
        python -m securepy_ai.cli scan --files-from-json '["a.py","b.py"]'
    """
    if not getattr(args, "watch", False):
        return _run_single_scan(args)

    # ── Watch mode ──────────────────────────────────────────────────────────
    console.print(
        f"[bold cyan]Watch mode active[/bold cyan] \u2014 monitoring "
        f"[bold]{args.target}[/bold]\nPress Ctrl+C to stop.\n"
    )

    target_path   = Path(args.target)
    poll_interval = 2  # seconds

    def _mtime(p: Path) -> float:
        if p.is_file():
            return p.stat().st_mtime
        total = 0.0
        for fp in p.rglob("*.py"):
            try:
                total += fp.stat().st_mtime
            except OSError:
                pass
        return total

    last_mtime = _mtime(target_path)
    exit_code  = _run_single_scan(args)

    try:
        while True:
            time.sleep(poll_interval)
            current_mtime = _mtime(target_path)
            if current_mtime != last_mtime:
                last_mtime = current_mtime
                console.rule("[bold yellow]File change detected \u2014 re-scanning\u2026[/bold yellow]")
                exit_code = _run_single_scan(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Watch mode stopped.[/dim]")

    return exit_code


def bench_command(args):
    """
    Handles: python -m securepy_ai.cli bench [--dataset] [--llm] [--model] [--output]
    """
    cases = load_dataset(args.dataset)
    if not cases:
        console.print(f"[bold red]No benchmark cases in {args.dataset}[/bold red]")
        return 2

    client = None
    if args.llm == "mock":
        client = MockLLMClient()
    elif args.llm == "ollama":
        client = OllamaClient(model=args.model)
        if not client.is_available():
            console.print("[bold red]Ollama is not reachable.[/bold red]")
            return 2

    results = BenchmarkRunner(client=client).run(cases)
    metrics = aggregate_metrics(results)
    ablation = ablation_table(results)
    path = write_benchmark_report(results, metrics, ablation, args.output)

    console.rule("[bold cyan]SecurePy AI Benchmark")
    console.print(f"Cases: [bold]{metrics.get('total_cases',0)}[/bold]")
    console.print(f"Detection recall: [bold]{metrics.get('detection_recall',0)}[/bold]")
    console.print(f"Oracle accept: [bold]{metrics.get('oracle_accept_rate',0)}[/bold]")
    console.print(f"Original rejection: [bold]{metrics.get('original_rejection_rate',0)}[/bold]")
    console.print(f"\n[green]Report:[/green] {path}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="securepy-ai",
        description="SecurePy AI \u2014 AST-aware SAST scanner for Python",
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
        "--apply",
        action="store_true",
        help="Write passing patches back to source files (makes .bak backup). Requires --fix.",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="With --apply: show what would be patched without writing files.",
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
        default=10,
        help="Maximum number of patches to generate (default: 10)",
    )
    scan_parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip patch validation",
    )
    scan_parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="PATTERN",
        help="Glob patterns of files/dirs to exclude (e.g. 'tests/*' 'migrations/*')",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Only show/fix findings at or above this severity level",
    )
    scan_parser.add_argument(
        "--watch",
        action="store_true",
        help="Re-scan automatically whenever a .py file in the target changes (Ctrl+C to stop)",
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

    bench_parser = subparsers.add_parser("bench", help="Run SecurePy-VulnBench evaluation")
    bench_parser.add_argument("--dataset", default="benchmark")
    bench_parser.add_argument("--llm", choices=["off", "mock", "ollama"], default="off")
    bench_parser.add_argument("--model", default="codellama:13b")
    bench_parser.add_argument("--output", default="reports/benchmark-results.md")

    args = parser.parse_args()

    if args.command == "scan":
        raise SystemExit(scan_command(args))

    if args.command == "bench":
        raise SystemExit(bench_command(args))


if __name__ == "__main__":
    main()

