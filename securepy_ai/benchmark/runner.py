import ast
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from securepy_ai.models import PatchCandidate, Severity, VulnerabilityFinding
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import ALL_RULES
from securepy_ai.remediator.patch_validator import PatchValidator

from securepy_ai.benchmark.loader import BenchCase


VALIDATION_LAYERS = ["syntax", "logic", "rescan", "nonew"]


class BenchmarkRunner:
    def __init__(self, client=None, prompt_builder=None):
        self.enricher = ContextEnricher()
        self.validator = PatchValidator()
        self.client = client
        self.prompt_builder = prompt_builder   # enables prompt ablation

    def _scan_code(self, code: str) -> List[VulnerabilityFinding]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        findings = []
        for rule_class in ALL_RULES:
            rule = rule_class()
            findings.extend(rule.scan(tree, "<bench>", code))
        return findings

    def run_case(self, case: BenchCase) -> Dict:
        result = {"id": case.case_id, "cwe": case.cwe, "rule_id": case.rule_id}

        vuln_findings = self._scan_code(case.vulnerable_code)
        result["detected"] = any(f.rule_id == case.rule_id for f in vuln_findings)

        fixed_findings = self._scan_code(case.fixed_code)
        result["fp_on_fix"] = any(f.rule_id == case.rule_id for f in fixed_findings)

        finding = next((f for f in vuln_findings if f.rule_id == case.rule_id), None)
        if finding is None:
            finding = VulnerabilityFinding(
                rule_id=case.rule_id, vuln_type=case.vuln_type, cwe_id=case.cwe,
                severity=Severity.HIGH, file_path=str(case.directory / "vulnerable.py"),
                line_number=1, code_snippet="", description="benchmark case",
            )
        finding.context = self.enricher.extract(finding, case.vulnerable_code)

        # Oracle: known-good fix must be accepted
        oracle = PatchCandidate(model="oracle", prompt_used="", original_code=case.vulnerable_code,
                                patched_code=case.fixed_code, raw_response="", latency_ms=0.0, success=True)
        ov = self.validator.validate(finding, oracle)
        result["oracle_valid"] = ov.passed
        result["oracle_confidence"] = ov.confidence_score

        # Original-as-patch must be rejected
        orig = PatchCandidate(model="oracle", prompt_used="", original_code=case.vulnerable_code,
                              patched_code=case.vulnerable_code, raw_response="", latency_ms=0.0, success=True)
        result["orig_rejected"] = not self.validator.validate(finding, orig).vuln_fixed

        # Bad patch + layer ablation
        if case.bad_code is not None:
            bad = PatchCandidate(model="oracle", prompt_used="", original_code=case.vulnerable_code,
                                 patched_code=case.bad_code, raw_response="", latency_ms=0.0, success=True)
            bv = self.validator.validate(finding, bad)
            result["bad_checks"] = {
                "syntax": bv.syntax_valid, "logic": bv.logic_preserved,
                "rescan": bv.vuln_fixed, "nonew": bv.no_new_vulns,
            }
            # A bad patch is rejected if it fails the security oracle: vuln still present.
            # Note: bv.passed can be True (score >= 60) even when vuln_fixed=False because
            # syntax+logic+no_new_vulns can still yield 70/100. We use vuln_fixed as the
            # definitive security criterion — if the original rule still fires, reject.
            result["bad_rejected_full"] = not bv.vuln_fixed

        # Optional LLM track
        if self.client is not None:
            from securepy_ai.remediator.patch_generator import PatchGenerator
            gen = PatchGenerator(client=self.client, prompt_builder=self.prompt_builder)
            patch = gen.generate_for_finding(finding)
            if patch.success:
                v = self.validator.validate(finding, patch)
                result["llm_fix_rate"] = v.vuln_fixed
                result["llm_safe"] = v.passed
                result["llm_confidence"] = v.confidence_score
            else:
                result["llm_fix_rate"] = False
                result["llm_safe"] = False
                result["llm_confidence"] = 0.0

        return result

    def run(self, cases: List[BenchCase]) -> List[Dict]:
        return [self.run_case(c) for c in cases]


def aggregate_metrics(results: List[Dict]) -> Dict:
    total = len(results)
    if total == 0:
        return {}
    detected = sum(1 for r in results if r.get("detected"))
    fp = sum(1 for r in results if r.get("fp_on_fix"))
    oracle = sum(1 for r in results if r.get("oracle_valid"))
    orig_rej = sum(1 for r in results if r.get("orig_rejected"))
    confs = [r["oracle_confidence"] for r in results if r.get("oracle_confidence") is not None]
    return {
        "total_cases": total,
        "detection_recall": round(detected / total, 3),
        "false_positives_on_fix": fp,
        "oracle_accept_rate": round(oracle / total, 3),
        "original_rejection_rate": round(orig_rej / total, 3),
        "avg_oracle_confidence": round(sum(confs) / len(confs), 2) if confs else 0.0,
    }


def ablation_table(results: List[Dict]) -> List[Dict]:
    bad = [r for r in results if r.get("bad_checks")]
    total = len(bad)
    table = []
    for k in range(1, len(VALIDATION_LAYERS) + 1):
        enabled = VALIDATION_LAYERS[:k]
        rejected = sum(
            1 for r in bad
            if any(not r["bad_checks"].get(layer, True) for layer in enabled)
        )
        table.append({
            "variant": f"V{k}", "layers": " + ".join(enabled),
            "rejected": rejected, "total": total,
            "rejection_rate": round(rejected / total, 3) if total else 0.0,
        })
    return table


def write_benchmark_report(results, metrics, ablation, output_path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    L = ["# SecurePy AI — Benchmark Results", "",
         f"Generated: {datetime.now(timezone.utc).isoformat()}", "",
         "## Detection", "", "| Metric | Value |", "|---|---:|",
         f"| Total cases | {metrics.get('total_cases',0)} |",
         f"| Detection recall | {metrics.get('detection_recall',0)} |",
         f"| False positives on fixed code | {metrics.get('false_positives_on_fix',0)} |", "",
         "## Remediation / Validation", "", "| Metric | Value |", "|---|---:|",
         f"| Oracle patch accept rate | {metrics.get('oracle_accept_rate',0)} |",
         f"| Original-as-patch rejection | {metrics.get('original_rejection_rate',0)} |",
         f"| Avg oracle confidence | {metrics.get('avg_oracle_confidence',0)} |", "",
         "## Validation-Layer Ablation (bad patches)", "",
         "| Variant | Layers | Rejected | Rate |", "|---|---|---:|---:|"]
    for row in ablation:
        L.append(f"| {row['variant']} | {row['layers']} | {row['rejected']}/{row['total']} | {row['rejection_rate']} |")
    L += ["", "## Per-Case", "",
          "| Case | CWE | Detected | Oracle Valid | Orig Rejected | Bad Rejected |",
          "|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['id']} | {r['cwe']} | {r.get('detected')} | {r.get('oracle_valid')} "
                 f"| {r.get('orig_rejected')} | {r.get('bad_rejected_full','n/a')} |")
    output.write_text("\n".join(L), encoding="utf-8")
    output.with_suffix(".json").write_text(
        json.dumps({"metrics": metrics, "ablation": ablation, "cases": results}, indent=2),
        encoding="utf-8",
    )
    return output
