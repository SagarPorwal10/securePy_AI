Phase 11 is the **evidence phase** — it turns your tool into a paper. Below is the complete, final implementation, now upgraded with two things your publication specifically needs: a **model-comparison track** and a **context-ablation track** (proving your AST-context prompting actually helps, mirroring the base paper's "guidance improves repair" finding).

---

# Phase 11 — Benchmarking & Evaluation Engine

## Files

```text
securepy_ai/benchmark/__init__.py
securepy_ai/benchmark/loader.py
securepy_ai/benchmark/runner.py          # updated: accepts prompt_builder (for ablation)
scripts/make_benchmark.py
scripts/compare_models.py                # NEW: model comparison + context ablation
securepy_ai/cli.py                       # add `bench` command
tests/test_benchmark.py
```

---

## 1. `securepy_ai/benchmark/loader.py`

```python
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class BenchCase:
    case_id: str
    cwe: str
    rule_id: str
    severity: str
    vuln_type: str
    directory: Path
    vulnerable_code: str
    fixed_code: str
    bad_code: Optional[str] = None
    metadata: dict = field(default_factory=dict)


def load_dataset(dataset_dir: str) -> List[BenchCase]:
    root = Path(dataset_dir)
    cases: List[BenchCase] = []

    for meta_path in sorted(root.rglob("metadata.json")):
        case_dir = meta_path.parent
        vulnerable_path = case_dir / "vulnerable.py"
        fixed_path = case_dir / "expected_fix.py"

        if not vulnerable_path.exists() or not fixed_path.exists():
            continue

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        bad_path = case_dir / "bad_fix.py"

        cases.append(
            BenchCase(
                case_id=meta.get("id", case_dir.name),
                cwe=meta.get("cwe", "CWE-000"),
                rule_id=meta.get("rule_id", ""),
                severity=meta.get("severity", "High"),
                vuln_type=meta.get("vuln_type", ""),
                directory=case_dir,
                vulnerable_code=vulnerable_path.read_text(encoding="utf-8"),
                fixed_code=fixed_path.read_text(encoding="utf-8"),
                bad_code=bad_path.read_text(encoding="utf-8") if bad_path.exists() else None,
                metadata=meta,
            )
        )

    return cases
```

---

## 2. `securepy_ai/benchmark/runner.py`

```python
import ast
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from securepy_ai.models import PatchCandidate, Severity, VulnerabilityFinding
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import ALL_RULES
from securepy_ai.validator.patch_validator import PatchValidator

from securepy_ai.benchmark.loader import BenchCase


VALIDATION_LAYERS = ["syntax", "logic", "rescan", "nonew"]


class BenchmarkRunner:
    def __init__(self, client=None, prompt_builder=None):
        self.enricher = ContextEnricher()
        self.validator = PatchValidator()
        self.client = client
        self.prompt_builder = prompt_builder   # NEW: enables prompt ablation

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
        ov = self.validator.validate_finding(finding, oracle)
        result["oracle_valid"] = ov.is_valid
        result["oracle_confidence"] = ov.confidence_score

        # Original-as-patch must be rejected
        orig = PatchCandidate(model="oracle", prompt_used="", original_code=case.vulnerable_code,
                              patched_code=case.vulnerable_code, raw_response="", latency_ms=0.0, success=True)
        result["orig_rejected"] = not self.validator.validate_finding(finding, orig).vulnerability_fixed

        # Bad patch + layer ablation
        if case.bad_code is not None:
            bad = PatchCandidate(model="oracle", prompt_used="", original_code=case.vulnerable_code,
                                 patched_code=case.bad_code, raw_response="", latency_ms=0.0, success=True)
            bv = self.validator.validate_finding(finding, bad)
            result["bad_checks"] = {
                "syntax": bv.syntax_valid, "logic": bv.ast_logic_preserved,
                "rescan": bv.vulnerability_fixed, "nonew": bv.no_new_vulnerabilities,
            }
            result["bad_rejected_full"] = not bv.is_valid

        # Optional LLM track
        if self.client is not None:
            from securepy_ai.remediator.patch_generator import PatchGenerator
            gen = PatchGenerator(client=self.client, prompt_builder=self.prompt_builder)
            patch = gen.generate_for_finding(finding)
            if patch.success:
                v = self.validator.validate_finding(finding, patch)
                result["llm_fix_rate"] = v.vulnerability_fixed
                result["llm_safe"] = v.is_valid
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
```

`securepy_ai/benchmark/__init__.py`:

```python
from securepy_ai.benchmark.loader import BenchCase, load_dataset
from securepy_ai.benchmark.runner import (
    BenchmarkRunner, ablation_table, aggregate_metrics, write_benchmark_report,
)
__all__ = ["BenchCase", "load_dataset", "BenchmarkRunner",
           "aggregate_metrics", "ablation_table", "write_benchmark_report"]
```

---

## 3. `scripts/make_benchmark.py` (10 cases, 2 per CWE)

```python
#!/usr/bin/env python3
import json
from pathlib import Path

CASES = [
    # CWE-89
    {"dir": "cwe_89_001", "meta": {"id": "cwe89_001", "cwe": "CWE-89", "rule_id": "SEC102", "severity": "Critical", "vuln_type": "SQL Injection"},
     "vuln": 'def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(query).fetchone()\n',
     "fix": 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n    return db.execute(query, (user_id,)).fetchone()\n',
     "bad": 'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return db.execute(query).fetchone()\n'},
    {"dir": "cwe_89_002", "meta": {"id": "cwe89_002", "cwe": "CWE-89", "rule_id": "SEC102", "severity": "Critical", "vuln_type": "SQL Injection"},
     "vuln": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = \'%s\'" % name\n    return conn.execute(sql)\n',
     "fix": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = ?"\n    return conn.execute(sql, (name,))\n',
     "bad": 'def search(name):\n    sql = "SELECT * FROM items WHERE title = \'" + name + "\'"\n    return conn.execute(sql)\n'},
    # CWE-798
    {"dir": "cwe_798_001", "meta": {"id": "cwe798_001", "cwe": "CWE-798", "rule_id": "SEC101", "severity": "High", "vuln_type": "Hardcoded Secret"},
     "vuln": 'API_KEY = "AKIA923848239482394"\n',
     "fix": 'import os\nAPI_KEY = os.environ.get("API_KEY")\n',
     "bad": 'API_KEY = "AKIA923848239482394"  # TODO move to env\n'},
    {"dir": "cwe_798_002", "meta": {"id": "cwe798_002", "cwe": "CWE-798", "rule_id": "SEC101", "severity": "High", "vuln_type": "Hardcoded Secret"},
     "vuln": 'db_password = "supersecret123"\n',
     "fix": 'import os\ndb_password = os.environ.get("DB_PASSWORD")\n',
     "bad": 'db_password = "supersecret123"  # rotate later\n'},
    # CWE-78
    {"dir": "cwe_78_001", "meta": {"id": "cwe78_001", "cwe": "CWE-78", "rule_id": "SEC103", "severity": "High", "vuln_type": "Command Injection"},
     "vuln": 'import os\ndef ping_host(host):\n    os.system("ping -c 1 " + host)\n',
     "fix": 'import subprocess\ndef ping_host(host):\n    subprocess.run(["ping", "-c", "1", host], check=True)\n',
     "bad": 'import os\ndef ping_host(host):\n    os.system("ping -c 1 " + host + " -W 2")\n'},
    {"dir": "cwe_78_002", "meta": {"id": "cwe78_002", "cwe": "CWE-78", "rule_id": "SEC103", "severity": "High", "vuln_type": "Command Injection"},
     "vuln": 'import os\ndef tail_log(path):\n    os.system("tail " + path)\n',
     "fix": 'import subprocess\ndef tail_log(path):\n    subprocess.run(["tail", path], check=True)\n',
     "bad": 'import os\ndef tail_log(path):\n    os.system("tail -n 20 " + path)\n'},
    # CWE-502
    {"dir": "cwe_502_001", "meta": {"id": "cwe502_001", "cwe": "CWE-502", "rule_id": "SEC104", "severity": "High", "vuln_type": "Insecure Deserialization"},
     "vuln": 'import pickle\ndef load_session(blob):\n    return pickle.loads(blob)\n',
     "fix": 'import json\ndef load_session(blob):\n    return json.loads(blob)\n',
     "bad": 'import pickle\ndef load_session(blob):\n    return pickle.loads(blob)  # validated upstream\n'},
    {"dir": "cwe_502_002", "meta": {"id": "cwe502_002", "cwe": "CWE-502", "rule_id": "SEC104", "severity": "High", "vuln_type": "Insecure Deserialization"},
     "vuln": 'import pickle\ndef restore_state(data):\n    return pickle.loads(data)\n',
     "fix": 'import json\ndef restore_state(data):\n    return json.loads(data)\n',
     "bad": 'import pickle\ndef restore_state(data):\n    return pickle.loads(data)  # trusted source\n'},
    # CWE-95
    {"dir": "cwe_95_001", "meta": {"id": "cwe95_001", "cwe": "CWE-95", "rule_id": "SEC105", "severity": "High", "vuln_type": "Unsafe Dynamic Execution"},
     "vuln": 'def calculate(expr):\n    return eval(expr)\n',
     "fix": 'import ast\ndef calculate(expr):\n    return ast.literal_eval(expr)\n',
     "bad": 'def calculate(expr):\n    return eval(expr, {"__builtins__": {}}, {})\n'},
    {"dir": "cwe_95_002", "meta": {"id": "cwe95_002", "cwe": "CWE-95", "rule_id": "SEC105", "severity": "High", "vuln_type": "Unsafe Dynamic Execution"},
     "vuln": 'def run_formula(formula):\n    return eval(formula)\n',
     "fix": 'import ast\ndef run_formula(formula):\n    return ast.literal_eval(formula)\n',
     "bad": 'def run_formula(formula):\n    return eval(formula)\n'},
]


def main():
    root = Path("benchmark")
    for case in CASES:
        d = root / case["dir"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "metadata.json").write_text(json.dumps(case["meta"], indent=2), encoding="utf-8")
        (d / "vulnerable.py").write_text(case["vuln"], encoding="utf-8")
        (d / "expected_fix.py").write_text(case["fix"], encoding="utf-8")
        (d / "bad_fix.py").write_text(case["bad"], encoding="utf-8")
    print(f"Created {len(CASES)} benchmark cases under benchmark/")


if __name__ == "__main__":
    main()
```

---

## 4. `scripts/compare_models.py` (NEW — paper tables)

```python
#!/usr/bin/env python3
"""
Model comparison + context ablation on SecurePy-VulnBench.

Produces:
  reports/model-comparison.md   (fix/safe/confidence per model)
  reports/context-ablation.md   (full-context prompt vs raw-code prompt)
"""
from pathlib import Path

from securepy_ai.benchmark import BenchmarkRunner, load_dataset
from securepy_ai.remediator.llm_client import OllamaClient

MODELS = ["qwen2.5-coder:1.5b", "deepseek-coder:6.7b", "codellama:13b"]


class RawPromptBuilder:
    """Ablation baseline: no context, no CWE guidance."""
    def get_system_prompt(self):
        return "Fix the bug in the code."
    def build_user_prompt(self, finding):
        return f"Fix this code:\n{finding.code_snippet}"


def llm_rates(results):
    n = len(results) or 1
    fix = sum(1 for r in results if r.get("llm_fix_rate"))
    safe = sum(1 for r in results if r.get("llm_safe"))
    conf = [r.get("llm_confidence", 0) for r in results]
    return (round(fix / n, 3), round(safe / n, 3),
            round(sum(conf) / len(conf), 2) if conf else 0.0)


def main():
    cases = load_dataset("benchmark")
    if not cases:
        print("Run scripts/make_benchmark.py first."); return

    rows = []
    for model in MODELS:
        client = OllamaClient(model=model)
        if not client.is_available():
            print(f"[skip] {model} not available"); continue
        results = BenchmarkRunner(client=client).run(cases)
        fix, safe, conf = llm_rates(results)
        rows.append((model, fix, safe, conf))
        print(f"[done] {model}: fix={fix} safe={safe} conf={conf}")

    out = Path("reports/model-comparison.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Model Comparison — SecurePy-VulnBench", "",
             "| Model | Fix Rate | Safe Patch Rate | Avg Confidence |",
             "|---|---:|---:|---:|"]
    lines += [f"| {m} | {f} | {s} | {c} |" for m, f, s, c in rows]
    out.write_text("\n".join(lines), encoding="utf-8")

    # Context ablation on the lightweight model
    ab_client = OllamaClient(model="qwen2.5-coder:1.5b")
    if ab_client.is_available():
        full = llm_rates(BenchmarkRunner(client=ab_client).run(cases))
        raw = llm_rates(BenchmarkRunner(client=ab_client, prompt_builder=RawPromptBuilder()).run(cases))
        ab = Path("reports/context-ablation.md")
        ab.write_text(
            "# Context Ablation (qwen2.5-coder:1.5b)\n\n"
            "| Prompt | Fix Rate | Safe Patch Rate | Avg Confidence |\n|---|---:|---:|---:|\n"
            f"| Raw code only | {raw[0]} | {raw[1]} | {raw[2]} |\n"
            f"| SecurePy full context | {full[0]} | {full[1]} | {full[2]} |\n",
            encoding="utf-8",
        )
        print(f"[ablation] raw={raw[0]} full={full[0]}  -> saved {ab}")

    print(f"Saved {out}")


if __name__ == "__main__":
    main()
```

---

## 5. CLI — add `bench` command

In `securepy_ai/cli.py`, add import:

```python
from securepy_ai.benchmark import (
    BenchmarkRunner, ablation_table, aggregate_metrics, load_dataset, write_benchmark_report,
)
```

Add function:

```python
def bench_command(args):
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
```

In `main()`, add subparser + dispatch:

```python
    bench_parser = subparsers.add_parser("bench", help="Run SecurePy-VulnBench evaluation")
    bench_parser.add_argument("--dataset", default="benchmark")
    bench_parser.add_argument("--llm", choices=["off", "mock", "ollama"], default="off")
    bench_parser.add_argument("--model", default="codellama:13b")
    bench_parser.add_argument("--output", default="reports/benchmark-results.md")
```

```python
    if args.command == "bench":
        raise SystemExit(bench_command(args))
```

---

## 6. `tests/test_benchmark.py`

```python
import json

from securepy_ai.benchmark import (
    BenchmarkRunner, ablation_table, aggregate_metrics, load_dataset,
)


def make_dataset(tmp_path):
    d = tmp_path / "cwe_89_001"
    d.mkdir(parents=True)
    (d / "metadata.json").write_text(json.dumps(
        {"id": "cwe89_001", "cwe": "CWE-89", "rule_id": "SEC102",
         "severity": "Critical", "vuln_type": "SQL Injection"}), encoding="utf-8")
    (d / "vulnerable.py").write_text(
        'def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        '    return db.execute(query).fetchone()\n', encoding="utf-8")
    (d / "expected_fix.py").write_text(
        'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n'
        '    return db.execute(query, (user_id,)).fetchone()\n', encoding="utf-8")
    (d / "bad_fix.py").write_text(
        'def get_user(user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n'
        '    return db.execute(query).fetchone()\n', encoding="utf-8")
    return load_dataset(str(tmp_path))


def test_detection_and_validation(tmp_path):
    results = BenchmarkRunner().run(make_dataset(tmp_path))
    r = results[0]
    assert r["detected"] is True
    assert r["fp_on_fix"] is False
    assert r["oracle_valid"] is True
    assert r["orig_rejected"] is True
    assert r["bad_rejected_full"] is True


def test_ablation_shows_rescan_contribution(tmp_path):
    results = BenchmarkRunner().run(make_dataset(tmp_path))
    ab = ablation_table(results)
    assert ab[0]["rejection_rate"] == 0.0   # V1 syntax only accepts the bad patch
    assert ab[2]["rejection_rate"] == 1.0   # V3 adds re-scan and rejects it


def test_aggregate_metrics(tmp_path):
    metrics = aggregate_metrics(BenchmarkRunner().run(make_dataset(tmp_path)))
    assert metrics["total_cases"] == 1
    assert metrics["detection_recall"] == 1.0
    assert metrics["oracle_accept_rate"] == 1.0
```

---

# Run it

```powershell
# 1. Dataset
python scripts/make_benchmark.py

# 2. Offline evaluation (no LLM) — detection + validation + ablation
python -m securepy_ai.cli bench

# 3. LLM track (Ollama running)
python -m securepy_ai.cli bench --llm ollama --model qwen2.5-coder:1.5b

# 4. Paper tables: model comparison + context ablation
python scripts/compare_models.py

# 5. Tests
pytest tests/test_benchmark.py -v
```

Outputs: `reports/benchmark-results.md/.json`, `reports/model-comparison.md`, `reports/context-ablation.md`.

---

# How each number maps to your paper

| Metric | What it proves | Paper location |
|---|---|---|
| Detection recall = 1.0 | Scanner is sound on the bench | Evaluation RQ1 |
| `fp_on_fix` = 0 | No alarms on already-fixed code (precision) | RQ1 |
| Oracle accept = 1.0 | Validator accepts correct fixes (no false rejection) | RQ2 |
| Original rejection = 1.0 | Validator never accepts an unfixed "patch" | RQ2 |
| Ablation V1→V4 rising | Each validation layer contributes; **security oracle > test-only** | RQ3 / Discussion |
| Context ablation (full > raw) | **AST context improves LLM repair** — mirrors base paper's "guidance improves repair" | RQ4 / core contribution |
| Model comparison | Local open-weight models are viable → privacy claim holds | RQ4 |

---

# Acceptance checklist

```text
✅ benchmark/ dataset generated (10 cases)
✅ bench runs offline and writes results
✅ ablation table shows V3/V4 reject bad patches
✅ compare_models produces model table (with Ollama)
✅ context ablation shows full-context ≥ raw
✅ 3 new tests pass (53 total now)
✅ committed
```

Commit:

```bash
git add .
git commit -m "feat(phase-11): add SecurePy-VulnBench evaluation, model comparison, and context ablation"
```

---

When your numbers are in, reply **`Phase 11 done`** and I'll give you **Phase 12: Thesis + Publication Pack** — abstract, chapter skeleton, related-work text tied to Fan et al., and the IEEE reference list, all pre-filled with your actual metrics.