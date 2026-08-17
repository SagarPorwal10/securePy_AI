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
