# How to Run SecurePy AI — Complete Guide

Covers everything built so far: **Phases 1–9 (engine + CI)**, **Phase 10–10.4 (live dashboard + remediation)**, **Phase 10.5 (Issue Store)**, and **Phase 11 (benchmarking)**.

---

## 🗺️ Feature Map

| Layer | What it is | How to run |
|---|---|---|
| Engine (Phases 1–9) | AST SAST + context + LLM patches + validation + reports + CI policies | `python -m securepy_ai.cli scan …` |
| Benchmark (Phase 11) | SecurePy-VulnBench evaluation + ablation | `python -m securepy_ai.cli bench` |
| Backend (Phase 10+) | FastAPI server exposing scan / git / issues APIs | `python server.py` |
| Dashboard (Phase 10+) | React operations console + remediation + issues queue | `cd dashboard && npm run dev` |
| CI/CD (Phase 9) | GitHub Action: PR scan, comment, SARIF, severity gate | push a PR |

---

## 🚀 Quick Start (Windows PowerShell)

```powershell
cd "c:\Users\SAAGAR PORWAL\Desktop\sem 3\coding\securePy AI"

# Only once, if PowerShell blocks activation:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Activate environment (you'll see (.venv) in the prompt)
.venv\Scripts\Activate.ps1

# Dependencies (if not already installed)
pip install rich fastapi uvicorn pytest
```

### Optional: real local LLM (Ollama)

```powershell
# Terminal A (leave running)
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve

# One-time model pull (any terminal)
ollama pull qwen2.5-coder:1.5b      # lightweight default (~1 GB)
# alternatives: codellama:13b | deepseek-coder:6.7b | qwen2.5-coder:7b
ollama list
```

---

## 🔍 Engine CLI (Phases 1–9)

```powershell
# Detection (Phase 1–2)
python -m securepy_ai.cli scan examples/vulnerable.py
python -m securepy_ai.cli scan securepy_ai/          # whole folder

# Context extraction (Phase 3)
python -m securepy_ai.cli scan examples/vulnerable.py --context

# CWE-aware prompts (Phase 5)
python -m securepy_ai.cli scan examples/vulnerable.py --show-prompts --max-prompts 2

# AI patches + validation (Phase 4–6)
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model qwen2.5-coder:1.5b

# Reports (Phase 7)
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --report all --output-dir reports

# CI mode + baseline (Phase 8)
python -m securepy_ai.cli scan . --quiet --fail-on high
python -m securepy_ai.cli scan . --create-baseline baseline.json --fail-on none
python -m securepy_ai.cli scan . --baseline baseline.json --fail-on high

# Diff-only file list (Phase 9, used by the Action)
python -m securepy_ai.cli scan --files-from-json '["examples/vulnerable.py"]' --fail-on high

python -m securepy_ai.cli --version
```

### `--fix` flags

| Flag | Default | Description |
|---|---|---|
| `--fix` | off | Enable AI patch generation |
| `--mock-llm` | off | Offline mock LLM (no Ollama) |
| `--model` | codellama:13b | Ollama model |
| `--ollama-url` | http://127.0.0.1:11434 | Ollama server |
| `--timeout` | 180 | Request timeout (s) |
| `--max-patches` | 3 | Max patches to generate |
| `--skip-validation` | off | Skip Phase 6 validation |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at/above `--fail-on` threshold |
| 1 | Blocking findings found |
| 2 | Scanner/tool error (e.g. Ollama unreachable) |

---

## 📊 Benchmark (Phase 11)

```powershell
# 1. Generate the starter dataset (5 cases, one per CWE)
python scripts/make_benchmark.py

# 2. Run evaluation (offline, no LLM)
python -m securepy_ai.cli bench

# 3. Run with the LLM generation track
python -m securepy_ai.cli bench --llm ollama --model qwen2.5-coder:1.5b
```

Options: `--dataset benchmark` · `--llm off|mock|ollama` · `--model …` · `--output reports/benchmark-results.md`

Outputs: `reports/benchmark-results.md` + `.json` containing:
- Detection recall & false-positives-on-fixed-code
- Oracle patch accept rate & original-as-patch rejection
- Validation-layer ablation (V1 syntax → V4 full)
- Optional LLM fix-rate / safe-rate / confidence

---

## 🧪 Tests

```powershell
pytest tests/ -v
```

| File | Tests |
|---|---:|
| test_context.py | 5 |
| test_llm.py | 5 |
| test_patch_validator.py | 17 |
| test_prompt_builder.py | 8 |
| test_rules.py | 12 |
| test_scanner.py | 3 |
| test_benchmark.py | 3 |
| **Total** | **53** |

---

## 🖥️ Live Product (Backend + Dashboard)

Open **three terminals** (venv active):

```powershell
# Terminal A — Ollama (optional, real LLM only)
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve

# Terminal B — Backend API (http://localhost:8000)
python server.py

# Terminal C — Dashboard (http://localhost:5173)
cd dashboard
npm run dev
```

### Console (default view)
1. Configure target / model; toggle `--fix`, `--mock-llm`, `--validate`.
2. Click **`$ securepy-ai scan`** → live scan, findings, LCS diff, 4-tier validation badges.
3. **History ledger** — every scan archived to `reports/history/`; click to reload.
4. **Remediation actions** — `download .patch` · `apply → working tree` (backup saved to `reports/backups/`) · `commit locally` (branch `securepy/fixes`, **never pushes**). Stale-patch snippet guard refuses outdated patches.
5. **Working-tree card** — live modified-file list, `Inspect Diff`, one-click `Revert`.
6. **Audit trail** — streams `reports/audit.jsonl` (`[APPLY] [PATCH_FILE] [COMMIT] [REVERT] [APPLY_REJECTED]`).
7. **Upload JSON** — inspect any `securepy-ai-report.json` from CLI or CI.

### Issues view (Phase 10.5 — Issue Store)
Switch to **issues** in the navbar.

- Issues are **auto-created on every scan** (deduped by fingerprint), with SLA due dates, risk scores, occurrences, and audit history.
- **Auto-verify:** fix the code and re-scan → issue flips to `fixed` automatically.
- **Regression:** a closed issue detected again reopens with a regression count.
- KPIs: open / overdue / fixed / fix-rate / **MTTR**, plus weekly opened-vs-fixed trend bars.
- Lifecycle actions in the detail panel: `start` · `mark fixed` · `false positive` (reason required) · `accept risk` (reason required) · `reopen` · `assign`.

API (open in browser or PowerShell):

```text
GET  http://localhost:8000/api/issues?status=open&overdue=false
GET  http://localhost:8000/api/issues/{id}
POST http://localhost:8000/api/issues/{id}/transition   {"action":"false_positive","reason":"…","actor":"sagar"}
POST http://localhost:8000/api/issues/{id}/assign       {"owner":"sagar"}
GET  http://localhost:8000/api/trends
GET  http://localhost:8000/api/audit
```

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/issues/<ID>/transition" `
  -ContentType "application/json" `
  -Body '{"action":"false_positive","reason":"test-only code","actor":"sagar"}'
```

Issue data lives in `reports/db/issues.json` (+ lifecycle audit in `reports/db/audit.jsonl`). To reset the store, delete `reports/db/`.

---

## 🤖 CI/CD (Phase 9)

Add `.github/workflows/securepy-ai.yml`:

```yaml
name: SecurePy AI Security Scan
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  securepy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Run SecurePy AI
        id: securepy
        uses: ./
        continue-on-error: true
        with:
          target: "."
          fail_on: high
          report: all
          output_dir: reports
          github_token: ${{ secrets.GITHUB_TOKEN }}
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with: { name: securepy-reports, path: reports/ }
      - name: Fail on blocking findings
        if: steps.securepy.outputs.exit_code == '1'
        run: exit 1
```

Useful inputs: `diff_only: true` (scan only changed files) · `enable_fix: mock` (demo patches in CI) · `baseline: baseline.json`.

Test the CI entrypoint locally (Linux/macOS/WSL):

```bash
export GITHUB_WORKSPACE="$(pwd)" INPUT_TARGET="examples/vulnerable.py" \
  INPUT_FAIL_ON="high" INPUT_REPORT="all" INPUT_OUTPUT_DIR="reports" \
  INPUT_BASELINE="" INPUT_DIFF_ONLY="false" INPUT_ENABLE_FIX="off" \
  PYTHONPATH="$(pwd):${PYTHONPATH:-}"
bash action/entrypoint.sh
```

---

## ✅ "Run Everything" 60-Second Checklist

```powershell
.venv\Scripts\Activate.ps1
pytest tests/ -v                                   # 53 passed
python scripts/make_benchmark.py
python -m securepy_ai.cli bench                    # evaluation tables
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --report all
python server.py                                   # terminal B
# terminal C:
cd dashboard; npm run dev                          # → http://localhost:5173
```

Then in the browser: scan → review → apply/commit → re-scan (auto-verify) → check **issues** queue & trends.

---

## ❓ Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named 'rich'` | Activate `.venv`, or use `.venv\Scripts\python` |
| `No module named 'securepy_ai'` | Run from the project root |
| `Ollama is not reachable` | Start Ollama in its own terminal, or use `--mock-llm` |
| Patch shows `[FAIL]` | Expected — validation is working. Try a stronger model / more patches |
| Action `permission denied` | `git update-index --chmod=+x action/entrypoint.sh scripts/pr_comment.py` |
| PR comment not posted | Workflow needs `pull-requests: write` + `github_token` input |
| Issues view empty | Run a scan through the dashboard (or CLI) first; store syncs on `/api/scan` |
| Reset issue store | Delete `reports/db/` |