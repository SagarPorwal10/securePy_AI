# How to Run SecurePy AI

This guide explains how to set up, activate, and run **SecurePy AI** on your machine — locally and in CI/CD.

---

## 🚀 Quick Start (Windows PowerShell)

### Step 1: Open Terminal in Project Directory
Ensure your terminal is inside the project root directory:
```powershell
cd "c:\Users\SAAGAR PORWAL\Desktop\sem 3\coding\securePy AI"
```

### Step 2: Activate the Virtual Environment
Activate the pre-configured `.venv` environment:
```powershell
.venv\Scripts\Activate.ps1
```
*(If you see `(.venv)` in your terminal prompt, the virtual environment is active!)*

> 💡 **PowerShell Execution Policy Error Fix**:  
> If PowerShell blocks script activation, run this command once:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

## 🔍 Scanning

### Scan a Single Python File
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py
```

### Scan an Entire Folder / Codebase
```powershell
python -m securepy_ai.cli scan securepy_ai/
```

### Show Extracted Security Context (Phase 3+)
Displays rich context (data flow, source/sink, imports, variables) for each finding:
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --context
```

### Show Generated LLM Prompts (Phase 5+)
Displays the CWE-aware structured prompt that will be sent to the LLM:
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --show-prompts --max-prompts 2
```

### Check Package Version
```powershell
python -m securepy_ai.cli --version
```

---

## 🤖 AI Patch Generation + Validation (Phase 4–6)

SecurePy AI generates fix candidates for detected vulnerabilities using a local LLM,
then **validates** each patch automatically (Phase 6).

### Option A — Mock LLM (No Ollama required, great for testing)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm
```

Expected output includes:
```text
Validation: [PASS]  Confidence: 100/100

  [OK]  Syntax valid        (+30)
  [OK]  Logic preserved     (+20)
  [OK]  Vulnerability fixed (+30)
  [OK]  No new vulns        (+20)
```

### Option B — Real Local LLM via Ollama

#### 1. Start the Ollama server
Open a **dedicated terminal** and run:
```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve
```
Leave this terminal running in the background.

#### 2. Pull a model (one-time)
The project uses `qwen2.5-coder:1.5b` by default (lightweight, ~986 MB):
```powershell
ollama pull qwen2.5-coder:1.5b
```

Other supported options:
```powershell
ollama pull codellama:13b       # best quality, needs ~8 GB RAM
ollama pull deepseek-coder:6.7b # good balance
ollama pull qwen2.5-coder:7b    # medium size
```

Verify models are available:
```powershell
ollama list
```

#### 3. Run scan with real LLM
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model qwen2.5-coder:1.5b
```

---

## ⚙️ All `--fix` Flags

| Flag | Default | Description |
|---|---|---|
| `--fix` | off | Enable AI patch generation |
| `--mock-llm` | off | Use mock LLM (no Ollama needed) |
| `--model` | `codellama:13b` | Ollama model to use |
| `--ollama-url` | `http://127.0.0.1:11434` | Ollama server URL |
| `--timeout` | `180` | Request timeout in seconds |
| `--max-patches` | `3` | Max number of patches to generate |
| `--skip-validation` | off | Skip Phase 6 patch validation (faster) |

---

## 📄 Report Generation (Phase 7)

SecurePy AI can export findings in **JSON**, **HTML**, and **SARIF** formats.

### Generate all report formats at once
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --report all --output-dir reports
```

### Generate a specific format
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --report json --output-dir reports
python -m securepy_ai.cli scan examples/vulnerable.py --report html --output-dir reports
python -m securepy_ai.cli scan examples/vulnerable.py --report sarif --output-dir reports
```

Reports are saved to:
```text
reports/securepy-ai-report.json
reports/securepy-ai-report.html
reports/securepy-ai-report.sarif
```

### Full pipeline with reports + AI patches
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --report all --output-dir reports
```

---

## 📊 Output Formats & Severity Gate (Phase 8)

### Quiet mode — CI-friendly one-liner output
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --quiet
```
Output:
```text
files_scanned=1 findings=10 baseline_ignored=0 errors=0 patches_generated=0 valid_patches=0 exit_code=1
```

### JSON output — machine-readable
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --format json
```

### Control when the build fails with `--fail-on`
```powershell
# Fail only on Critical findings
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on critical

# Fail on High and above (default)
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on high

# Never fail (useful for reporting only)
python -m securepy_ai.cli scan examples/vulnerable.py --fail-on none
```

| Exit code | Meaning |
|---|---|
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | Blocking findings found |
| `2` | Scanner error (e.g. Ollama unreachable) |

---

## 🔖 Baseline — Ignore Known Findings (Phase 8)

Baselines let CI ignore pre-existing findings so only **new** vulnerabilities block the build.

### Create a baseline from current findings
```powershell
python -m securepy_ai.cli scan . --create-baseline baseline.json --fail-on none
```

### Scan using a baseline (only new findings are reported)
```powershell
python -m securepy_ai.cli scan . --baseline baseline.json --fail-on high
```

Commit the baseline so CI always has it:
```powershell
git add baseline.json
git commit -m "chore: add SecurePy AI baseline"
```

---

## 🤖 GitHub Action / CI/CD (Phase 9)

SecurePy AI ships as a **Docker-based GitHub Action** — drop it into any repository with a few lines of YAML.

### Minimal workflow setup

Add `.github/workflows/securepy-ai.yml` to your repo:
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
        with:
          fetch-depth: 0

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
        with:
          name: securepy-reports
          path: reports/

      - name: Fail on blocking findings
        if: steps.securepy.outputs.exit_code == '1'
        run: exit 1
```

### Action inputs reference

| Input | Default | Description |
|---|---|---|
| `target` | `.` | File or directory to scan |
| `fail_on` | `high` | Severity gate: `critical`, `high`, `medium`, `low`, `info`, `none` |
| `report` | `all` | Report type: `json`, `html`, `sarif`, `all` |
| `output_dir` | `reports` | Directory to store reports |
| `baseline` | _(empty)_ | Path to baseline JSON file |
| `diff_only` | `false` | Scan only Python files changed in the PR |
| `enable_fix` | `off` | AI patches: `off`, `mock`, `ollama` |
| `model` | `codellama:13b` | Ollama model (when `enable_fix=ollama`) |
| `ollama_url` | `http://127.0.0.1:11434` | Ollama server URL |
| `max_patches` | `3` | Max patches to generate |
| `github_token` | _(empty)_ | Token for posting PR comments |

### Diff-only scanning (faster CI)
Only scan Python files that changed in the pull request:
```yaml
        with:
          diff_only: true
```

### Enable mock AI patches in CI (no Ollama needed)
Useful for demos and college presentations:
```yaml
        with:
          enable_fix: mock
          max_patches: 3
```

### Generate PR comment locally
Test the PR comment script against an existing report:
```powershell
python scripts/pr_comment.py reports/securepy-ai-report.json
```

Expected output:
```markdown
## 🛡️ SecurePy AI Security Scan

### Scan Summary

| Metric | Value |
|---|---:|
| Files scanned | 1 |
| Total findings | 10 |
...
```

### Diff-only scan from the CLI (Phase 9 feature)
Scan a specific list of files (used internally by the Action in diff-only mode):
```powershell
# PowerShell — pass a JSON array of file paths
python -m securepy_ai.cli scan --files-from-json '["examples/vulnerable.py"]' --fail-on high
```

---

## 📋 Common Commands — Quick Reference

### Phase 6 — Full pipeline (scan → context → patches → validation)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --max-patches 2
```

### Phase 6 — With real Ollama, 1 patch
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model qwen2.5-coder:1.5b --max-patches 1
```

### Phase 5 — Show CWE-aware prompts only (no LLM call)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --show-prompts --max-prompts 2
```

### Phase 4–6 — Full output: context + prompts + patches + validation
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --context --show-prompts --fix --mock-llm --max-patches 2
```

### Phase 7 — Full pipeline with all reports
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --report all --output-dir reports
```

### Phase 8 — CI-friendly quiet mode with severity gate
```powershell
python -m securepy_ai.cli scan . --quiet --fail-on high --report all --output-dir reports
```

### Phase 8 — Scan with baseline (new findings only)
```powershell
python -m securepy_ai.cli scan . --baseline baseline.json --fail-on high --quiet
```

### Phase 9 — Test CI entrypoint locally (Linux/macOS/WSL)
```bash
export GITHUB_WORKSPACE="$(pwd)"
export INPUT_TARGET="examples/vulnerable.py"
export INPUT_FAIL_ON="high"
export INPUT_REPORT="all"
export INPUT_OUTPUT_DIR="reports"
export INPUT_BASELINE=""
export INPUT_DIFF_ONLY="false"
export INPUT_ENABLE_FIX="off"
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"

bash action/entrypoint.sh
```

### Skip validation (speed test / offline comparison)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --skip-validation
```

---

## 🧪 Running Automated Tests

### Run All Tests (50 tests across all phases)
```powershell
pytest tests/ -v
```

Expected output:
```text
tests/test_context.py           5 tests  PASSED
tests/test_llm.py               5 tests  PASSED
tests/test_patch_validator.py  17 tests  PASSED
tests/test_prompt_builder.py    8 tests  PASSED
tests/test_rules.py            12 tests  PASSED
tests/test_scanner.py           3 tests  PASSED

50 passed in 0.32s
```

### Run Phase-Specific Tests

| Phase | Command |
|---|---|
| Phase 3 (context) | `pytest tests/test_context.py -v` |
| Phase 4 (LLM) | `pytest tests/test_llm.py -v` |
| Phase 5 (prompts) | `pytest tests/test_prompt_builder.py -v` |
| Phase 6 (validator) | `pytest tests/test_patch_validator.py -v` |
| Rules only | `pytest tests/test_rules.py -v` |
| All | `pytest tests/ -v` |

---

## 💡 Alternative Ways to Run (Without Activating `.venv`)

If you do not wish to run `Activate.ps1`, you can execute using the direct paths below:

### Option 1: Direct `.venv` Executable
```powershell
.venv\Scripts\python -m securepy_ai.cli scan examples/vulnerable.py
```

### Option 2: Windows Python Launcher
```powershell
py -m securepy_ai.cli scan examples/vulnerable.py
```

---

## ❓ Troubleshooting

### Error: `ModuleNotFoundError: No module named 'rich'`
**Cause**: The default `python` in your terminal is pointing outside `.venv`.  
**Fix**: Make sure you activated `.venv` via `.venv\Scripts\Activate.ps1`, or use `.venv\Scripts\python`.

### Error: `ModuleNotFoundError: No module named 'securepy_ai'`
**Cause**: The command was executed outside the root project folder.  
**Fix**: Ensure your working directory contains `securepy_ai/` and run `python -m securepy_ai.cli ...`.

### Error: `Ollama is not reachable` / `timed out waiting for server to start`
**Cause**: The Ollama server process is not running.  
**Fix**:
1. Open a separate terminal and run: `& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" serve`
2. Or open the **Ollama** desktop app from the Start menu and wait for the tray icon.
3. Or use `--mock-llm` to skip Ollama entirely for offline testing.

### Patch shows `[FAIL]` validation
**Cause**: The LLM didn't fully fix the vulnerability, or introduced a new one.  
**Fix**: This is expected behaviour — it shows Phase 6 validation is working. Try a stronger model or `--max-patches` with a higher limit to generate more attempts.

### GitHub Action fails with `permission denied` on entrypoint.sh
**Cause**: The shell script lost its executable bit during `git add`.  
**Fix**: Run once before pushing:
```bash
git update-index --chmod=+x action/entrypoint.sh scripts/pr_comment.py
git commit -m "fix: mark shell scripts as executable"
```

### GitHub Action: PR comment not posted
**Cause**: `github_token` input is missing or the workflow lacks `pull-requests: write` permission.  
**Fix**: Ensure the workflow has:
```yaml
permissions:
  pull-requests: write
```
and the step passes `github_token: ${{ secrets.GITHUB_TOKEN }}`.
