# How to Run SecurePy AI

This guide explains how to set up, activate, and run **SecurePy AI** on your machine.

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
| `--no-validate` | off | Skip Phase 6 patch validation (faster) |

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

### Skip validation (speed test / offline comparison)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm --no-validate
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
