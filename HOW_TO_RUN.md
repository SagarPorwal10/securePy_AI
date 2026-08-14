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

### Check Package Version
```powershell
python -m securepy_ai.cli --version
```

---

## 🤖 AI Patch Generation (Phase 4)

SecurePy AI can generate fix candidates for detected vulnerabilities using a local LLM.

### Option A — Mock LLM (No Ollama required, great for testing)
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --mock-llm
```

### Option B — Real Local LLM via Ollama

#### 1. Start the Ollama server
Open a dedicated terminal and run:
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

### Useful `--fix` Flags

| Flag | Default | Description |
|---|---|---|
| `--fix` | off | Enable AI patch generation |
| `--mock-llm` | off | Use mock LLM (no Ollama needed) |
| `--model` | `codellama:13b` | Ollama model to use |
| `--ollama-url` | `http://127.0.0.1:11434` | Ollama server URL |
| `--timeout` | `180` | Request timeout in seconds |
| `--max-patches` | `3` | Max number of patches to generate |

### Example — Scan with context + 1 real patch
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py --fix --model qwen2.5-coder:1.5b --max-patches 1 --context
```

---

## 🧪 Running Automated Tests

### Run All Tests
```powershell
pytest tests/ -v
```

Expected output (25 tests):
```text
tests/test_context.py::test_sql_injection_context PASSED
tests/test_context.py::test_command_injection_context PASSED
tests/test_context.py::test_hardcoded_secret_context PASSED
tests/test_context.py::test_context_contains_surrounding_lines PASSED
tests/test_context.py::test_context_contains_cwe_guidance PASSED
tests/test_llm.py::test_extract_python_code_from_markdown PASSED
tests/test_llm.py::test_extract_invalid_python_code PASSED
tests/test_llm.py::test_patch_generator_with_mock_llm PASSED
tests/test_llm.py::test_prompt_contains_finding_details PASSED
tests/test_llm.py::test_prompt_includes_code_to_fix PASSED
tests/test_rules.py::... (10 tests) PASSED
tests/test_scanner.py::... (3 tests) PASSED
```

### Run Only Phase 4 LLM Tests
```powershell
pytest tests/test_llm.py -v
```

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
