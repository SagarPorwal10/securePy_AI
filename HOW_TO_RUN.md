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

### Step 3: Run the Scanner

#### Scan a Single Python File
```powershell
python -m securepy_ai.cli scan examples/vulnerable.py
```

#### Scan an Entire Folder / Codebase
```powershell
python -m securepy_ai.cli scan securepy_ai/
```

#### Check Package Version
```powershell
python -m securepy_ai.cli --version
```

---

## 🧪 Running Automated Tests

Run the full `pytest` test suite to verify scanner rules and logic:
```powershell
pytest tests/ -v
```

Expected output:
```text
tests/test_scanner.py::test_detect_hardcoded_secret PASSED               [ 33%]
tests/test_scanner.py::test_ignore_normal_variable PASSED                [ 66%]
tests/test_scanner.py::test_scan_directory PASSED                        [100%]
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
