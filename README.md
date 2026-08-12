# SecurePy AI

SecurePy AI is an AST-aware SAST scanner for Python.

This repository is being developed in phases:

- Phase 1: Core AST scanner
- Phase 2: Security rules engine
- Phase 3: Context extraction
- Phase 4: Local LLM integration
- Phase 5: Prompt builder
- Phase 6: Patch validator
- Phase 7: Reporting engine
- Phase 8: CLI enhancements
- Phase 9: GitHub Action integration
- Phase 10: Dashboard visualization

## Quick Start & Usage Guide

For step-by-step instructions on running the scanner and resolving environment issues, see [HOW_TO_RUN.md](HOW_TO_RUN.md).

### Activate Environment & Run Scan

```bash
.venv\Scripts\Activate.ps1
python -m securepy_ai.cli scan examples/vulnerable.py
```

## Run Tests


```bash
pytest tests/ -v
```
