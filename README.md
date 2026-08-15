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

## Architecture & Design

For complete Mermaid diagrams and end-to-end system architecture specifications, see [ARCHITECTURE.md](ARCHITECTURE.md).

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

## License & Intellectual Property

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

- ✅ **Free for Noncommercial Use**: You are free to inspect, study, test, and use this codebase for academic research, education, and personal projects.
- 🚫 **Commercial Use Prohibited**: Copying, redistributing, or incorporating this software into commercial products, paid services, APIs, or enterprise solutions for monetary gain is **strictly prohibited** without an explicit commercial license from the author.

**Copyright (c) 2026 Sagar Porwal**, National Forensic Sciences University, Delhi.  
For commercial inquiries: `sagarporwalofficial@gmail.com`

