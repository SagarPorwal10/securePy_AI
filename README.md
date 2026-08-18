# SecurePy AI

## Context-Aware LLM-Assisted Auto-Remediation of Python Security Vulnerabilities

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python"/>
  <img src="https://img.shields.io/badge/Security-SAST-red.svg" alt="Security"/>
  <img src="https://img.shields.io/badge/AI-LLM-orange.svg" alt="AI"/>
  <img src="https://img.shields.io/badge/AST-Code%20Analysis-green.svg" alt="AST"/>
  <img src="https://img.shields.io/badge/LLM-Ollama-yellow.svg" alt="Ollama"/>
  <img src="https://img.shields.io/badge/Research-Cybersecurity-purple.svg" alt="Research"/>
</p>

**SecurePy AI** is a research-oriented security tool that extends traditional Static Application Security Testing (SAST) from **vulnerability detection** to **automated vulnerability remediation**.

It combines:

- AST-based static security analysis
- CWE-aware vulnerability context extraction
- Local Large Language Models (LLMs)
- Security-specific patch validation
- Confidence-based patch recommendation
- CI/CD-friendly GitHub Action integration

The goal of SecurePy AI is not only to detect vulnerabilities, but also to generate secure, validated, and explainable patches for Python code.

---

## Project Vision

Traditional SAST tools such as Bandit and Semgrep are effective at detecting insecure patterns, but they usually stop at detection. Developers must manually understand the issue, identify the correct secure pattern, and write the fix.

SecurePy AI aims to close this gap by providing an automated pipeline:

```text
Vulnerable Python Code
        ↓
AST-Based Vulnerability Detection
        ↓
Security Context Extraction
        ↓
CWE-Specific LLM Prompting
        ↓
Secure Patch Generation
        ↓
Multi-Layer Patch Validation
        ↓
Confidence-Based Recommendation / Auto-Fix
```

---

## Key Features

### 1. AST-Based Python Security Scanning
SecurePy AI uses Python’s `ast` module to perform recursive traversal of source code and detect insecure coding patterns.

### 2. CWE-Aware Detection
Each detected issue is mapped to a relevant CWE category such as:

- SQL Injection
- OS Command Injection
- Insecure Deserialization
- Hardcoded Credentials
- Code Injection
- Path Traversal
- Weak Cryptography
- Weak Randomness

### 3. Security Context Extraction
Instead of giving raw code to the LLM, SecurePy AI extracts structured context:

- Vulnerable line
- Parent function
- Variable names
- Data-flow hints
- Sink/source information
- CWE category
- Severity level
- Suggested fix strategy

This helps the LLM generate more accurate and security-aware patches.

### 4. Local LLM Remediation
SecurePy AI supports local open-source models using **Ollama**, including:

- Code Llama
- DeepSeek Coder
- StarCoder
- Llama-based instruction models

This allows source code analysis without sending sensitive code to external cloud APIs.

### 5. Multi-Layer Patch Validation
Generated patches are not blindly accepted. SecurePy AI validates them through:

- Python syntax validation
- AST parsing validation
- SAST re-scan
- Logic preservation checks
- Regression checks
- New vulnerability checks

### 6. Confidence Scoring
Each generated patch is assigned a confidence score.

| Confidence | Action |
|---:|---|
| 85–100 | Safe for automatic suggestion |
| 60–84 | Recommended for human review |
| Below 60 | Patch rejected or flagged |

### 7. GitHub Action Integration
SecurePy AI can be integrated into CI/CD pipelines to scan pull requests and suggest security fixes automatically.

---

## Research Motivation

Recent research has shown that AI coding assistants may generate insecure code and that machine learning models can detect vulnerabilities. However, most existing systems focus only on detection or general bug repair.

SecurePy AI addresses the following research gaps:

1. **Detection-to-Repair Gap**  
   Existing SAST tools detect vulnerabilities but do not automatically generate secure fixes.

2. **Context Gap**  
   Generic LLM prompting often lacks structured security context such as CWE type, sink/source data, and AST-level function scope.

3. **Validation Gap**  
   Many LLM-generated patches are syntactically valid but may still be insecure or may alter program logic.

4. **Privacy Gap**  
   Cloud-based LLM APIs may not be suitable for proprietary or sensitive source code.

5. **CI/CD Gap**  
   Few research prototypes integrate vulnerability repair directly into developer workflows.

---

## Supported Vulnerability Categories

| CWE ID | Vulnerability Type | Example Vulnerable Pattern | Secure Fix Strategy |
|---|---|---|---|
| CWE-89 | SQL Injection | f-string SQL query | Parameterized queries |
| CWE-78 | OS Command Injection | `os.system()` with user input | `subprocess.run()` with argument list |
| CWE-502 | Insecure Deserialization | `pickle.loads()`, `yaml.load()` | `json.loads()`, `yaml.safe_load()` |
| CWE-798 | Hardcoded Credentials | `password = "admin"` | Environment variables |
| CWE-94 | Code Injection | `eval()`, `exec()` | Safe parsers / removal of dynamic execution |
| CWE-22 | Path Traversal | Unsafe file path construction | Path normalization and validation |
| CWE-327 | Weak Cryptography | MD5 / SHA1 | SHA-256 or stronger algorithms |
| CWE-338 | Weak Randomness | `random.randint()` for tokens | `secrets.token_hex()` |

---

## System Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                     SecurePy AI Pipeline                     │
└──────────────────────────────────────────────────────────────┘

        ┌──────────────────────┐
        │  Python Source Code  │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  SecurePy AST Scanner │
        │  Rule-Based Detection │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ VulnerabilityContext │
        │ CWE, sink, function, │
        │ variables, severity  │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Prompt Engineering  │
        │  CWE-Specific Prompt │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Local LLM via Ollama │
        │ CodeLlama/DeepSeek   │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Candidate Patch     │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   Patch Validator    │
        │ Syntax + AST + SAST  │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Confidence Scoring  │
        └──────────┬───────────┘
                   │
       ┌───────────┴───────────┐
       │                       │
       ▼                       ▼
┌──────────────┐       ┌──────────────┐
│ Auto-Suggest │       │ Human Review │
└──────────────┘       └──────────────┘
```

---

## Planned Repository Structure

```text
securepy-ai/
│
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
│
├── securepy/
│   ├── __init__.py
│   ├── scanner.py
│   ├── cwe_mapper.py
│   └── rules/
│       ├── sqli.py
│       ├── command_injection.py
│       ├── deserialization.py
│       ├── hardcoded_secrets.py
│       ├── code_injection.py
│       ├── path_traversal.py
│       ├── weak_crypto.py
│       └── weak_random.py
│
├── context/
│   ├── __init__.py
│   ├── extractor.py
│   ├── scope_resolver.py
│   ├── taint_analyzer.py
│   └── models.py
│
├── remediation/
│   ├── __init__.py
│   ├── remediator.py
│   ├── model_manager.py
│   └── prompts/
│       ├── base_prompt.py
│       ├── sqli_prompt.py
│       ├── command_injection_prompt.py
│       ├── deserialization_prompt.py
│       ├── hardcoded_credentials_prompt.py
│       ├── code_injection_prompt.py
│       ├── path_traversal_prompt.py
│       ├── weak_crypto_prompt.py
│       └── weak_random_prompt.py
│
├── validation/
│   ├── __init__.py
│   ├── validator.py
│   ├── ast_equivalence.py
│   ├── rescan_checker.py
│   └── test_runner.py
│
├── scoring/
│   ├── __init__.py
│   └── confidence.py
│
├── integrations/
│   ├── github_action.py
│   └── action.yml
│
├── cli/
│   ├── __init__.py
│   └── main.py
│
├── benchmarks/
│   ├── dataset.json
│   ├── cwe089_sqli/
│   ├── cwe078_command_injection/
│   ├── cwe502_deserialization/
│   ├── cwe798_hardcoded_credentials/
│   ├── cwe094_code_injection/
│   ├── cwe022_path_traversal/
│   ├── cwe327_weak_crypto/
│   ├── cwe338_weak_random/
│   └── safe_samples/
│
├── tests/
│   ├── test_scanner.py
│   ├── test_context_extractor.py
│   ├── test_remediator.py
│   ├── test_validator.py
│   └── test_confidence.py
│
└── docs/
    ├── architecture.md
    ├── research_gap.md
    ├── benchmark.md
    └── results.md
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/SagarPorwal10/securepy-ai.git
cd securepy-ai
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows:

```bash
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Ollama

Install Ollama from:

```text
https://ollama.com
```

### 5. Pull a Local Code Model

Recommended:

```bash
ollama pull codellama:13b
```

Alternative lightweight model:

```bash
ollama pull deepseek-coder:6.7b
```

---

## Usage

### Scan a Python File or Directory

```bash
python -m cli.main scan --path samples/ --report report.json
```

### Generate Security Fixes

```bash
python -m cli.main fix \
  --path samples/ \
  --model codellama:13b \
  --confidence 80 \
  --output patched/
```

### Validate Generated Patches

```bash
python -m cli.main validate \
  --original samples/ \
  --patched patched/
```

### Run Benchmark Evaluation

```bash
python -m cli.main benchmark \
  --dataset benchmarks/dataset.json
```

---

## Example

### Vulnerable Code

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
```

### Detected Vulnerability

```text
CWE-89: SQL Injection
Severity: HIGH
Sink: cursor.execute()
Tainted Variable: username
Fix Strategy: Use parameterized query
```

### SecurePy AI Generated Patch

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
```

---

## Benchmark: PySecRepair-Bench

SecurePy AI will be evaluated on a custom Python security remediation benchmark called **PySecRepair-Bench**.

### Benchmark Composition

| Source Type | Description |
|---|---|
| Synthetic Vulnerable Samples | Manually created vulnerable Python functions |
| Vulnerable Applications | Samples extracted from intentionally vulnerable Python apps |
| CVE-Inspired Samples | Patterns derived from real Python CVEs and advisories |
| Safe Samples | Non-vulnerable samples used for false-positive evaluation |

### Target Dataset Size

```text
300+ vulnerable and safe Python samples
```

### Target CWE Coverage

```text
CWE-89, CWE-78, CWE-502, CWE-798,
CWE-94, CWE-22, CWE-327, CWE-338
```

### Dataset Metadata Format

```json
{
  "id": "cwe089_sqli_001",
  "cwe_id": "CWE-89",
  "cwe_name": "SQL Injection",
  "language": "python",
  "source": "synthetic",
  "file": "benchmarks/cwe089_sqli/synthetic/sqli_001.py",
  "fixed_file": "benchmarks/cwe089_sqli/synthetic/sqli_001_fix.py",
  "vulnerable": true,
  "vulnerable_lines": [6, 7],
  "fix_strategy": "Use parameterized query",
  "severity": "HIGH",
  "manual_verified": true
}
```

---

## Evaluation Metrics

### Detection Metrics

- Precision
- Recall
- F1-Score
- False Positive Rate
- False Negative Rate

### Remediation Metrics

- Fix Success Rate
- Valid Patch Rate
- Regression Rate
- New Vulnerability Introduction Rate
- Average Patch Generation Time
- Confidence Threshold Accuracy

---

## Baselines

SecurePy AI will be compared against the following baselines:

| Baseline | Purpose |
|---|---|
| Bandit | Existing Python SAST tool |
| Semgrep | Rule-based static analysis |
| Raw LLM Prompting | LLM receives only vulnerable code |
| LLM + CWE Prompt | LLM receives code and CWE type |
| SecurePy AI Full | Full AST context + validation pipeline |

---

## Ablation Study

To understand the contribution of each component, the following experiments will be performed:

| Experiment | Input Provided to LLM |
|---|---|
| A | Raw vulnerable code only |
| B | Raw code + vulnerability type |
| C | Raw code + CWE ID |
| D | Raw code + function scope |
| E | Raw code + AST-derived security context |
| F | SecurePy AI full pipeline with validation |

---

## GitHub Action Integration

SecurePy AI can be used as a GitHub Action to scan pull requests.

### Example Workflow

```yaml
name: SecurePy AI Security Scan

on:
  pull_request:
    branches:
      - main

jobs:
  securepy-ai:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run SecurePy AI Scan
        run: |
          python -m cli.main scan --path . --report securepy_report.json

      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: securepy-report
          path: securepy_report.json
```

---

## Research Base Papers

This project is inspired by and builds upon research from the following papers:

### 1. Vulnerability Detection

**VulDeePecker: A Deep Learning-Based System for Vulnerability Detection**  
Li et al., NDSS 2018  
arXiv: 1801.01681

**LineVul: A Transformer-based Line-Level Vulnerability Prediction**  
Fu and Tantithamthavorn, MSR 2022

### 2. LLM Code Generation

**Evaluating Large Language Models Trained on Code**  
Chen et al., 2021  
arXiv: 2107.03374

### 3. Security of AI-Generated Code

**Asleep at the Keyboard? Assessing the Security of GitHub Copilot’s Code Contributions**  
Pearce et al., IEEE S&P 2022  
arXiv: 2108.09293

### 4. LLM-Based Program Repair

**Automated Repair of Programs from Large Language Models**  
Fan et al., ICSE 2023  
arXiv: 2205.10583

---

## How SecurePy AI Differs from Existing Research

| Capability | Existing Detection Research | Existing APR Research | SecurePy AI |
|---|:---:|:---:|:---:|
| Detects vulnerabilities | ✅ | ❌ | ✅ |
| Generates patches | ❌ | ✅ | ✅ |
| Security-specific context | ❌ | ❌ | ✅ |
| CWE-aware prompting | ❌ | ❌ | ✅ |
| Security patch validation | ❌ | Partial | ✅ |
| Python-focused | Partial | Partial | ✅ |
| Local LLM support | ❌ | Partial | ✅ |
| CI/CD integration | ❌ | ❌ | ✅ |

---

## Development Roadmap

### Phase 1: SecurePy Scanner Extension
- Extend existing SecurePy AST scanner
- Add CWE mapping
- Add new vulnerability rules

### Phase 2: Context Extraction Engine
- Build `VulnerabilityContext`
- Extract function scope
- Extract sink/source hints
- Extract imports and variables

### Phase 3: LLM Remediation Engine
- Integrate Ollama
- Build CWE-specific prompt templates
- Generate patch candidates

### Phase 4: Patch Validation Engine
- Syntax validation
- AST re-parsing
- SAST re-scan
- Logic preservation checks

### Phase 5: Benchmark Creation
- Create PySecRepair-Bench
- Add synthetic vulnerable samples
- Add CVE-inspired samples
- Add safe samples

### Phase 6: Evaluation and Paper Writing
- Run baseline comparisons
- Perform ablation study
- Manually review generated patches
- Prepare results for thesis/publication

---

## Disclaimer

SecurePy AI is a research prototype. Generated patches should be reviewed by a human security engineer before deployment in production systems.

Automated patch generation can reduce remediation effort, but it does not guarantee complete security correctness.

---

## Author

**Sagar Porwal**  
National Forensic Sciences University, Delhi  
Integrated B.Tech–M.Tech in Computer Science (Cyber Security)

GitHub: [github.com/SagarPorwal10](https://github.com/SagarPorwal10)

---

## License

This project is intended for academic and research purposes.