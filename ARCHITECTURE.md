# SecurePy AI — Complete System Architecture

> **Context-Aware Static Analysis (SAST) with Local LLM Remediation, Security Oracle Validation, and CI/CD Gating**

---

## 1. High-Level End-to-End Architecture

```mermaid
flowchart TD
    %% Styling definitions
    classDef input fill:#1c2333,stroke:#58c4dc,stroke-width:1.5px,color:#dbe4ec
    classDef scanner fill:#0d141c,stroke:#7ee787,stroke-width:2px,color:#dbe4ec
    classDef remediator fill:#161b22,stroke:#d29922,stroke-width:2px,color:#dbe4ec
    classDef validator fill:#1a1020,stroke:#f85149,stroke-width:2px,color:#dbe4ec
    classDef output fill:#0b1017,stroke:#8b98a5,stroke-width:1.5px,color:#dbe4ec
    classDef ui fill:#091a28,stroke:#58c4dc,stroke-width:2px,color:#dbe4ec

    subgraph INGEST ["01 · Ingestion & Diff Filtering"]
        SRC["📁 Python Source Code\n(Repository / Examples)"]:::input
        GIT["🐙 Git Diff / PR Target\n(--files-from-json)"]:::input
        BASE["📄 Baseline Supressions\n(baseline.json)"]:::input
    end

    subgraph DETECTION ["02 · AST Traversal & Rule Engines"]
        PARSER["🌳 SecurePyParser\n(Python ast.parse)"]:::scanner
        
        subgraph RULES ["CWE Detection Engines"]
            R1["SEC101 · Hardcoded Secrets\n(CWE-798)"]:::scanner
            R2["SEC102 · SQL Injection\n(CWE-89)"]:::scanner
            R3["SEC103 · Command Injection\n(CWE-78)"]:::scanner
            R4["SEC104 · Insecure Deserialization\n(CWE-502)"]:::scanner
            R5["SEC105 · Dynamic Eval/Exec\n(CWE-95)"]:::scanner
        end

        CTX["🔍 Context Extractor\n- Function Scope\n- Taint Data-Flow\n- Sink / Source Detection\n- Surrounding Lines & Imports"]:::scanner
    end

    subgraph REMEDIATION ["03 · Local LLM Remediation (Offline)"]
        PROMPT["📝 PromptBuilder\n- CWE Defense Directives\n- Surrounding Context\n- Structural Constraints"]:::remediator
        OLLAMA["🦙 Local LLM Client (Ollama)\n- CodeLlama / DeepSeek / Qwen\n- 100% Offline (Privacy Preserved)"]:::remediator
        EXTRACT["✂️ Patch Extractor\n- Code Block Parser\n- Syntax Sanitizer"]:::remediator
    end

    subgraph VALIDATION ["04 · Multi-Layer Security Oracle"]
        V1{"1. Syntax Valid?\n(ast.parse)"}:::validator
        V2{"2. Logic Preserved?\n(Defs & signatures)"}:::validator
        V3{"3. Flaw Eliminated?\n(Re-scan original rule)"}:::validator
        V4{"4. Zero New Flaws?\n(Full rule re-scan)"}:::validator
        SCORE["⚖️ Confidence Scoring (0-100%)\n- Syntax (+30)\n- Logic (+20)\n- Flaw Fixed (+30)\n- No New Vulns (+20)"]:::validator
        ROUTE["🚦 Policy Router\n- ≥90%: AUTO APPLY\n- 60-89%: REVIEW REQUIRED\n- <60%: REJECT"]:::validator
    end

    subgraph OUTPUTS ["05 · Gating & Reporting Engine"]
        CLI["💻 Rich Terminal CLI\n(Tables, Panels, Colors)"]:::output
        JSON_REP["📊 JSON Report\n(securepy-ai-report.json)"]:::output
        HTML_REP["🌐 Standalone HTML Report\n(securepy-ai-report.html)"]:::output
        SARIF_REP["🛡️ SARIF Report\n(GitHub Code Scanning)"]:::output
        PR_BOT["💬 PR Automated Commenter\n(scripts/pr_comment.py)"]:::output
        ACTION["⚙️ GitHub Action / CI Gate\n(Exit Codes: 0 / 1 / 2)"]:::output
    end

    subgraph DASHBOARD ["06 · Phase 10 Web Dashboard (React + Vite)"]
        D_HERO["⚡ Streaming Terminal Replay"]:::ui
        D_PIPE["🔄 8-Stage Pipeline Inspector"]:::ui
        D_WORK["🛠️ Findings Workbench\n(Diff / Before / After)"]:::ui
        D_LIVE["📂 Dynamic JSON Report Loader"]:::ui
    end

    %% Flow Connections
    SRC --> PARSER
    GIT --> PARSER
    PARSER --> R1 & R2 & R3 & R4 & R5
    R1 & R2 & R3 & R4 & R5 --> BASE
    BASE -->|Unsuppressed Findings| CTX
    CTX -->|VulnerabilityFinding + Context| PROMPT
    PROMPT --> OLLAMA
    OLLAMA --> EXTRACT
    EXTRACT -->|PatchCandidate| V1
    
    V1 -->|Yes| V2
    V2 -->|Yes| V3
    V3 -->|Yes| V4
    V4 --> SCORE
    V1 -->|No| SCORE
    V2 -->|No| SCORE
    V3 -->|No| SCORE
    V4 -->|No| SCORE
    
    SCORE --> ROUTE
    ROUTE -->|ScanReport Object| CLI & JSON_REP & HTML_REP & SARIF_REP & ACTION
    ACTION --> PR_BOT
    JSON_REP -.->|Loads Report Data| D_LIVE
    D_LIVE --> D_WORK & D_HERO & D_PIPE
```

---

## 2. Component Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Runner
    participant CLI as SecurePy CLI (cli.py)
    participant Scanner as AST Scanner & Rules
    participant Context as Context Extractor
    participant LLM as Local LLM (Ollama)
    participant Oracle as Patch Validator
    participant Reporter as Reporter (JSON/HTML/SARIF)
    participant UI as Web Dashboard

    Dev->>CLI: run scan (e.g. securepy-ai scan --fix)
    CLI->>Scanner: Parse files to AST & run rule engines
    Scanner-->>CLI: Return raw VulnerabilityFindings (SEC101-SEC105)
    
    loop For each Finding
        CLI->>Context: Extract function scope, data-flow & surrounding lines
        Context-->>CLI: Return enriched VulnerabilityContext
        CLI->>LLM: Generate secure patch with CWE constraints
        LLM-->>CLI: Return PatchCandidate
        CLI->>Oracle: Validate patch against 4 security checks
        Oracle-->>CLI: Return PatchValidation (Confidence Score + Decision)
    end

    CLI->>Reporter: Generate JSON, HTML & SARIF artifacts
    Reporter-->>Dev: Print summary table + exit code (0 / 1 / 2)
    Dev->>UI: View interactive results in Web Dashboard
```

---

## 3. Four-Layer Security Oracle Architecture (Phase 6)

```mermaid
flowchart LR
    classDef step fill:#0d141c,stroke:#7ee787,stroke-width:1.5px,color:#dbe4ec
    classDef pass fill:#0b2e1b,stroke:#7ee787,stroke-width:2px,color:#7ee787
    classDef fail fill:#331014,stroke:#f85149,stroke-width:2px,color:#f85149
    classDef decision fill:#161b22,stroke:#d29922,stroke-width:2px,color:#dbe4ec

    PATCH["Candidate Patch Code"] --> S1["1. Syntax Check\n(ast.parse)"]:::step
    
    S1 -->|Valid Python| P1["+30 pts"]:::pass
    S1 -->|SyntaxError| F1["0 pts"]:::fail
    
    P1 --> S2["2. Logic Check\n(Definitions Preserved)"]:::step
    F1 --> S2
    
    S2 -->|Names Intact| P2["+20 pts"]:::pass
    S2 -->|Defs Removed| F2["0 pts"]:::fail
    
    P2 --> S3["3. Flaw Elimination\n(Re-scan Target Rule)"]:::step
    F2 --> S3
    
    S3 -->|Flaw Cleared| P3["+30 pts"]:::pass
    S3 -->|Still Vulnerable| F3["0 pts"]:::fail
    
    P3 --> S4["4. Zero Side-Effects\n(All Rules Re-scan)"]:::step
    F3 --> S4
    
    S4 -->|Clean AST| P4["+20 pts"]:::pass
    S4 -->|New Flaw Found| F4["0 pts"]:::fail
    
    P4 & F4 --> TOTAL["Total Confidence Score\n(0% to 100%)"]:::decision
    
    TOTAL -->|Score ≥ 90%| D1["🟢 AUTO APPLY\n(Safe to commit)"]:::pass
    TOTAL -->|60% ≤ Score < 90%| D2["🟡 REVIEW REQUIRED\n(Manual sign-off)"]:::decision
    TOTAL -->|Score < 60%| D3["🔴 REJECTED\n(Unsafe candidate)"]:::fail
```

---

## 4. CI/CD & GitHub Actions Gating Architecture (Phase 9)

```mermaid
flowchart TD
    classDef action fill:#0d141c,stroke:#58c4dc,stroke-width:1.5px,color:#dbe4ec
    classDef decision fill:#161b22,stroke:#d29922,stroke-width:2px,color:#dbe4ec
    classDef pass fill:#0b2e1b,stroke:#7ee787,stroke-width:2px,color:#7ee787
    classDef fail fill:#331014,stroke:#f85149,stroke-width:2px,color:#f85149

    PR["Pull Request / Git Push"] --> DOCKER["Docker Container Runner\n(action/Dockerfile + entrypoint.sh)"]:::action
    
    DOCKER --> DIFF["Determine Changed Files\n(git diff origin/main...HEAD)"]:::action
    DIFF --> SCAN["Run SecurePy AI Scanner\n(--files-from-json + --report all)"]:::action
    
    SCAN --> ARTIFACTS["Generate Reports\n(JSON, SARIF, HTML)"]:::action
    
    ARTIFACTS --> UPLOAD["Upload SARIF to GitHub Security Tab\n(github/codeql-action/upload-sarif)"]:::action
    ARTIFACTS --> COMMENT["Post Markdown Findings Table to PR\n(scripts/pr_comment.py)"]:::action
    
    SCAN --> GATE{"Evaluate Findings vs\n--fail-on Threshold"}:::decision
    
    GATE -->|No Blocking Vulns| PASS["Exit Code 0\n✅ CI Pipeline Passes"]:::pass
    GATE -->|Policy Breached| FAIL["Exit Code 1 / 2\n❌ CI Pipeline Blocks PR"]:::fail
```

---

## 5. Directory & Module Mapping

| Layer | Files / Directories | Responsibility |
|---|---|---|
| **Core Models** | [`securepy_ai/models.py`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/securepy_ai/models.py) | Data contracts (`VulnerabilityFinding`, `PatchCandidate`, `PatchValidation`, `ScanReport`) |
| **AST Scanner** | [`securepy_ai/scanner/`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/securepy_ai/scanner) | AST parsing, node visitors, CWE detection rules (SEC101–SEC105), context & taint extraction |
| **LLM Remediator** | [`securepy_ai/remediator/`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/securepy_ai/remediator) | Structured prompt generator, Ollama/Mock clients, code extraction, and 4-tier PatchValidator |
| **Reporting** | [`securepy_ai/reporter/`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/securepy_ai/reporter) | JSON, standalone interactive HTML, and SARIF v2.1.0 report writers |
| **CLI & Policy Engine**| [`securepy_ai/cli.py`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/securepy_ai/cli.py) | Rich terminal interface, exit codes (0/1/2), diff-only scanning, baseline filtering |
| **GitHub Action** | [`action/`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/action), [`scripts/pr_comment.py`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/scripts/pr_comment.py) | Docker container, entrypoint automation, PR Markdown summary poster |
| **Web Dashboard** | [`dashboard/`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/dashboard) | React + Vite security operations console, live report loader, diff workbench |
| **Legal Protection** | [`LICENSE`](file:///c:/Users/SAAGAR%20PORWAL/Desktop/sem%203/coding/securePy%20AI/LICENSE) | PolyForm Noncommercial License 1.0.0 (Intellectual property protection) |
