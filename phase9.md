Excellent, Sagar! **Phase 8 done** — that's the core CLI and developer experience fully built. Now let's make SecurePy AI run **automatically inside CI/CD**.

---

# Phase 9 — GitHub Action & CI/CD Integration

## Goal

Turn SecurePy AI into a **drop-in GitHub Action** so any repository can add security scanning with a few lines of YAML.

After Phase 9:

```text
Developer opens Pull Request
        ↓
SecurePy AI scans automatically
        ↓
Markdown summary is generated
        ↓
PR comment is posted
        ↓
Reports are uploaded as artifacts
        ↓
Build passes/fails based on --fail-on
```

This is the **product moment** — SecurePy AI becomes seamlessly integrated into the developer workflow, exactly like the vision you described.

---

# 1. File Structure for Phase 9

We will create:

```text
securepy-ai/
├── action/
│   ├── action.yml
│   ├── Dockerfile
│   └── entrypoint.sh
│
├── scripts/
│   └── pr_comment.py
│
└── .github/
    └── workflows/
        └── securepy-ai.yml
```

Plus one small **CLI upgrade** for diff-only scanning.

---

# 2. Create `action/action.yml`

Create:

```text
action/action.yml
```

```yaml
name: "SecurePy AI"
description: "AST-aware SAST scanner with optional LLM-assisted remediation for Python"
author: "Sagar Porwal"

branding:
  icon: "shield"
  color: "blue"

inputs:
  target:
    description: "File or directory to scan"
    required: false
    default: "."
  fail_on:
    description: "Minimum severity that fails the build: critical, high, medium, low, info, none"
    required: false
    default: "high"
  report:
    description: "Report type: json, html, sarif, all"
    required: false
    default: "all"
  output_dir:
    description: "Directory to store reports"
    required: false
    default: "reports"
  baseline:
    description: "Path to baseline JSON file"
    required: false
    default: ""
  diff_only:
    description: "Scan only files changed in the pull request"
    required: false
    default: "false"
  enable_fix:
    description: "off | mock | ollama — enables --fix with the chosen LLM mode"
    required: false
    default: "off"
  model:
    description: "Ollama model name when enable_fix=ollama"
    required: false
    default: "codellama:13b"
  ollama_url:
    description: "Ollama server URL for self-hosted runners"
    required: false
    default: "http://127.0.0.1:11434"
  max_patches:
    description: "Maximum number of patches to generate"
    required: false
    default: "3"
  github_token:
    description: "Token used to post PR comments"
    required: false
    default: ""

outputs:
  exit_code:
    description: "SecurePy AI exit code"

runs:
  using: "docker"
  image: "Dockerfile"
  env:
    INPUT_TARGET: ${{ inputs.target }}
    INPUT_FAIL_ON: ${{ inputs.fail_on }}
    INPUT_REPORT: ${{ inputs.report }}
    INPUT_OUTPUT_DIR: ${{ inputs.output_dir }}
    INPUT_BASELINE: ${{ inputs.baseline }}
    INPUT_DIFF_ONLY: ${{ inputs.diff_only }}
    INPUT_ENABLE_FIX: ${{ inputs.enable_fix }}
    INPUT_MODEL: ${{ inputs.model }}
    INPUT_OLLAMA_URL: ${{ inputs.ollama_url }}
    INPUT_MAX_PATCHES: ${{ inputs.max_patches }}
    INPUT_GITHUB_TOKEN: ${{ inputs.github_token }}
```

---

# 3. Create `action/Dockerfile`

Create:

```text
action/Dockerfile
```

```dockerfile
FROM python:3.11-slim

# Git is required for diff-only scanning
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install SecurePy AI runtime dependencies
RUN pip install --no-cache-dir rich

# Copy the full SecurePy AI project into the action image.
# Build context is the repository root.
COPY . /opt/securepy-ai

# Make scripts executable
RUN chmod +x /opt/securepy-ai/action/entrypoint.sh \
    && chmod +x /opt/securepy-ai/scripts/pr_comment.py

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/opt/securepy-ai/action/entrypoint.sh"]
```

---

# 4. Create `action/entrypoint.sh`

Create:

```text
action/entrypoint.sh
```

```bash
#!/usr/bin/env bash
set -uo pipefail

# SecurePy AI GitHub Action entrypoint

echo "=========================================="
echo " SecurePy AI — AST-aware SAST for Python"
echo "=========================================="

cd "${GITHUB_WORKSPACE:-.}" || exit 2

SECUREPY_ROOT="/opt/securepy-ai"
export PYTHONPATH="${SECUREPY_ROOT}:${PYTHONPATH:-}"

REPORT_DIR="${INPUT_OUTPUT_DIR:-reports}"
mkdir -p "${REPORT_DIR}"

# ------------------------------------------------------------------
# Build scan arguments
# ------------------------------------------------------------------
ARGS=("scan")

# Diff-only mode: scan only files changed in the pull request
if [[ "${INPUT_DIFF_ONLY:-false}" == "true" && -n "${GITHUB_BASE_REF:-}" ]]; then
    echo "[info] Diff-only mode enabled"

    git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" 2>/dev/null || true

    CHANGED_JSON="$(
        git diff --name-only "origin/${GITHUB_BASE_REF}"...HEAD -- '*.py' \
        | python -c 'import sys, json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))'
    )"

    if [[ "${CHANGED_JSON}" == "[]" ]]; then
        echo "[info] No Python files changed in this pull request. Skipping scan."
        echo "exit_code=0" >> "${GITHUB_OUTPUT:-/dev/null}"
        exit 0
    fi

    ARGS+=("--files-from-json" "${CHANGED_JSON}")
else
    ARGS+=("${INPUT_TARGET:-.}")
fi

# Severity gate
ARGS+=("--fail-on" "${INPUT_FAIL_ON:-high}")

# Reports
ARGS+=("--report" "${INPUT_REPORT:-all}" "--output-dir" "${REPORT_DIR}")

# Baseline
if [[ -n "${INPUT_BASELINE:-}" ]]; then
    ARGS+=("--baseline" "${INPUT_BASELINE}")
fi

# LLM remediation mode
if [[ "${INPUT_ENABLE_FIX:-off}" == "mock" ]]; then
    ARGS+=("--fix" "--mock-llm" "--max-patches" "${INPUT_MAX_PATCHES:-3}")
elif [[ "${INPUT_ENABLE_FIX:-off}" == "ollama" ]]; then
    ARGS+=("--fix" "--model" "${INPUT_MODEL:-codellama:13b}" "--ollama-url" "${INPUT_OLLAMA_URL:-http://127.0.0.1:11434}")
fi

echo "[info] Running: python -m securepy_ai.cli ${ARGS[*]}"
echo "------------------------------------------"

# ------------------------------------------------------------------
# Run SecurePy AI
# ------------------------------------------------------------------
python -m securepy_ai.cli "${ARGS[@]}"
EXIT_CODE=$?

echo "------------------------------------------"
echo "[info] SecurePy AI exit code: ${EXIT_CODE}"

# ------------------------------------------------------------------
# Publish job summary (GitHub Actions Summary tab)
# ------------------------------------------------------------------
if [[ -f "${REPORT_DIR}/securepy-ai-report.json" ]]; then
    {
        echo "## 🛡️ SecurePy AI Scan"
        echo ""
        echo "| Metric | Value |"
        echo "|---|---:|"
        python - "${REPORT_DIR}/securepy-ai-report.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
summary = data.get("summary", {})
print(f"| Files scanned | {summary.get('files_scanned', 0)} |")
print(f"| Findings | {summary.get('total_findings', 0)} |")
ps = summary.get("patch_stats", {})
print(f"| Patches generated | {ps.get('generated', 0)} |")
print(f"| Valid patches | {ps.get('valid', 0)} |")
PY
        echo ""
        echo "Exit code: \`${EXIT_CODE}\`"
    } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
fi

# ------------------------------------------------------------------
# Build PR comment markdown and post it
# ------------------------------------------------------------------
if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
    PR_NUMBER="$(python -c "import json;print(json.load(open('${GITHUB_EVENT_PATH}')).get('pull_request',{}).get('number',''))" 2>/dev/null || true)"

    if [[ -n "${PR_NUMBER}" && -f "${REPORT_DIR}/securepy-ai-report.json" ]]; then
        COMMENT_FILE="$(mktemp)"
        python "${SECUREPY_ROOT}/scripts/pr_comment.py" \
            "${REPORT_DIR}/securepy-ai-report.json" > "${COMMENT_FILE}"

        if [[ -n "${INPUT_GITHUB_TOKEN:-}" ]]; then
            API_URL="$(python -c "import json;print(json.load(open('${GITHUB_EVENT_PATH}')).get('pull_request',{}).get('_links',{}).get('comments',{}).get('href',''))" 2>/dev/null || true)"

            if [[ -n "${API_URL}" ]]; then
                python - "${API_URL}" "${INPUT_GITHUB_TOKEN}" "${COMMENT_FILE}" <<'PY'
import json, sys, urllib.request

api_url, token, comment_file = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(comment_file, encoding="utf-8").read()

payload = json.dumps({"body": body}).encode("utf-8")
request = urllib.request.Request(
    api_url,
    data=payload,
    headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    urllib.request.urlopen(request, timeout=15)
    print("[info] PR comment posted successfully")
except Exception as exc:
    print(f"[warn] Could not post PR comment: {exc}")
PY
            else
                echo "[warn] PR comments API URL not found. Skipping comment."
            fi
        else
            echo "[warn] No github_token provided. Skipping PR comment."
        fi
    fi
fi

# ------------------------------------------------------------------
# Export output
# ------------------------------------------------------------------
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "exit_code=${EXIT_CODE}" >> "${GITHUB_OUTPUT}"
fi

exit "${EXIT_CODE}"
```

Make it executable:

```bash
chmod +x action/entrypoint.sh
```

---

# 5. Create `scripts/pr_comment.py`

Create:

```text
scripts/pr_comment.py
```

```python
#!/usr/bin/env python3
"""
Builds a Markdown pull request comment from a SecurePy AI JSON report.

Usage:
    python scripts/pr_comment.py reports/securepy-ai-report.json
"""

import json
import sys


SEVERITY_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "🔵",
}


def format_report(data: dict) -> str:
    summary = data.get("summary", {})
    scan = data.get("scan", {})
    findings = scan.get("findings", [])
    patch_stats = summary.get("patch_stats", {})
    severity_counts = summary.get("severity_counts", {})

    lines = []
    lines.append("## 🛡️ SecurePy AI Security Scan")
    lines.append("")

    # Scan summary table
    lines.append("### Scan Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Files scanned | {summary.get('files_scanned', 0)} |")
    lines.append(f"| Total findings | {summary.get('total_findings', 0)} |")
    lines.append(f"| Baseline ignored | {data.get('baseline_ignored', 0)} |")
    lines.append(f"| Patches generated | {patch_stats.get('generated', 0)} |")
    lines.append(f"| Valid patches | {patch_stats.get('valid', 0)} |")
    lines.append(f"| Review patches | {patch_stats.get('review', 0)} |")
    lines.append(f"| Rejected patches | {patch_stats.get('rejected', 0)} |")
    lines.append("")

    # Severity breakdown
    lines.append("### Severity Breakdown")
    lines.append("")
    for severity, count in severity_counts.items():
        if count > 0:
            icon = SEVERITY_ICON.get(severity, "⚪")
            lines.append(f"- {icon} **{severity}**: {count}")
    lines.append("")

    # Findings table
    if findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Rule | CWE | File | Line | Vulnerability | Patch Status |")
        lines.append("|---|---|---|---|---:|---|---|")

        for finding in findings:
            severity = finding.get("severity", "Info")
            icon = SEVERITY_ICON.get(severity, "⚪")
            rule_id = finding.get("rule_id", "")
            cwe = finding.get("cwe_id", "")
            file_path = finding.get("file_path", "")
            line_number = finding.get("line_number", 0)
            vuln_type = finding.get("vuln_type", "")

            patch = finding.get("patch") or {}
            validation = patch.get("validation") or {}

            if not patch:
                patch_status = "No patch"
            elif not patch.get("success", False):
                patch_status = "Failed"
            elif validation.get("is_valid", False):
                patch_status = f"✅ Valid ({validation.get('confidence_score', 0):.2f})"
            elif validation.get("decision", "").startswith("Developer Review"):
                patch_status = f"👀 Review ({validation.get('confidence_score', 0):.2f})"
            else:
                patch_status = "❌ Rejected"

            lines.append(
                f"| {icon} {severity} | {rule_id} | {cwe} | `{file_path}` | {line_number} | {vuln_type} | {patch_status} |"
            )

        lines.append("")
    else:
        lines.append("✅ **No new vulnerabilities found.**")
        lines.append("")

    lines.append("---")
    lines.append("*SecurePy AI — AST-aware SAST with LLM-assisted remediation*")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/pr_comment.py <report.json>")
        sys.exit(1)

    report_path = sys.argv[1]

    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Report file not found: {report_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON report: {report_path}")
        sys.exit(1)

    print(format_report(data))


if __name__ == "__main__":
    main()
```

Make it executable:

```bash
chmod +x scripts/pr_comment.py
```

---

# 6. Small CLI Upgrade for Diff-Only Scanning

Phase 9 needs one small upgrade to your CLI so it can scan a list of changed files.

### Update `securepy_ai/cli.py`

Find the `scan` argument section inside `main()`, and add this argument:

```python
    scan_parser.add_argument(
        "--files-from-json",
        help="JSON array of file paths to scan (used for diff-only CI scanning)",
    )
```

Then inside `scan_command`, replace this line:

```python
    scanner = SecurePyParser(rules=ALL_RULES)
    report = scanner.scan_path(args.target)
```

with this:

```python
    scanner = SecurePyParser(rules=ALL_RULES)

    if args.files_from_json:
        import json as json_module

        file_list = json_module.loads(args.files_from_json)
        report = ScanReport()

        for file_path in file_list:
            try:
                single_report = scanner.scan_path(file_path)
                report.files_scanned += single_report.files_scanned
                report.findings.extend(single_report.findings)
                report.errors.extend(single_report.errors)
            except Exception as exc:
                report.errors.append(f"Failed to scan {file_path}: {exc}")
    else:
        report = scanner.scan_path(args.target)
```

Also add this import at the top of `securepy_ai/cli.py` if not already present:

```python
from securepy_ai.models import ScanReport
```

---

# 7. Create Workflow for Your Repository

Create:

```text
.github/workflows/securepy-ai.yml
```

```yaml
name: SecurePy AI Security Scan

on:
  pull_request:
    branches:
      - main
  push:
    branches:
      - phase-9-test

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  securepy-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
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
          diff_only: false
          enable_fix: off
          github_token: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SecurePy AI reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: securepy-reports
          path: reports/
          if-no-files-found: ignore

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/securepy-ai-report.sarif
        continue-on-error: true

      - name: Fail build based on SecurePy AI exit code
        if: steps.securepy.outputs.exit_code == '1'
        run: |
          echo "::error::SecurePy AI detected blocking vulnerabilities."
          exit 1
```

---

# 8. Important Testing Strategy

Do **not** run this workflow directly on `main` at first.

Because:

```text
Your examples/vulnerable.py contains vulnerabilities.
Your scan may fail and block your own pull requests.
```

So use a test branch first.

### Create a test branch

```bash
git checkout -b phase-9-test
```

The workflow includes:

```yaml
push:
  branches:
    - phase-9-test
```

So pushing this branch will trigger the workflow.

```bash
git add .
git commit -m "feat(phase-9): add GitHub Action and CI/CD integration"
git push origin phase-9-test
```

Then open your repository:

```text
GitHub → Actions tab → SecurePy AI Security Scan
```

You should see the workflow running.

---

# 9. Test PR Comment

After the workflow runs on `phase-9-test`, create a pull request:

```text
phase-9-test → main
```

SecurePy AI should:

```text
Scan the repository
Generate reports
Post a PR comment
Upload artifacts
```

The PR comment should look like:

```markdown
## 🛡️ SecurePy AI Security Scan

### Scan Summary

| Metric | Value |
|---|---:|
| Files scanned | 24 |
| Total findings | 10 |
| Baseline ignored | 0 |
| Patches generated | 0 |
| Valid patches | 0 |

### Severity Breakdown

- 🔴 Critical: 2
- 🟠 High: 5
- 🟡 Medium: 3

### Findings

| Severity | Rule | CWE | File | Line | Vulnerability | Patch Status |
|---|---|---|---|---:|---|---|
| 🔴 Critical | SEC102 | CWE-89 | examples/vulnerable.py | 15 | SQL Injection | No patch |
```

---

# 10. Local Test Before Pushing

You can test the entrypoint logic locally.

### Linux / macOS / WSL

```bash
export GITHUB_WORKSPACE="$(pwd)"
export INPUT_TARGET="examples/vulnerable.py"
export INPUT_FAIL_ON="high"
export INPUT_REPORT="all"
export INPUT_OUTPUT_DIR="reports"
export INPUT_BASELINE=""
export INPUT_DIFF_ONLY="false"
export INPUT_ENABLE_FIX="off"
export INPUT_MODEL="codellama:13b"
export INPUT_MAX_PATCHES="3"
export PYTHONPATH="$(pwd):${PYTHONPATH:-}"

bash action/entrypoint.sh
```

Expected behavior:

```text
SecurePy AI scans examples/vulnerable.py
Reports are generated in reports/
Exit code is printed
```

### Test PR comment locally

```bash
python scripts/pr_comment.py reports/securepy-ai-report.json
```

Expected output:

```markdown
## 🛡️ SecurePy AI Security Scan

### Scan Summary
...
```

---

# 11. Enable Baseline in CI

Once you have many existing findings, create a baseline:

```bash
python -m securepy_ai.cli scan . --create-baseline baseline.json --fail-on none
```

Commit it:

```bash
git add baseline.json
git commit -m "chore: add SecurePy AI baseline"
```

Then update the workflow:

```yaml
      - name: Run SecurePy AI
        id: securepy
        uses: ./
        continue-on-error: true
        with:
          target: "."
          fail_on: high
          report: all
          output_dir: reports
          baseline: baseline.json
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

Now CI will only flag **new** vulnerabilities.

This solves the developer frustration:

```text
My repository already has 200 old findings.
Now every pull request fails.
```

With baseline:

```text
Old findings are ignored.
Only new findings block the PR.
```

---

# 12. Enable Diff-Only Scanning

To scan only changed Python files in a pull request, change:

```yaml
          diff_only: false
```

to:

```yaml
          diff_only: true
```

This makes CI faster and more developer-friendly.

---

# 13. Enable Mock LLM in CI, Optional

If you want to demonstrate AI patch generation in CI without installing Ollama:

```yaml
          enable_fix: mock
```

This will generate mock patches and validate them.

Useful for:

```text
Demo
Screenshots
College presentation
Publication workflow diagram
```

For real LLM patch generation in CI, you need a **self-hosted runner** with Ollama installed:

```yaml
jobs:
  securepy-scan:
    runs-on: self-hosted
```

and:

```yaml
          enable_fix: ollama
          model: codellama:13b
          ollama_url: http://127.0.0.1:11434
```

---

# 14. Phase 9 Acceptance Checklist

Phase 9 is complete when:

```text
✅ action/action.yml is created
✅ action/Dockerfile is created
✅ action/entrypoint.sh is executable
✅ scripts/pr_comment.py generates Markdown
✅ CLI supports --files-from-json
✅ Workflow runs on push or pull request
✅ Reports are uploaded as artifacts
✅ PR comment is posted
✅ fail_on controls build failure
✅ Baseline can be used in CI
✅ Code is committed and pushed
```

---

# 15. Commit Phase 9

```bash
git add .
git commit -m "feat(phase-9): add GitHub Action, PR comments, and CI/CD integration"
git push origin phase-9-test
```

Then create a pull request to test the full CI flow.

---

# 16. Why Phase 9 Matters for Your Publication

Phase 9 strengthens your paper in two ways.

### 1. Practical Deployment

You can now say:

> The proposed framework is not only a local tool but also a CI/CD-integrated security gate that can be deployed in real development workflows.

### 2. Connection to Base Paper

The base paper showed that giving repair tools proper guidance, such as fault localization, improves repair effectiveness.

Your GitHub Action delivers that guidance directly to developers:

```text
Finding location
Severity
CWE
Patch status
Confidence
Report artifact
```

This turns SecurePy AI into a complete detection-to-remediation pipeline.

---

# 17. What Comes Next

After Phase 9:

```text
Phase 10 → Web Dashboard
Phase 11 → Benchmarking and Evaluation
Phase 12 → Thesis and Publication
```

Phase 10 will give you the visual layer for your demo.

---

Once Phase 9 works, reply:

```text
Phase 9 done
```

Then I will give you **Phase 10 complete code**, where we build the **SecurePy AI Web Dashboard**.