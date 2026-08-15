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
