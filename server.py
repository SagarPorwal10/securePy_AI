import difflib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict

from securepy_ai import __version__
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import ALL_RULES
from securepy_ai.remediator.llm_client import MockLLMClient, OllamaClient
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.remediator.patch_validator import PatchValidator
from securepy_ai.reporter.json_report import (
    build_report_dict,
    SecurePyJSONEncoder,
)

ROOT = Path(__file__).resolve().parent
HISTORY_DIR = ROOT / "reports" / "history"
BACKUP_DIR = ROOT / "reports" / "backups"
PATCH_DIR = ROOT / "reports" / "patches"
AUDIT_PATH = ROOT / "reports" / "audit.jsonl"

HISTORY_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
PATCH_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SecurePy AI API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_git(args):
    try:
        r = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "ok": r.returncode == 0,
            "out": r.stdout.strip(),
            "err": r.stderr.strip(),
        }
    except Exception as e:
        return {"ok": False, "out": "", "err": str(e)}


def audit(action: str, detail: dict):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "action": action,
        **detail,
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


class ScanRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    target: str = "examples/vulnerable.py"
    fix: bool = True
    mock_llm: bool = True
    model: str = "codellama:13b"
    do_validate: bool = Field(default=True, alias="validate")
    max_patches: int = 10


@app.get("/api/health")
def health():
    ollama_ok = False
    try:
        ollama_ok = OllamaClient().is_available()
    except Exception:
        ollama_ok = False

    return {
        "status": "ok",
        "version": __version__,
        "ollama": ollama_ok,
        "time": datetime.now(timezone.utc).isoformat(),
    }


_SKIP_DIRS = {".venv", "__pycache__", "node_modules", ".git", "tests", "benchmark", ".github"}


@app.get("/api/files")
def list_py_files():
    """Return a sorted list of scannable .py files relative to project root."""
    files = []
    for p in ROOT.rglob("*.py"):
        parts = set(p.relative_to(ROOT).parts)
        if parts & _SKIP_DIRS:
            continue
        rel = str(p.relative_to(ROOT)).replace("\\", "/")
        files.append(rel)
    return {"files": sorted(files)}


@app.get("/api/git/status")

def git_status():
    b = run_git(["rev-parse", "--abbrev-ref", "HEAD"])
    s = run_git(["status", "--porcelain"])
    return {
        "is_repo": b["ok"],
        "branch": b["out"] or None,
        "dirty": bool(s["out"]),
        "changed": [l.strip() for l in s["out"].splitlines() if l.strip()],
    }


@app.post("/api/scan")
def scan(req: ScanRequest):
    start = time.perf_counter()

    target_path = Path(req.target)
    if not target_path.exists():
        target_path = ROOT / req.target
        if not target_path.exists():
            raise HTTPException(404, f"Target path '{req.target}' does not exist.")

    # Security check: scan target must reside inside project root
    try:
        target_path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(400, "Scan target is outside the project root.")

    scanner = SecurePyParser(rules=ALL_RULES)
    report = scanner.scan_path(str(target_path))

    ContextEnricher().enrich(report)

    if req.fix and report.findings:
        client = MockLLMClient() if req.mock_llm else OllamaClient(model=req.model)
        validator = PatchValidator() if req.do_validate else None
        generator = PatchGenerator(client=client, validator=validator)
        generator.generate_for_report(report, max_patches=req.max_patches)

    payload = build_report_dict(report, target=req.target)
    payload["scan_time_ms"] = round((time.perf_counter() - start) * 1000, 1)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = HISTORY_DIR / f"scan_{ts}.json"
    path.write_text(
        json.dumps(payload, indent=2, cls=SecurePyJSONEncoder),
        encoding="utf-8",
    )
    payload["id"] = path.stem

    # Also update the live report in reports/ for static readers
    live_report_path = ROOT / "reports" / "securepy-ai-report.json"
    live_report_path.parent.mkdir(parents=True, exist_ok=True)
    live_report_path.write_text(
        json.dumps(payload, indent=2, cls=SecurePyJSONEncoder),
        encoding="utf-8",
    )

    # And in dashboard public folder if it exists
    dash_pub = ROOT / "dashboard" / "public" / "reports" / "securepy-ai-report.json"
    if dash_pub.parent.exists():
        dash_pub.write_text(
            json.dumps(payload, indent=2, cls=SecurePyJSONEncoder),
            encoding="utf-8",
        )

    return payload


@app.get("/api/report")
def latest():
    files = sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)
    if not files:
        std = ROOT / "reports" / "securepy-ai-report.json"
        if std.exists():
            try:
                return {"report": json.loads(std.read_text(encoding="utf-8"))}
            except Exception:
                pass
        return {"report": None}
    return {"report": json.loads(files[0].read_text(encoding="utf-8"))}


@app.get("/api/history")
def history():
    items = []
    for p in sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            items.append(
                {
                    "id": p.stem,
                    "generated_at": d.get("generated_at"),
                    "target": d.get("target"),
                    "findings": d.get("summary", {}).get("total_findings", 0),
                    "valid": d.get("summary", {}).get("patch_stats", {}).get("auto_apply", 0),
                }
            )
        except Exception:
            continue
    return {"history": items}


@app.get("/api/history/{scan_id}")
def get_history(scan_id: str):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(404, "Scan not found")
    return json.loads(path.read_text(encoding="utf-8"))


class ApplyRequest(BaseModel):
    file_path: str
    original_code: str
    patched_code: str
    finding_id: str = ""
    mode: str = "working_tree"  # "patch" | "working_tree" | "commit"
    branch: str = "securepy/fixes"
    message: str = ""


@app.post("/api/apply")
def apply_patch(req: ApplyRequest):
    if not req.original_code.strip():
        raise HTTPException(400, "No original code to match.")

    # Security check: must reside inside project root
    target = (ROOT / req.file_path).resolve()
    try:
        target.relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(400, "Path is outside project root.")

    if not target.exists():
        raise HTTPException(404, f"Target file '{req.file_path}' not found.")

    content = target.read_text(encoding="utf-8", errors="ignore")

    # Stale-patch guard: snippet match check
    if req.original_code not in content:
        audit("apply_rejected", {"finding": req.finding_id, "reason": "snippet mismatch"})
        raise HTTPException(
            409,
            "Original snippet not found in target file — the file changed since the scan. Re-scan first.",
        )

    new_content = content.replace(req.original_code, req.patched_code, 1)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # MODE 1: Generate downloadable .patch file (file NOT modified)
    if req.mode == "patch":
        diff = difflib.unified_diff(
            content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile="a/" + req.file_path.replace("\\", "/"),
            tofile="b/" + req.file_path.replace("\\", "/"),
        )
        patch_text = "".join(diff)
        patch_path = PATCH_DIR / f"{ts}_{Path(req.file_path).name}.patch"
        patch_path.write_text(patch_text, encoding="utf-8")
        audit("patch_file", {"finding": req.finding_id, "file": req.file_path, "path": str(patch_path)})
        return {"applied": False, "patch_text": patch_text, "pushed": False}

    # Backup before modifying the file
    shutil.copy2(target, BACKUP_DIR / f"{ts}_{target.name}.bak")

    # MODE 2 & 3: Modify working tree file
    target.write_text(new_content, encoding="utf-8")
    result = {"applied": True, "file": req.file_path, "mode": req.mode, "pushed": False}

    if req.mode == "commit":
        if req.branch:
            # Validate branch name: only allow safe git branch characters
            _SAFE_BRANCH = re.compile(r"^[a-zA-Z0-9/_.-]+$")
            if not _SAFE_BRANCH.match(req.branch):
                raise HTTPException(400, "Invalid branch name. Only alphanumerics, '/', '_', '-', and '.' are allowed.")
            # Try checking out the branch (create if doesn't exist)
            b_check = run_git(["checkout", req.branch])
            if not b_check["ok"]:
                run_git(["checkout", "-b", req.branch])
        run_git(["add", "--", req.file_path])
        msg = req.message or f"fix(security): {req.finding_id or 'securepy-ai'} auto-remediation (local, not pushed)"
        c = run_git(["commit", "-m", msg])
        result["committed"] = c["ok"]
        result["commit_err"] = c["err"]

    audit("apply", {"finding": req.finding_id, "file": req.file_path, "mode": req.mode})
    return result


@app.get("/api/git/diff")
def git_diff(file_path: str = ""):
    args = ["diff"]
    if file_path:
        args.extend(["--", file_path])
    res = run_git(args)
    return {"diff": res["out"], "ok": res["ok"]}


class RevertRequest(BaseModel):
    file_path: str


@app.post("/api/git/revert")
def git_revert(req: RevertRequest):
    target = (ROOT / req.file_path).resolve()
    try:
        target.relative_to(ROOT.resolve())
    except ValueError:
        raise HTTPException(400, "Path is outside project root.")

    res = run_git(["checkout", "--", req.file_path])
    audit("revert", {"file": req.file_path, "ok": res["ok"]})
    return {"reverted": res["ok"], "file": req.file_path, "err": res["err"]}


@app.get("/api/audit")
def get_audit_trail():
    if not AUDIT_PATH.exists():
        return {"entries": []}
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    entries = []
    for line in lines:
        if line.strip():
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
    return {"entries": entries[::-1]}  # latest first


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

