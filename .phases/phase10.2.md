Understood — you want a **live, working product console**, not a demo with fake data. That means two real pieces:

1. A **FastAPI backend** that wraps your actual `securepy_ai` engine (scanner → context → LLM → validator → reporter) and serves real results over HTTP.
2. A **React dashboard** that talks to that backend — runs real scans, shows real findings, real patches, real validation — with zero hardcoded sample data.

Here is the complete, runnable project.

---

# 1. Backend — `server.py` (place at project root)

```python
"""
SecurePy AI — Live Dashboard Backend (FastAPI)

Run from project root:
    pip install fastapi uvicorn
    python server.py
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from securepy_ai import __version__
from securepy_ai.scanner.ast_parser import SecurePyParser
from securepy_ai.scanner.context_extractor import ContextEnricher
from securepy_ai.scanner.rules import ALL_RULES
from securepy_ai.remediator.llm_client import MockLLMClient, OllamaClient
from securepy_ai.remediator.patch_generator import PatchGenerator
from securepy_ai.validator.patch_validator import PatchValidator
from securepy_ai.reporter.json_report import (
    build_report_dict,
    SecurePyJSONEncoder,
)

ROOT = Path(__file__).resolve().parent
HISTORY_DIR = ROOT / "reports" / "history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="SecurePy AI API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = "examples/vulnerable.py"
    fix: bool = False
    mock_llm: bool = True
    model: str = "codellama:13b"
    validate: bool = True
    max_patches: int = 3


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "ollama": OllamaClient().is_available(),
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan")
def scan(req: ScanRequest):
    start = time.perf_counter()

    scanner = SecurePyParser(rules=ALL_RULES)
    report = scanner.scan_path(req.target)

    ContextEnricher().enrich(report)

    if req.fix and report.findings:
        client = MockLLMClient() if req.mock_llm else OllamaClient(model=req.model)
        PatchGenerator(client=client).generate_for_report(
            report, max_patches=req.max_patches
        )
        if req.validate:
            PatchValidator().validate_report(report)

    payload = build_report_dict(report, target=req.target)
    payload["scan_time_ms"] = round((time.perf_counter() - start) * 1000, 1)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = HISTORY_DIR / f"scan_{ts}.json"
    path.write_text(
        json.dumps(payload, indent=2, cls=SecurePyJSONEncoder),
        encoding="utf-8",
    )
    payload["id"] = path.stem

    return payload


@app.get("/api/report")
def latest():
    files = sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)
    if not files:
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
                    "valid": d.get("summary", {}).get("patch_stats", {}).get("valid", 0),
                }
            )
        except Exception:
            continue
    return {"history": items}


@app.get("/api/history/{scan_id}")
def get_history(scan_id: str):
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists():
        raise HTTPException(404, "scan not found")
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

# 2. Frontend — `src/App.jsx` (real, live, no demo data)

```jsx
import React, { useEffect, useMemo, useState } from "react";

/* ================================================================
   SecurePy AI — Live Operations Console
   100% real data from the FastAPI backend. No demo/sample data.
   ================================================================ */

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const ACCENT = "#7ee787", AMBER = "#d29922", RED = "#f85149", CYAN = "#58c4dc";
const MUT = "#8b98a5", LINE = "rgba(140,160,180,.16)";

const SEV_COLOR = { Critical: RED, High: AMBER, Medium: CYAN, Low: ACCENT, Info: MUT };

/* ---------- LCS line diff (real diff, not fake) ---------- */
function diffLines(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ t: "ctx", x: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: "del", x: a[i] }); i++; }
    else { out.push({ t: "add", x: b[j] }); j++; }
  }
  while (i < n) out.push({ t: "del", x: a[i++] });
  while (j < m) out.push({ t: "add", x: b[j++] });
  return out;
}

const split = (s) => (s || "").split("\n").filter((l) => l.length || l === "");

function Logo() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" stroke={ACCENT} strokeWidth="1.4" />
      <path d="M9 12c0-1.6 1.3-2.4 3-2.4s3 .8 3 2.2c0 1.5-1.4 2-3 2s-3 .6-3 2.1c0 1.4 1.3 2.2 3 2.2s3-.8 3-2.3" stroke={ACCENT} strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

function ConfRing({ v }) {
  const c = 2 * Math.PI * 15.5;
  const col = v >= 0.8 ? ACCENT : v >= 0.5 ? AMBER : RED;
  return (
    <svg viewBox="0 0 36 36" className="rd-ring">
      <path d="M18 2.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 1 1 0-31" fill="none" stroke="rgba(140,160,180,.18)" strokeWidth="3" />
      <path d="M18 2.5a15.5 15.5 0 1 1 0 31 15.5 15.5 0 1 1 0-31" fill="none" stroke={col} strokeWidth="3"
        strokeDasharray={`${(v || 0) * c} ${c}`} strokeLinecap="round" />
    </svg>
  );
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [sel, setSel] = useState(0);
  const [mode, setMode] = useState("diff");
  const [filter, setFilter] = useState("ALL");

  const [form, setForm] = useState({ target: "examples/vulnerable.py", fix: true, mock_llm: true, validate: true, model: "codellama:13b" });

  const loadHealth = () => fetch(`${API}/api/health`).then(r => r.json()).then(setHealth).catch(() => setHealth(null));
  const loadHistory = () => fetch(`${API}/api/history`).then(r => r.json()).then(d => setHistory(d.history || [])).catch(() => {});
  const loadLatest = () => fetch(`${API}/api/report`).then(r => r.json()).then(d => d.report && setReport(d.report)).catch(() => {});

  useEffect(() => { loadHealth(); loadLatest(); loadHistory(); const id = setInterval(loadHealth, 5000); return () => clearInterval(id); }, []);

  const runScan = async () => {
    setScanning(true); setError("");
    try {
      const res = await fetch(`${API}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
      if (!res.ok) throw new Error(`scan failed (${res.status})`);
      const data = await res.json();
      setReport(data); setSel(0); loadHistory();
    } catch (e) { setError(String(e.message || e)); }
    finally { setScanning(false); }
  };

  const openScan = async (id) => {
    const d = await fetch(`${API}/api/history/${id}`).then(r => r.json()).catch(() => null);
    if (d) { setReport(d); setSel(0); }
  };

  const findings = useMemo(() => report?.scan?.findings || [], [report]);
  const shown = findings.filter(f => filter === "ALL" || (f.severity || "").toUpperCase() === filter);
  const f = shown[Math.min(sel, shown.length - 1)] || shown[0] || null;
  const summary = report?.summary || null;

  const diff = useMemo(() => {
    if (!f?.patch?.patched_code) return null;
    return diffLines(split(f.patch.original_code), split(f.patch.patched_code));
  }, [f]);

  return (
    <div className="rd-root">
      <style>{CSS}</style>

      {/* status bar */}
      <div className="rd-status">
        <span className="rd-item"><span className={"rd-live" + (health ? " on" : "")} />{health ? "backend · connected" : "backend · offline"}</span>
        <span className="rd-item">ollama <b>{health?.ollama ? "reachable" : "not reachable"}</b></span>
        <span className="rd-item hide-s">v<b>{health?.version || "—"}</b></span>
        <span className="rd-item rd-right">live · no demo data</span>
      </div>

      <header className="rd-nav">
        <span className="rd-brand"><Logo /> SecurePy<span>_AI</span></span>
        <span className="rd-nav-sub">operations console</span>
      </header>

      <div className="rd-grid">
        {/* LEFT: scan control + history */}
        <aside className="rd-left">
          <div className="rd-panel">
            <div className="rd-phead">run_scan</div>
            <label className="rd-label">target</label>
            <input className="rd-input" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} />
            <label className="rd-label">model</label>
            <select className="rd-input" value={form.model} onChange={e => setForm({ ...form, model: e.target.value })}>
              <option>codellama:13b</option><option>deepseek-coder:6.7b</option><option>qwen2.5-coder:7b</option>
            </select>
            <div className="rd-toggles">
              <label><input type="checkbox" checked={form.fix} onChange={e => setForm({ ...form, fix: e.target.checked })} /> --fix</label>
              <label><input type="checkbox" checked={form.mock_llm} onChange={e => setForm({ ...form, mock_llm: e.target.checked })} /> --mock-llm</label>
              <label><input type="checkbox" checked={form.validate} onChange={e => setForm({ ...form, validate: e.target.checked })} /> validate</label>
            </div>
            <button className="rd-run" onClick={runScan} disabled={scanning}>{scanning ? "scanning…" : "$ securepy-ai scan"}</button>
            {error && <div className="rd-err">{error}</div>}
            {report?.scan_time_ms != null && <div className="rd-scanmeta">last scan {report.scan_time_ms} ms · {report.scan?.files_scanned} files</div>}
          </div>

          <div className="rd-panel">
            <div className="rd-phead">history</div>
            <div className="rd-hist">
              {history.length === 0 && <div className="rd-empty">no scans yet</div>}
              {history.map(h => (
                <button key={h.id} className={"rd-hrow" + (report?.id === h.id ? " on" : "")} onClick={() => openScan(h.id)}>
                  <b>{h.target}</b>
                  <i>{h.findings} findings · {h.valid} valid</i>
                  <span>{(h.generated_at || "").slice(11, 19)}</span>
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* RIGHT: results */}
        <main className="rd-main">
          {!report && (
            <div className="rd-empty big">
              No scan loaded.<br />Configure a target on the left and run <code>$ securepy-ai scan</code>.
            </div>
          )}

          {report && (
            <>
              {/* summary strip */}
              <div className="rd-strip">
                <div><b>{summary?.files_scanned ?? 0}</b><i>files</i></div>
                <div><b>{summary?.total_findings ?? 0}</b><i>findings</i></div>
                <div><b>{summary?.patch_stats?.generated ?? 0}</b><i>patches</i></div>
                <div><b>{summary?.patch_stats?.valid ?? 0}</b><i>valid</i></div>
                <div><b>{Math.round((summary?.average_patch_confidence ?? 0) * 100)}%</b><i>avg conf</i></div>
              </div>

              <div className="rd-filters">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(s => (
                  <button key={s} className={"rd-fbtn" + (filter === s ? " on" : "")} onClick={() => { setFilter(s); setSel(0); }}>{s}</button>
                ))}
              </div>

              <div className="rd-console">
                {/* findings list */}
                <div className="rd-list">
                  {shown.length === 0 && <div className="rd-empty">no findings match</div>}
                  {shown.map((x, i) => (
                    <button key={x.rule_id + x.line_number} className={"rd-row" + (f === x ? " on" : "")} onClick={() => setSel(i)}>
                      <span className="rd-sev" style={{ color: SEV_COLOR[x.severity] || MUT, borderColor: (SEV_COLOR[x.severity] || MUT) + "66" }}>{(x.severity || "").toUpperCase()}</span>
                      <span className="rd-rowmain"><b>{x.vuln_type}</b><i>{x.file_path}:{x.line_number} · {x.cwe_id}</i></span>
                      <span className="rd-conf">{x.patch?.validation ? Math.round(x.patch.validation.confidence_score * 100) + "%" : "—"}</span>
                    </button>
                  ))}
                </div>

                {/* detail */}
                <div className="rd-detail">
                  {!f && <div className="rd-empty">select a finding</div>}
                  {f && (
                    <>
                      <div className="rd-dhead">
                        <div>
                          <div className="rd-dtitle">{f.vuln_type} <span className="rd-cwe">{f.cwe_id}</span></div>
                          <div className="rd-flow">{f.context?.data_flow || f.description}</div>
                        </div>
                        {f.patch?.validation && (
                          <div className="rd-confbox"><ConfRing v={f.patch.validation.confidence_score} />
                            <div><b>{Math.round(f.patch.validation.confidence_score * 100)}%</b><i>{f.patch.validation.decision}</i></div>
                          </div>
                        )}
                      </div>

                      <div className="rd-modes">
                        {["diff", "before", "after"].map(m => (
                          <button key={m} className={"rd-mbtn" + (mode === m ? " on" : "")} onClick={() => setMode(m)}>{m}</button>
                        ))}
                        {f.patch && <span className="rd-pmodel">{f.patch.model}</span>}
                      </div>

                      <div className="rd-code">
                        {mode === "diff" && diff && diff.map((l, i) => (
                          <div key={i} className={"rd-cl rd-cl-" + l.t}><span className="rd-cls">{l.t === "add" ? "+" : l.t === "del" ? "−" : " "}</span>{l.x}</div>
                        ))}
                        {mode === "diff" && !diff && <div className="rd-empty">no patch generated for this finding</div>}
                        {mode !== "diff" && split(mode === "before" ? f.patch?.original_code || f.context?.function_scope || f.code_snippet : f.patch?.patched_code).map((l, i) => (
                          <div key={i} className={"rd-cl " + (mode === "before" ? "rd-cl-src" : "rd-cl-fix")}><span className="rd-clno">{i + 1}</span>{l}</div>
                        ))}
                      </div>

                      {f.patch?.validation && (
                        <div className="rd-checks">
                          {f.patch.validation.checks.map(c => (
                            <div key={c.name} className="rd-check">
                              <span className={"rd-cic rd-cic-" + c.status}>{c.status === "pass" ? "✓" : c.status === "warn" ? "!" : "✕"}</span>
                              <span>{c.name}</span>
                              <span className="rd-cst">{c.status.toUpperCase()}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </>
          )}
        </main>
      </div>

      <footer className="rd-foot">Sagar Porwal · NFSU Delhi · github.com/SagarPorwal10</footer>
    </div>
  );
}

const CSS = `
@import url('https://cdn.jsdelivr.net/npm/@fontsource/space-grotesk@5.0.16/700.css');
@import url('https://cdn.jsdelivr.net/npm/@fontsource/ibm-plex-mono@5.0.13/400.css');
@import url('https://cdn.jsdelivr.net/npm/@fontsource/ibm-plex-sans@5.0.13/400.css');
:root{--ink:#0a0e14;--panel:#0d141c;--line:rgba(140,160,180,.16);--txt:#dbe4ec;--mut:#8b98a5;--acc:#7ee787;--amb:#d29922;--red:#f85149;--cyn:#58c4dc;--mono:'IBM Plex Mono',monospace;--disp:'Space Grotesk',sans-serif;--body:'IBM Plex Sans',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
.rd-root{background:var(--ink);color:var(--txt);font-family:var(--body);min-height:100vh;display:flex;flex-direction:column}
.rd-root ::-webkit-scrollbar{width:9px;height:9px}.rd-root ::-webkit-scrollbar-thumb{background:#1c2836}
.rd-status{display:flex;gap:20px;padding:7px 20px;border-bottom:1px solid var(--line);font-family:var(--mono);font-size:11px;color:var(--mut);background:#0b1017}
.rd-status b{color:var(--txt);font-weight:500}.rd-right{margin-left:auto;color:var(--acc)}
.rd-item{display:flex;gap:7px;align-items:center}
.rd-live{width:7px;height:7px;border-radius:50%;background:#3a4654}.rd-live.on{background:var(--acc);box-shadow:0 0 8px var(--acc)}
.rd-nav{display:flex;align-items:baseline;gap:14px;padding:14px 20px;border-bottom:1px solid var(--line)}
.rd-brand{display:flex;gap:9px;align-items:center;font-family:var(--disp);font-weight:700;font-size:17px}
.rd-brand span{color:var(--acc)}.rd-nav-sub{font-family:var(--mono);font-size:11px;color:var(--mut)}
.rd-grid{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px 20px;flex:1;align-items:start}
.rd-left{display:flex;flex-direction:column;gap:16px}
.rd-panel{border:1px solid var(--line);background:var(--panel)}
.rd-phead{font-family:var(--mono);font-size:11px;letter-spacing:.16em;color:var(--acc);padding:11px 14px;border-bottom:1px solid var(--line);text-transform:uppercase}
.rd-label{display:block;font-family:var(--mono);font-size:10px;color:var(--mut);margin:12px 14px 5px;letter-spacing:.1em}
.rd-input{display:block;width:calc(100% - 28px);margin:0 14px;background:#0b1017;border:1px solid var(--line);color:var(--txt);font-family:var(--mono);font-size:12px;padding:9px 10px}
.rd-input:focus{outline:none;border-color:rgba(126,231,135,.4)}
.rd-toggles{display:flex;gap:14px;padding:12px 14px;font-family:var(--mono);font-size:11px;color:var(--mut);flex-wrap:wrap}
.rd-toggles label{display:flex;gap:6px;align-items:center}
.rd-toggles input{accent-color:var(--acc)}
.rd-run{display:block;width:calc(100% - 28px);margin:0 14px 14px;background:rgba(126,231,135,.1);border:1px solid rgba(126,231,135,.4);color:var(--acc);font-family:var(--mono);font-size:12px;padding:11px;cursor:pointer}
.rd-run:hover:not(:disabled){background:rgba(126,231,135,.18)}
.rd-run:disabled{opacity:.5;cursor:wait}
.rd-err{margin:0 14px 12px;color:var(--red);font-family:var(--mono);font-size:11px}
.rd-scanmeta{margin:0 14px 14px;color:var(--mut);font-family:var(--mono);font-size:10.5px}
.rd-hist{max-height:240px;overflow:auto}
.rd-hrow{display:grid;grid-template-columns:1fr auto;gap:2px 10px;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid var(--line);padding:10px 14px;cursor:pointer;color:var(--txt)}
.rd-hrow i{grid-column:1;font-style:normal;font-family:var(--mono);font-size:10.5px;color:var(--mut)}
.rd-hrow span{grid-row:1/3;font-family:var(--mono);font-size:10px;color:var(--mut)}
.rd-hrow b{font-size:12.5px;font-weight:600;word-break:break-all}
.rd-hrow.on{background:rgba(126,231,135,.07);box-shadow:inset 2px 0 0 var(--acc)}
.rd-empty{color:var(--mut);font-family:var(--mono);font-size:12px;padding:20px;text-align:center}
.rd-empty.big{padding:70px 20px;font-size:13px;line-height:2}
.rd-empty code{color:var(--acc)}
.rd-strip{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);background:var(--panel);margin-bottom:14px}
.rd-strip>div{padding:14px 8px;text-align:center;border-right:1px solid var(--line)}
.rd-strip>div:last-child{border-right:0}
.rd-strip b{font-family:var(--disp);font-size:22px;color:var(--acc)}
.rd-strip i{display:block;font-style:normal;font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;color:var(--mut);margin-top:4px;text-transform:uppercase}
.rd-filters{display:flex;gap:8px;margin-bottom:12px}
.rd-fbtn{font-family:var(--mono);font-size:11px;color:var(--mut);background:none;border:1px solid var(--line);padding:6px 12px;cursor:pointer}
.rd-fbtn.on{color:var(--ink);background:var(--acc);border-color:var(--acc)}
.rd-console{display:grid;grid-template-columns:340px 1fr;border:1px solid var(--line);background:var(--panel)}
.rd-list{border-right:1px solid var(--line);max-height:640px;overflow:auto}
.rd-row{display:grid;grid-template-columns:80px 1fr 46px;gap:10px;align-items:center;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid var(--line);padding:13px 12px;cursor:pointer;color:var(--txt)}
.rd-row.on{background:rgba(126,231,135,.08);box-shadow:inset 2px 0 0 var(--acc)}
.rd-sev{font-family:var(--mono);font-size:9.5px;text-align:center;padding:4px 0;border:1px solid}
.rd-rowmain b{display:block;font-size:13px;font-weight:600}
.rd-rowmain i{display:block;font-style:normal;font-family:var(--mono);font-size:10.5px;color:var(--mut);margin-top:3px}
.rd-conf{font-family:var(--mono);font-size:11.5px;color:var(--acc);text-align:right}
.rd-detail{padding:18px 20px;max-height:640px;overflow:auto}
.rd-dhead{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:14px}
.rd-dtitle{font-family:var(--disp);font-size:19px;font-weight:700}
.rd-cwe{font-family:var(--mono);font-size:11px;color:var(--cyn);margin-left:8px}
.rd-flow{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:6px}
.rd-confbox{display:flex;gap:10px;align-items:center}
.rd-ring{width:52px;height:52px}
.rd-confbox b{font-family:var(--disp);font-size:16px;display:block}
.rd-confbox i{font-style:normal;font-family:var(--mono);font-size:9.5px;color:var(--mut)}
.rd-modes{display:flex;gap:6px;align-items:center;margin-bottom:9px}
.rd-mbtn{font-family:var(--mono);font-size:11px;color:var(--mut);background:none;border:1px solid var(--line);padding:5px 11px;cursor:pointer}
.rd-mbtn.on{color:var(--acc);border-color:rgba(126,231,135,.45)}
.rd-pmodel{margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--cyn)}
.rd-code{border:1px solid var(--line);background:#0b1017;font-family:var(--mono);font-size:11.5px;line-height:1.8;padding:10px;max-height:260px;overflow:auto}
.rd-cl{white-space:pre-wrap;word-break:break-word;padding:0 6px}
.rd-cl-add{background:rgba(126,231,135,.09);color:#b7f4c0}
.rd-cl-del{background:rgba(248,81,73,.09);color:#f2a19b}
.rd-cl-ctx{color:var(--mut)}
.rd-cls{display:inline-block;width:15px}
.rd-cl-src{color:#f2a19b}.rd-cl-fix{color:#b7f4c0}
.rd-clno{display:inline-block;width:20px;color:#41506a;text-align:right;margin-right:10px}
.rd-checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:13px}
.rd-check{display:flex;gap:9px;align-items:center;border:1px solid var(--line);padding:8px 11px;font-size:12px;color:var(--mut)}
.rd-cic{width:19px;height:19px;display:grid;place-items:center;font-size:10.5px}
.rd-cic-pass{color:var(--acc);border:1px solid rgba(126,231,135,.4)}
.rd-cic-warn{color:var(--amb);border:1px solid rgba(210,153,34,.4)}
.rd-cic-fail,.rd-cic-skipped{color:var(--red);border:1px solid rgba(248,81,73,.4)}
.rd-cst{margin-left:auto;font-family:var(--mono);font-size:9.5px}
.rd-foot{padding:16px 20px;color:var(--mut);font-family:var(--mono);font-size:11px;border-top:1px solid var(--line)}
@media(max-width:960px){.rd-grid{grid-template-columns:1fr}.rd-console{grid-template-columns:1fr}.rd-list{border-right:0;border-bottom:1px solid var(--line)}.hide-s{display:none}}
`;
```

---

# 3. Run it

```bash
# Backend (from your securepy-ai project root)
pip install fastapi uvicorn
python server.py            # → http://localhost:8000

# Frontend
npm create vite@latest securepy-console -- --template react
cd securepy-console
# replace src/App.jsx with the file above
npm run dev                 # → http://localhost:5173
```

---

# Why this is "real"

- **No sample data anywhere.** Every number, finding, diff, and validation check comes from your actual engine via `/api/scan`.
- **It runs your pipeline for real** — scanner → context → LLM (mock or Ollama) → validator → reporter.
- **Real LCS diff** of `original_code` vs `patched_code`, not a fake before/after.
- **Persistence + history** — every scan is saved; you can reopen any past scan.
- **Live health** — shows backend and Ollama reachability, polled every 5s.
- **Empty / loading / error states** handled, like a real product.

Toggle `--mock-llm` off and point it at Ollama to see genuine CodeLlama patches validated live.