import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";

/* ================================================================
   SecurePy AI — Live Operations Console & Security Workbench
   Unified Phase 10.2 Implementation
   ================================================================ */

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const ACCENT = "#7ee787";
const AMBER  = "#d29922";
const RED    = "#f85149";
const CYAN   = "#58c4dc";
const INK    = "#0a0e14";
const LINE   = "rgba(140,160,180,0.16)";
const MUT    = "#8b98a5";
const TXT    = "#dbe4ec";

const MONO = "'IBM Plex Mono', ui-monospace, monospace";
const DISP = "'Space Grotesk', sans-serif";
const BODY = "'IBM Plex Sans', system-ui, sans-serif";

const SEV_COLOR = { Critical: RED, High: AMBER, Medium: CYAN, Low: ACCENT, Info: MUT };

/* ---------- Real LCS line diff generator ---------- */
function diffLines(a, b) {
  const n = a.length, m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
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

/* ---- Static Pipeline & Roadmap Data ---- */
const TICKER = [
  "CWE-89 · SQL INJECTION", "CWE-78 · COMMAND INJECTION", "CWE-798 · HARDCODED CREDENTIALS",
  "CWE-502 · INSECURE DESERIALIZATION", "CWE-95 · EVAL / EXEC", "CWE-79 · CROSS-SITE SCRIPTING",
  "CWE-22 · PATH TRAVERSAL", "CWE-306 · MISSING AUTHENTICATION",
];

const PIPELINE = [
  { n: "01", t: "Ingest",   d: "Collect Python sources from repo / PR; filter venv, cache, fixtures.", tech: "git · pathlib" },
  { n: "02", t: "AST Scan", d: "Parse to Abstract Syntax Trees; recursive traversal of calls, assigns, imports.", tech: "python ast" },
  { n: "03", t: "Rules",    d: "CWE-mapped detection: SQLi, cmd-inj, secrets, deserialization, eval/exec.", tech: "5 rule engines" },
  { n: "04", t: "Context",  d: "Function scope, data-flow, sink/source, imports → VulnerabilityContext.", tech: "taint heuristics" },
  { n: "05", t: "Prompt",   d: "CWE-specific templates + secure-coding constraints + output rules.", tech: "prompt builder" },
  { n: "06", t: "LLM",      d: "Local CodeLlama / DeepSeek via Ollama. Code never leaves the host.", tech: "ollama · codellama:13b" },
  { n: "07", t: "Validate", d: "Syntax · AST-logic · re-scan · new-vuln · tests. A security oracle, not just tests.", tech: "patch validator" },
  { n: "08", t: "Route",    d: "Confidence ≥0.80 auto · 0.50 review · else reject. CI exit codes 0/1/2.", tech: "policy engine" },
];

const ROADMAP = [
  { range: "01–08", name: "Core engine",       status: "done",    items: ["AST scanner","5 CWE rules","Context extraction","Local LLM","Prompt builder","Patch validator","Reports","CI policies"] },
  { range: "09",    name: "CI/CD integration", status: "done",    items: ["GitHub Action","PR comments","SARIF upload","Baseline + diff-only"] },
  { range: "10–12", name: "Evidence & Dashboard", status: "current", items: ["Live Dashboard","FastAPI Engine Backend","SecurePy-VulnBench","Thesis + paper"] },
  { range: "13–16", name: "Product depth",     status: "future",  items: ["Test generation","Deep taint","Patch explanations","Repo memory / RAG"] },
  { range: "17–20", name: "Intelligence",      status: "future",  items: ["Exploit verification","Repair agent","SCA / IaC / secrets","Risk + compliance"] },
  { range: "21–24", name: "Autonomous",        status: "future",  items: ["IDE plugins","Multi-language","Enterprise","Self-healing SDLC"] },
];

/* ---- fallback initial demo findings ---- */
const DEMO_FINDINGS = [
  {
    id: "SP-001", sev: "CRITICAL", cwe: "CWE-89", title: "SQL Injection", file: "examples/vulnerable.py", line: 16,
    conf: 0.93, status: "VALIDATED", rule: "SEC102",
    flow: "user_id → f-string query → cursor.execute()",
    before: ["def get_user(user_id):", "    # SEC102: SQL injection using f-string", "    query = f\"SELECT * FROM users WHERE id = {user_id}\"", "    return query"],
    after:  ["def get_user(user_id):", "    # fix: parameterized query (CWE-89)", "    query = \"SELECT * FROM users WHERE id = ?\"", "    return query, (user_id,)"],
    diff: [
      { t: "ctx", x: "def get_user(user_id):" },
      { t: "del", x: "    query = f\"SELECT * FROM users WHERE id = {user_id}\"" },
      { t: "add", x: "    # fix: parameterized query (CWE-89)" },
      { t: "add", x: "    query = \"SELECT * FROM users WHERE id = ?\"" },
      { t: "add", x: "    return query, (user_id,)" },
      { t: "del", x: "    return query" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","pass"],["Vulnerability re-scan","pass"],["No new vulnerabilities","pass"],["Routing decision","pass"]],
  },
  {
    id: "SP-002", sev: "HIGH", cwe: "CWE-798", title: "Hardcoded Secret", file: "examples/vulnerable.py", line: 8,
    conf: 0.86, status: "VALIDATED", rule: "SEC101",
    flow: "literal string → api_key variable",
    before: ["api_key = \"AKIA923848239482394\""],
    after:  ["import os", "# fix: secret from environment (CWE-798)", "api_key = os.environ.get(\"API_KEY\")"],
    diff: [
      { t: "del", x: "api_key = \"AKIA923848239482394\"" },
      { t: "add", x: "import os" },
      { t: "add", x: "api_key = os.environ.get(\"API_KEY\")" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","pass"],["Vulnerability re-scan","pass"],["No new vulnerabilities","pass"],["Routing decision","pass"]],
  },
];

/* ---- Terminal Lines ---- */
const TERM_LINES = [
  ["$", "securepy-ai scan examples/vulnerable.py --fix --model codellama:13b"],
  ["·", "ingest    target path analyzed"],
  ["·", "ast       parsing syntax trees & AST traversal …"],
  ["!", "SEC101  CWE-798  examples/vulnerable.py:7   HIGH"],
  ["!", "SEC101  CWE-798  examples/vulnerable.py:8   HIGH"],
  ["!", "SEC102  CWE-89   examples/vulnerable.py:16  CRITICAL"],
  ["!", "SEC103  CWE-78   examples/vulnerable.py:28  HIGH"],
  ["!", "SEC104  CWE-502  examples/vulnerable.py:38  HIGH"],
  ["·", "context   function scope + data-flow extracted"],
  ["·", "llm       generating candidate patches (local, offline) …"],
  ["✓", "SP-001  patch valid   conf 1.00  → AUTO APPLY"],
  ["✓", "SP-002  patch valid   conf 1.00  → AUTO APPLY"],
  ["~", "SP-003  patch review  conf 0.85  → REVIEW"],
  ["·", "report    json + html + sarif generated in reports/"],
  ["$", "scan finished — all findings loaded into console"],
];

/* ---- hooks ---- */
function usePRM() {
  const [prm, setPrm] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setPrm(mq.matches);
    const fn = (e) => setPrm(e.matches);
    mq.addEventListener?.("change", fn);
    return () => mq.removeEventListener?.("change", fn);
  }, []);
  return prm;
}

/* scramble-decode text */
function Scramble({ text, className, delay = 0 }) {
  const prm = usePRM();
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const [out, setOut] = useState(prm ? text : "");
  useEffect(() => {
    if (prm) { setOut(text); return; }
    if (!inView) return;
    const chars = "█▓▒░<>/\\|=+*#01";
    let frame = 0; let raf;
    const total = 26;
    const tick = () => {
      frame++;
      const prog = Math.max(0, frame - delay / 16) / total;
      const reveal = Math.floor(prog * text.length);
      let s = "";
      for (let i = 0; i < text.length; i++) {
        if (i < reveal) s += text[i];
        else if (text[i] === " ") s += " ";
        else s += chars[Math.floor(Math.random() * chars.length)];
      }
      setOut(s);
      if (reveal < text.length) raf = requestAnimationFrame(tick);
      else setOut(text);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, text, prm, delay]);
  return <span ref={ref} className={className} aria-label={text}>{out || "\u00A0"}</span>;
}

/* count-up */
function CountUp({ to, suffix = "", decimals = 0 }) {
  const prm = usePRM();
  const ref = useRef(null);
  const inView = useInView(ref, { once: true });
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!inView) return;
    if (prm) { setV(to); return; }
    const t0 = performance.now(); const dur = 1200;
    let raf;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      setV(to * e);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, to, prm]);
  return <span ref={ref}>{v.toFixed(decimals)}{suffix}</span>;
}

/* streaming terminal */
function Terminal({ onTriggerScan, scanning }) {
  const prm = usePRM();
  const [count, setCount] = useState(prm ? TERM_LINES.length : 0);
  const [run, setRun] = useState(0);
  useEffect(() => {
    if (prm) { setCount(TERM_LINES.length); return; }
    setCount(0);
    let i = 0;
    const id = setInterval(() => {
      i++;
      setCount(i);
      if (i >= TERM_LINES.length) clearInterval(id);
    }, 240);
    return () => clearInterval(id);
  }, [run, prm]);
  const done = count >= TERM_LINES.length;
  return (
    <div className="sy-term">
      <div className="sy-term-bar">
        <span className="sy-dot" style={{ background: RED }} />
        <span className="sy-dot" style={{ background: AMBER }} />
        <span className="sy-dot" style={{ background: ACCENT }} />
        <span className="sy-term-title">sagar@nfsu — securepy-ai live engine — 80×24</span>
        <button className="sy-term-rerun" onClick={() => setRun((r) => r + 1)}>↻ replay</button>
      </div>
      <div className="sy-term-body">
        {TERM_LINES.slice(0, count).map((l, i) => (
          <div key={i} className="sy-tl">
            <span className={"sy-tg sy-tg-" + (l[0] === "!" ? "warn" : l[0] === "✓" ? "ok" : l[0] === "✕" ? "bad" : l[0] === "~" ? "rev" : "dim")}>{l[0]}</span>
            <span className={l[0] === "$" ? "sy-cmd" : ""}>{l[1]}</span>
          </div>
        ))}
        {!done && <span className="sy-caret">▊</span>}
        {done && <div className="sy-tl"><span className="sy-tg sy-tg-dim">$</span><span className="sy-caret">▊</span></div>}
      </div>
    </div>
  );
}

/* logo mark */
function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" stroke={ACCENT} strokeWidth="1.4" />
      <path d="M9 12c0-1.6 1.3-2.4 3-2.4s3 .8 3 2.2c0 1.5-1.4 2-3 2s-3 .6-3 2.1c0 1.4 1.3 2.2 3 2.2s3-.8 3-2.3" stroke={ACCENT} strokeWidth="1.3" strokeLinecap="round" />
      <path d="M10 7.6h4" stroke={ACCENT} strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  );
}

/* line-mask reveal */
function MaskLine({ children, i = 0 }) {
  const prm = usePRM();
  return (
    <span className="sy-mask">
      <motion.span className="sy-mask-in"
        initial={prm ? { y: 0 } : { y: "110%" }}
        whileInView={prm ? {} : { y: 0 }}
        viewport={{ once: true, margin: "-60px" }}
        transition={{ duration: 0.7, delay: i * 0.12, ease: [0.22, 1, 0.36, 1] }}>
        {children}
      </motion.span>
    </span>
  );
}

function SectionHead({ index, label, title }) {
  return (
    <div className="sy-shead">
      <div className="sy-shead-top">
        <span className="sy-idx">{index}</span>
        <span className="sy-slabel"><Scramble text={label} /></span>
        <span className="sy-rule" />
      </div>
      <h2 className="sy-h2">{title}</h2>
    </div>
  );
}

/* Mapper function for Backend ScanReport payload */
function mapReportToFindings(reportData) {
  if (!reportData || !reportData.scan || !reportData.scan.findings) return null;
  return reportData.scan.findings.map((f, i) => {
    const patch = f.patch;
    const val = patch?.validation;
    const conf = val?.confidence_score ? (val.confidence_score > 1 ? val.confidence_score / 100 : val.confidence_score) : (patch?.success ? 0.85 : 0);
    const status = !patch ? "NO PATCH" : (val?.passed ? (conf >= 0.8 ? "VALIDATED" : "REVIEW") : "REJECTED");

    const beforeLines = split(
      patch?.original_code || f.context?.function_scope || f.context?.surrounding_lines || f.code_snippet
    );

    const afterLines = patch?.patched_code
      ? split(patch.patched_code)
      : ["# No patch generated for this finding (enable --fix)"];

    const diff = (patch?.original_code && patch?.patched_code)
      ? diffLines(split(patch.original_code), split(patch.patched_code))
      : (patch?.patched_code
          ? [{ t: "del", x: f.code_snippet || "Vulnerable code" }, ...split(patch.patched_code).map(x => ({ t: "add", x }))]
          : [{ t: "del", x: f.code_snippet || "Vulnerable expression" }]);

    const checks = val ? [
      ["Syntax validation", val.syntax_valid ? "pass" : "fail"],
      ["AST logic preservation", val.logic_preserved ? "pass" : "fail"],
      ["Vulnerability re-scan", val.vuln_fixed ? "pass" : "fail"],
      ["No new vulnerabilities", val.no_new_vulns ? "pass" : "fail"],
      ["Routing decision", val.passed ? "pass" : "warn"]
    ] : [
      ["Syntax validation", "warn"],
      ["AST logic preservation", "warn"],
      ["Vulnerability re-scan", "warn"],
      ["No new vulnerabilities", "warn"],
      ["Routing decision", "fail"]
    ];

    return {
      id: `SP-${String(i + 1).padStart(3, "0")}`,
      sev: (f.severity || "INFO").toUpperCase(),
      cwe: f.cwe_id || "CWE",
      title: f.vuln_type || "Security Flaw",
      file: f.file_path || "file.py",
      line: f.line_number || 1,
      conf: conf,
      status: status,
      rule: f.rule_id || "SEC000",
      flow: f.context?.data_flow || f.description || "Source to sink taint flow",
      before: beforeLines,
      after: afterLines,
      diff: diff,
      checks: checks,
      patchModel: patch?.model || "mock-llm",
      decisionText: val?.decision || status,
      rawFinding: f,
    };
  });
}

/* ================================================================
   Main Application Component
   ================================================================ */
export default function App() {
  const prm = usePRM();
  const [step, setStep] = useState(0);
  const [sel, setSel] = useState(0);
  const [mode, setMode] = useState("diff");
  const [filter, setFilter] = useState("ALL");

  // Backend / Live Data States
  const [health, setHealth] = useState(null);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [git, setGit] = useState(null);
  const [auditEntries, setAuditEntries] = useState([]);
  const [activeDiffText, setActiveDiffText] = useState("");
  const [activeDiffFile, setActiveDiffFile] = useState("");
  const [scanning, setScanning] = useState(false);
  const [applying, setApplying] = useState(false);
  const [reverting, setReverting] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const fileInputRef = useRef(null);

  // Scan Form Configuration
  const [form, setForm] = useState({
    target: "examples/vulnerable.py",
    fix: true,
    mock_llm: true,
    model: "codellama:13b",
    validate: true,
    max_patches: 10
  });

  // Polling backend health, history, git status & audit trail
  const loadHealth = () => fetch(`${API}/api/health`).then(r => r.json()).then(setHealth).catch(() => setHealth(null));
  const loadHistory = () => fetch(`${API}/api/history`).then(r => r.json()).then(d => setHistory(d.history || [])).catch(() => {});
  const loadGit = () => fetch(`${API}/api/git/status`).then(r => r.json()).then(setGit).catch(() => {});
  const loadAudit = () => fetch(`${API}/api/audit`).then(r => r.json()).then(d => setAuditEntries(d.entries || [])).catch(() => {});

  /* ---- fetch scannable .py files from project root ---- */
  const [pyFiles, setPyFiles] = useState([]);
  const loadPyFiles = () => fetch(`${API}/api/files`).then(r => r.json()).then(d => setPyFiles(d.files || [])).catch(() => {});

  const loadGitDiff = async (filePath = "") => {
    try {
      const res = await fetch(`${API}/api/git/diff${filePath ? `?file_path=${encodeURIComponent(filePath)}` : ""}`);
      const data = await res.json();
      setActiveDiffText(data.diff || "(No uncommitted diffs)");
      setActiveDiffFile(filePath || "working tree");
    } catch (e) {
      console.error(e);
    }
  };

  const revertFile = async (filePath) => {
    if (!confirm(`Are you sure you want to revert modifications to '${filePath}'?`)) return;
    setReverting(true);
    try {
      const res = await fetch(`${API}/api/git/revert`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: filePath })
      });
      const data = await res.json();
      if (data.reverted) {
        setNotice(`✅ Reverted ${filePath} to pristine git HEAD.`);
        loadGit();
        loadAudit();
        setActiveDiffText("");
        setActiveDiffFile("");
      } else {
        setError(`Failed to revert: ${data.err}`);
      }
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setReverting(false);
    }
  };

  const loadLatest = () => {
    fetch(`${API}/api/report`)
      .then(r => r.json())
      .then(d => {
        if (d.report) {
          setReport(d.report);
        } else {
          // Fallback to static public file if backend is fresh
          fetch("/reports/securepy-ai-report.json")
            .then(res => res.json())
            .then(staticData => setReport(staticData))
            .catch(() => {});
        }
      })
      .catch(() => {
        // Fallback to static public file
        fetch("/reports/securepy-ai-report.json")
          .then(res => res.json())
          .then(staticData => setReport(staticData))
          .catch(() => {});
      });
  };

  useEffect(() => {
    loadHealth();
    loadLatest();
    loadHistory();
    loadGit();
    loadAudit();
    loadPyFiles();
    const intervalId = setInterval(() => {
      loadHealth();
      loadGit();
      loadAudit();
    }, 5000);
    return () => clearInterval(intervalId);
  }, []);

  // Trigger Real Scan
  const runScan = async () => {
    setScanning(true);
    setError("");
    setNotice("");
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form)
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Scan failed (${res.status}): ${errText}`);
      }
      const data = await res.json();
      setReport(data);
      setSel(0);
      loadHistory();
      loadGit();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setScanning(false);
    }
  };

  // Phase 10.3: Apply Patch Locally (NEVER pushes)
  const applyPatch = async (applyMode) => {
    if (!f) return;
    const originalCode = f.rawFinding?.patch?.original_code || f.before.join("\n");
    const patchedCode = f.rawFinding?.patch?.patched_code || f.after.join("\n");
    if (!patchedCode || patchedCode.startsWith("# No patch")) {
      setError("No generated patch available for this finding.");
      return;
    }

    setApplying(true);
    setNotice("");
    setError("");
    try {
      const res = await fetch(`${API}/api/apply`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_path: f.file,
          original_code: originalCode,
          patched_code: patchedCode,
          finding_id: `${f.rule}:${f.file}:${f.line}`,
          mode: applyMode,
          branch: "securepy/fixes",
          message: `fix(security): ${f.cwe} ${f.title} in ${f.file}:${f.line} [SecurePy AI · local only]`
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Patch application failed");
      }

      const data = await res.json();
      if (applyMode === "patch" && data.patch_text) {
        const blob = new Blob([data.patch_text], { type: "text/x-diff" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `${f.rule}_L${f.line}.patch`;
        a.click();
        URL.revokeObjectURL(a.href);
        setNotice(`.patch file downloaded — apply with: git apply ${f.rule}_L${f.line}.patch`);
      } else if (applyMode === "commit") {
        setNotice(`✅ Committed locally on branch 'securepy/fixes' — NEVER pushed to remote. Click Re-scan to verify the fix is clean.`);
      } else {
        setNotice(`✅ Applied to working tree (${f.file}) — review with 'git diff'. Backup saved in reports/backups/. Click Re-scan to verify.`);
      }
      loadGit();
      loadAudit();
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setApplying(false);
    }
  };

  // Open Historical Scan
  const openScan = async (scanId) => {
    try {
      const d = await fetch(`${API}/api/history/${scanId}`).then(r => r.json());
      if (d) {
        setReport(d);
        setSel(0);
      }
    } catch (e) {
      console.error(e);
    }
  };


  // Handle Manual File Upload
  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result);
        setReport(data);
        setSel(0);
      } catch (err) {
        alert("Invalid SecurePy AI JSON report file.");
      }
    };
    reader.readAsText(file);
  };

  // Derive findings list
  const activeFindings = useMemo(() => {
    const mapped = mapReportToFindings(report);
    return mapped && mapped.length > 0 ? mapped : DEMO_FINDINGS;
  }, [report]);

  const shown = activeFindings.filter((x) => filter === "ALL" || x.sev === filter);
  const safeSel = Math.min(sel, shown.length - 1);
  const f = shown[safeSel] || shown[0] || activeFindings[0];

  const summary = report?.summary || null;
  const stats = {
    files: summary?.files_scanned ?? 1,
    findings: summary?.total_findings ?? activeFindings.length,
    patches: summary?.patch_stats?.generated ?? (report ? 0 : 4),
    validated: summary?.patch_stats?.auto_apply ?? (report ? 0 : 2),
    topConf: activeFindings.length > 0 ? Math.round(Math.max(...activeFindings.map(x => x.conf)) * 100) : 0
  };

  /* ---- severity breakdown for bar chart ---- */
  const sevCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    activeFindings.forEach(f => {
      const k = f.sev.charAt(0) + f.sev.slice(1).toLowerCase();
      if (k in counts) counts[k]++;
    });
    return counts;
  }, [activeFindings]);
  const sevMax = Math.max(1, ...Object.values(sevCounts));

  return (
    <div className="sy-root">
      <style>{CSS}</style>

      {/* ── Status Bar ── */}
      <div className="sy-status" role="status" aria-label="System status">
        <span className="sy-status-item">
          <span className={"sy-live " + (health ? "on" : "off")} aria-hidden="true" />
          {health ? "FastAPI backend · connected" : "backend · offline (using cached data)"}
        </span>
        <span className="sy-status-item">
          ollama <b>{health?.ollama ? "reachable" : "offline (mock active)"}</b>
        </span>
        <span className="sy-status-item">
          ⎇ <b>{git?.branch || "main"}</b>{git?.dirty ? " · dirty" : " · clean"}
        </span>
        <span className="sy-status-item hide-s">target <b>{report?.target || form.target}</b></span>
        <span className="sy-status-item hide-s">build <b>v{health?.version || "1.0.0"}</b></span>
        <span className="sy-status-item sy-right">local execution · 100% privacy</span>
      </div>

      {/* ── Navigation ── */}
      <header className="sy-nav">
        <a className="sy-brand" href="#top" aria-label="SecurePy AI home">
          <Logo />
          <span className="sy-word">SecurePy<span className="sy-word-ai">_AI</span></span>
        </a>
        <nav className="sy-links" aria-label="Page sections">
          <a href="#control">run_scan</a>
          <a href="#pipeline">pipeline</a>
          <a href="#console">workbench</a>
          <a href="#research">research</a>
          <a href="#roadmap">roadmap</a>
        </nav>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <input
            type="file"
            ref={fileInputRef}
            style={{ display: "none" }}
            accept=".json"
            onChange={handleFileUpload}
          />
          <button
            className="sy-fbtn"
            style={{ padding: "6px 12px", fontSize: "11px" }}
            onClick={() => fileInputRef.current?.click()}
            title="Upload any securepy-ai-report.json"
          >
            Upload JSON
          </button>
          <a className="sy-cta" href="#control" aria-label="Jump to scan console">
            $ securepy-ai scan
          </a>
        </div>
      </header>

      {/* ── Hero Section with Terminal & Live Stats ── */}
      <section className="sy-open" id="top" aria-label="Hero">
        <div className="sy-open-left">
          <div className="sy-kicker" aria-hidden="true">SAST × LOCAL-LLM REMEDIATION × CI GATE</div>
          <h1 className="sy-h1">
            <MaskLine i={0}>Find the flaw.</MaskLine><br />
            <MaskLine i={1}>Fix the flaw.</MaskLine><br />
            <MaskLine i={2}><em>Prove the fix.</em></MaskLine>
          </h1>
          <p className="sy-lede">
            SecurePy AI is a context-aware static analysis engine for Python. It detects
            vulnerabilities through AST traversal, generates candidate patches with a locally-hosted
            LLM, validates every patch against a 4-tier security oracle — and gates your CI on confidence,
            not noise.
          </p>
          <div className="sy-open-meta" role="list" aria-label="Feature highlights">
            <span className="sy-chip" role="listitem">{stats.findings} findings in scope</span>
            <span className="sy-chip" role="listitem">5 CWE rule engines</span>
            <span className="sy-chip" role="listitem">4 validation layers</span>
            <span className="sy-chip sy-chip-g" role="listitem">privacy-first offline</span>
          </div>
        </div>
        <div className="sy-open-right">
          <Terminal onTriggerScan={runScan} scanning={scanning} />
          <div className="sy-open-strip" aria-label="Scan statistics">
            <div><CountUp to={stats.files} /> <i>files</i></div>
            <div><CountUp to={stats.findings} /> <i>findings</i></div>
            <div><CountUp to={stats.patches} /> <i>patches</i></div>
            <div><CountUp to={stats.validated} /> <i>validated</i></div>
            <div><CountUp to={stats.topConf} suffix="%" /> <i>top conf.</i></div>
          </div>
        </div>
      </section>

      {/* ── CWE Ticker ── */}
      <div className="sy-ticker" aria-hidden="true">
        <div className="sy-ticker-track">
          {[...TICKER, ...TICKER].map((t, i) => (
            <span key={i} className="sy-ticker-item">{t}<span className="sy-ticker-sep">/</span></span>
          ))}
        </div>
      </div>

      {/* ── Live Scan Control Center & Scan History ── */}
      <section className="sy-sec" id="control" aria-labelledby="control-heading">
        <SectionHead index="01" label="LIVE ENGINE CONTROLLER" title="Run real scans against your Python codebase." />
        <div className="sy-control-grid">
          <div className="sy-control-card">
            <div className="sy-card-title">SCAN CONFIGURATION</div>
            <div className="sy-cform">
              <div>
                <label className="sy-clabel">Target Path / File</label>
                {pyFiles.length > 0 ? (
                  <select
                    className="sy-cinput"
                    value={form.target}
                    onChange={(e) => setForm({ ...form, target: e.target.value })}
                  >
                    {pyFiles.map(p => <option key={p} value={p}>{p}</option>)}
                    <option value="__custom__">— enter manually —</option>
                  </select>
                ) : (
                  <input
                    className="sy-cinput"
                    value={form.target}
                    onChange={(e) => setForm({ ...form, target: e.target.value })}
                    placeholder="examples/vulnerable.py"
                  />
                )}
                {form.target === "__custom__" && (
                  <input
                    className="sy-cinput"
                    style={{ marginTop: "6px" }}
                    placeholder="Type path e.g. myapp/views.py"
                    onBlur={(e) => e.target.value && setForm({ ...form, target: e.target.value })}
                  />
                )}
              </div>

              <div>
                <label className="sy-clabel">LLM Model</label>
                <select
                  className="sy-cinput"
                  value={form.model}
                  onChange={(e) => setForm({ ...form, model: e.target.value })}
                >
                  <option value="codellama:13b">codellama:13b (Recommended)</option>
                  <option value="deepseek-coder:6.7b">deepseek-coder:6.7b</option>
                  <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option>
                  <option value="qwen2.5-coder:1.5b">qwen2.5-coder:1.5b (Fast)</option>
                </select>
              </div>

              <div className="sy-ctoggles">
                <label className="sy-toggle">
                  <input
                    type="checkbox"
                    checked={form.fix}
                    onChange={(e) => setForm({ ...form, fix: e.target.checked })}
                  />
                  <span>Generate Patches (--fix)</span>
                </label>
                <label className="sy-toggle">
                  <input
                    type="checkbox"
                    checked={form.mock_llm}
                    onChange={(e) => setForm({ ...form, mock_llm: e.target.checked })}
                  />
                  <span>Use Mock LLM (Fast Test)</span>
                </label>
                <label className="sy-toggle">
                  <input
                    type="checkbox"
                    checked={form.validate}
                    onChange={(e) => setForm({ ...form, validate: e.target.checked })}
                  />
                  <span>Run Security Oracle Validation</span>
                </label>
              </div>

              <button
                className="sy-run-btn"
                onClick={runScan}
                disabled={scanning}
              >
                {scanning ? "SCANNING ENGINE RUNNING…" : "$ securepy-ai scan"}
              </button>

              {error && <div className="sy-cerr">{error}</div>}
              {notice && <div className="sy-notice">{notice}</div>}
              {report?.scan_time_ms != null && (
                <div className="sy-cmeta">
                  Last execution: <b>{report.scan_time_ms} ms</b> · Target: <b>{report.target}</b> · Findings: <b>{stats.findings}</b>
                </div>
              )}
            </div>
          </div>

          <div className="sy-control-card">
            <div className="sy-card-title">SCAN LEDGER & HISTORY ({history.length})</div>
            <div className="sy-chist">
              {history.length === 0 && (
                <div className="sy-empty">
                  No previous scans recorded.<br />Run a scan above to save results.
                </div>
              )}
              {history.map((h) => {
                const ts = h.generated_at ? new Date(h.generated_at) : null;
                const dateStr = ts ? ts.toLocaleDateString("en-IN", { day: "2-digit", month: "short" }) : "";
                const timeStr = ts ? ts.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }) : (h.id || "").slice(5, 13);
                return (
                  <button
                    key={h.id}
                    className={"sy-hrow" + (report?.id === h.id ? " on" : "")}
                    onClick={() => openScan(h.id)}
                  >
                    <div className="sy-hrow-main">
                      <b>{h.target || "unknown"}</b>
                      <i>{h.findings} finding{h.findings !== 1 ? "s" : ""} · {h.valid ?? 0} auto-apply fix{(h.valid ?? 0) !== 1 ? "es" : ""}</i>
                    </div>
                    <span className="sy-htime" title={ts?.toISOString()}>{dateStr} {timeStr}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Phase 10.4: Working Tree Changes & Audit Trail Row */}
        <div className="sy-control-grid" style={{ marginTop: "24px" }}>
          {/* Working Tree Changes */}
          <div className="sy-control-card">
            <div className="sy-card-title" style={{ display: "flex", justifyContent: "space-between" }}>
              <span>WORKING TREE MODIFICATIONS</span>
              <span style={{ color: git?.dirty ? AMBER : ACCENT }}>
                {git?.dirty ? `● ${git?.changed?.length || 0} modified` : "✓ clean"}
              </span>
            </div>
            <div className="sy-chist">
              {(!git?.changed || git.changed.length === 0) && (
                <div className="sy-empty">Working tree is clean. No uncommitted file modifications.</div>
              )}
              {git?.changed?.map((line) => {
                const parts = line.split(/\s+/);
                const statusFlag = parts[0] || "M";
                const filePath = parts.slice(1).join(" ") || line;
                return (
                  <div key={filePath} className="sy-hrow" style={{ cursor: "default" }}>
                    <div className="sy-hrow-main">
                      <b><span style={{ color: AMBER, fontFamily: MONO, marginRight: "8px" }}>[{statusFlag}]</span>{filePath}</b>
                      <i>Local change in working tree</i>
                    </div>
                    <div style={{ display: "flex", gap: "6px" }}>
                      <button
                        className="sy-fbtn"
                        style={{ padding: "4px 8px", fontSize: "10.5px" }}
                        onClick={() => loadGitDiff(filePath)}
                      >
                        Inspect Diff
                      </button>
                      <button
                        className="sy-fbtn"
                        style={{ padding: "4px 8px", fontSize: "10.5px", color: RED, borderColor: "rgba(248,81,73,0.4)" }}
                        disabled={reverting}
                        onClick={() => revertFile(filePath)}
                      >
                        Revert
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Remediation Audit Trail */}
          <div className="sy-control-card">
            <div className="sy-card-title">REMEDIATION AUDIT TRAIL ({auditEntries.length})</div>
            <div className="sy-chist">
              {auditEntries.length === 0 && (
                <div className="sy-empty">No remediation decisions logged yet.<br />Apply or download a patch to record actions.</div>
              )}
              {auditEntries.map((a, i) => (
                <div key={i} className="sy-hrow" style={{ cursor: "default" }}>
                  <div className="sy-hrow-main">
                    <b>
                      <span style={{
                        color: a.action === "apply" ? ACCENT : a.action === "patch_file" ? CYAN : a.action === "revert" ? AMBER : RED,
                        fontFamily: MONO,
                        marginRight: "8px"
                      }}>
                        [{a.action.toUpperCase()}]
                      </span>
                      {a.file || a.finding || a.action}
                    </b>
                    <i>{a.mode ? `Mode: ${a.mode}` : a.reason ? `Reason: ${a.reason}` : "Decision recorded"}</i>
                  </div>
                  <span className="sy-htime">{(a.time || "").slice(11, 19)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live Git Diff Viewer Modal / Box */}
        {activeDiffText && (
          <div style={{ marginTop: "20px", border: `1px solid ${LINE}`, background: "#0b1017", padding: "18px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <span style={{ fontFamily: MONO, fontSize: "11.5px", color: ACCENT }}>
                DIFF INSPECTOR: <b>{activeDiffFile}</b>
              </span>
              <button className="sy-fbtn" style={{ padding: "4px 10px" }} onClick={() => setActiveDiffText("")}>
                Close Diff
              </button>
            </div>
            <pre style={{
              background: "#0d141c",
              border: `1px solid ${LINE}`,
              padding: "12px",
              fontFamily: MONO,
              fontSize: "12px",
              color: TXT,
              maxHeight: "260px",
              overflowY: "auto",
              whiteSpace: "pre-wrap"
            }}>
              {activeDiffText}
            </pre>
          </div>
        )}
      </section>

      {/* ── Pipeline Section ── */}
      <section className="sy-sec" id="pipeline" aria-labelledby="pipeline-heading">
        <SectionHead index="02" label="DETECTION → REMEDIATION PIPELINE" title="Eight stages. One verified patch." />
        <div className="sy-pipe">
          <div className="sy-pipe-list" role="tablist" aria-label="Pipeline stages">
            {PIPELINE.map((p, i) => (
              <button key={p.n}
                className={"sy-pipe-row" + (step === i ? " on" : "")}
                onClick={() => setStep(i)}
                role="tab"
                aria-selected={step === i}
                id={`pipeline-tab-${i}`}
                aria-controls={`pipeline-panel-${i}`}>
                <span className="sy-pipe-n">{p.n}</span>
                <span className="sy-pipe-t">{p.t}</span>
                <span className="sy-pipe-bar"><span style={{ width: step === i ? "100%" : "0%" }} /></span>
              </button>
            ))}
          </div>
          <div className="sy-pipe-detail" role="tabpanel" id={`pipeline-panel-${step}`} aria-labelledby={`pipeline-tab-${step}`}>
            <AnimatePresence mode="wait">
              <motion.div key={step}
                initial={prm ? {} : { opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25 }}>
                <div className="sy-pipe-dn">{PIPELINE[step].n} / {PIPELINE[step].t}</div>
                <p className="sy-pipe-dd">{PIPELINE[step].d}</p>
                <div className="sy-pipe-tech">{PIPELINE[step].tech}</div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </section>

      {/* ── Findings Workbench ── */}
      <section className="sy-sec" id="console" aria-labelledby="console-heading">
        <SectionHead index="03" label="REMEDIATION WORKBENCH" title="Every finding ships with a validated fix." />

        {/* ── Severity Breakdown Bar Chart ── */}
        {activeFindings.length > 0 && (
          <div style={{ display: "flex", gap: "12px", alignItems: "flex-end", marginBottom: "20px", padding: "16px", background: "#0b1017", border: `1px solid ${LINE}`, borderRadius: "8px" }}>
            <span style={{ fontFamily: MONO, fontSize: "10px", color: MUT, writingMode: "vertical-rl", transform: "rotate(180deg)", marginRight: "4px" }}>SEVERITY</span>
            {Object.entries(sevCounts).map(([sev, count]) => (
              <div key={sev} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "4px", flex: 1 }}>
                <span style={{ fontFamily: MONO, fontSize: "11px", color: SEV_COLOR[sev] || MUT, fontWeight: 700 }}>{count}</span>
                <div style={{ width: "100%", background: "rgba(140,160,180,0.1)", borderRadius: "3px", height: "60px", display: "flex", alignItems: "flex-end" }}>
                  <div style={{
                    width: "100%",
                    height: `${(count / sevMax) * 100}%`,
                    background: SEV_COLOR[sev] || MUT,
                    borderRadius: "3px 3px 0 0",
                    minHeight: count > 0 ? "4px" : "0",
                    transition: "height 0.5s ease"
                  }} />
                </div>
                <span style={{ fontFamily: MONO, fontSize: "9px", color: MUT, textTransform: "uppercase" }}>{sev}</span>
              </div>
            ))}
            <div style={{ marginLeft: "auto", textAlign: "right", alignSelf: "center" }}>
              <div style={{ fontFamily: MONO, fontSize: "22px", fontWeight: 700, color: TXT }}>{activeFindings.length}</div>
              <div style={{ fontFamily: MONO, fontSize: "9px", color: MUT }}>TOTAL FINDINGS</div>
            </div>
          </div>
        )}

        <div className="sy-filters" role="group" aria-label="Filter by severity">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((s) => (
            <button key={s}
              className={"sy-fbtn" + (filter === s ? " on" : "")}
              onClick={() => { setFilter(s); setSel(0); }}
              aria-pressed={filter === s}
              id={`filter-${s.toLowerCase()}`}>
              {s}
            </button>
          ))}
          <span style={{ marginLeft: "auto", fontFamily: MONO, fontSize: "11px", color: MUT, alignSelf: "center" }}>
            Showing {shown.length} of {activeFindings.length} findings
          </span>
        </div>

        <div className="sy-console">
          <div className="sy-clist" role="listbox" aria-label="Security findings">
            {shown.length === 0 && (
              <div className="sy-empty">No findings matching "{filter}"</div>
            )}
            {shown.map((x, i) => (
              <button key={x.id + x.file + x.line}
                className={"sy-crow" + (safeSel === i ? " on" : "")}
                onClick={() => setSel(i)}
                role="option"
                aria-selected={safeSel === i}
                id={`finding-${x.id.toLowerCase()}`}>
                <span className={"sy-sev sy-sev-" + x.sev.toLowerCase()}>{x.sev}</span>
                <span className="sy-crow-main">
                  <b>{x.title}</b>
                  <i>{x.file}:{x.line} · {x.cwe}</i>
                </span>
                <span className="sy-conf">{Math.round(x.conf * 100)}%</span>
              </button>
            ))}
          </div>

          <div className="sy-cdetail" aria-live="polite" aria-label="Finding details">
            {f && (
              <>
                <div className="sy-cd-head">
                  <div>
                    <div className="sy-cd-title">{f.title} <span className="sy-cd-cwe">{f.cwe}</span></div>
                    <div className="sy-cd-flow">{f.flow}</div>
                  </div>
                  <div className="sy-cd-conf" aria-label={`Confidence score: ${Math.round(f.conf * 100)}%`}>
                    <svg viewBox="0 0 36 36" className="sy-ring" aria-hidden="true">
                      <path d="M18 2.5 a 15.5 15.5 0 1 1 0 31 a 15.5 15.5 0 1 1 0 -31" fill="none" stroke="rgba(140,160,180,.18)" strokeWidth="3" />
                      <path d="M18 2.5 a 15.5 15.5 0 1 1 0 31 a 15.5 15.5 0 1 1 0 -31" fill="none"
                        stroke={f.conf >= 0.8 ? ACCENT : f.conf >= 0.5 ? AMBER : RED} strokeWidth="3"
                        strokeDasharray={`${f.conf * 97.4} 97.4`} strokeLinecap="round" />
                    </svg>
                    <div><b>{Math.round(f.conf * 100)}%</b><i>confidence</i></div>
                  </div>
                </div>

                <div className="sy-cd-modes" role="group" aria-label="Code view mode">
                  {["diff", "before", "after"].map((m) => (
                    <button key={m}
                      className={"sy-mbtn" + (mode === m ? " on" : "")}
                      onClick={() => setMode(m)}
                      aria-pressed={mode === m}
                      id={`mode-${m}`}>
                      {m}
                    </button>
                  ))}
                  <span className={"sy-cd-status sy-st-" + f.status.toLowerCase().replace(/\s+/g, "-")}>
                    {f.status}
                  </span>
                </div>

                <div className="sy-code" role="region" aria-label="Code diff viewer">
                  {mode === "diff" && f.diff.map((l, i) => (
                    <div key={i} className={"sy-cl sy-cl-" + l.t}>
                      <span className="sy-cl-s">{l.t === "add" ? "+" : l.t === "del" ? "−" : " "}</span>{l.x}
                    </div>
                  ))}
                  {mode !== "diff" && (mode === "before" ? f.before : f.after).map((l, i) => (
                    <div key={i} className={"sy-cl " + (mode === "before" ? "sy-cl-src" : "sy-cl-fix")}>
                      <span className="sy-cl-no">{i + 1}</span>{l}
                    </div>
                  ))}
                </div>

                <div className="sy-checks" role="list" aria-label="Validation checks">
                  {f.checks.map(([label, st]) => (
                    <div key={label} className="sy-check" role="listitem">
                      <span className={"sy-check-ic sy-check-" + st} aria-hidden="true">{st === "pass" ? "✓" : st === "warn" ? "!" : "✕"}</span>
                      <span>{label}</span>
                      <span className="sy-check-st" aria-label={`Status: ${st}`}>{st.toUpperCase()}</span>
                    </div>
                  ))}
                </div>

                {/* Phase 10.3: Remediation Decision & Apply Actions */}
                <div className="sy-actions-box">
                  <div className="sy-actions-title">HUMAN-IN-THE-LOOP REMEDIATION</div>
                  <div className="sy-actions">
                    <button
                      className="sy-act-btn"
                      disabled={applying}
                      onClick={() => applyPatch("patch")}
                      title="Download git-applicable .patch file"
                    >
                      download .patch
                    </button>
                    <button
                      className="sy-act-btn"
                      disabled={applying}
                      onClick={() => applyPatch("working_tree")}
                      title="Apply changes directly to working tree file (backed up)"
                    >
                      apply → working tree
                    </button>
                    <button
                      className="sy-act-btn sy-act-commit"
                      disabled={applying}
                      onClick={() => applyPatch("commit")}
                      title="Commit changes locally to securepy/fixes branch"
                    >
                      commit locally (securepy/fixes)
                    </button>
                    <span className="sy-nopush">🛡️ human-in-the-loop · never pushes</span>
                  </div>
                  {notice && (
                    <div className="sy-notice-banner" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
                      <span>{notice}</span>
                      {(notice.includes("Re-scan") || notice.includes("verify")) && (
                        <button
                          className="sy-run-btn"
                          style={{ padding: "6px 16px", fontSize: "11px", marginTop: 0, flexShrink: 0 }}
                          onClick={() => { setNotice(""); runScan(); }}
                          disabled={scanning}
                        >
                          {scanning ? "Scanning…" : "🔄 Re-scan to Verify"}
                        </button>
                      )}
                    </div>
                  )}
                  {error && <div className="sy-cerr">{error}</div>}
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      {/* ── Research Section ── */}
      <section className="sy-sec sy-research" id="research" aria-labelledby="research-heading">
        <div className="sy-res-grid">
          <div className="sy-res-sticky">
            <img
              src="/images/ast-diagram.jpg"
              alt="Abstract Syntax Tree with flagged vulnerability sinks"
              style={{ width: '100%', display: 'block', borderRadius: 0 }}
              loading="lazy"
            />
            <div className="sy-res-cap">fig. 01 — abstract syntax tree with flagged sinks</div>
          </div>
          <div className="sy-res-body">
            <SectionHead index="04" label="RESEARCH POSITION" title="Beyond detection-only SAST." />
            <p className="sy-res-p">
              Existing SAST tools and ML detectors <b>flag</b> vulnerabilities but leave remediation to humans.
              Generic LLM repair fixes bugs but ignores <b>security correctness</b> — a patch can pass every test
              and remain exploitable. SecurePy AI closes both gaps.
            </p>
            <div className="sy-res-rows">
              <div className="sy-res-row"><span className="sy-res-k">Gap 01</span><p>Detection-to-repair: findings are wired straight into a remediation pipeline.</p></div>
              <div className="sy-res-row"><span className="sy-res-k">Gap 02</span><p>Context: AST-derived scope, data-flow and CWE guidance steer the LLM — echoing Fan et al.'s finding that fault-localization guidance improves LLM repair.</p></div>
              <div className="sy-res-row"><span className="sy-res-k">Gap 03</span><p>Validation: a security oracle (re-scan + no-new-vuln) replaces test-only oracles.</p></div>
              <div className="sy-res-row"><span className="sy-res-k">Gap 04</span><p>Privacy: open-weight local models, so source never reaches a cloud API.</p></div>
            </div>
            <div className="sy-res-cite">
              Base paper — Z. Fan et al., <i>"Automated Repair of Programs from Large Language Models,"</i> arXiv:2205.10583.
            </div>
          </div>
        </div>
      </section>

      {/* ── Roadmap Section ── */}
      <section className="sy-sec" id="roadmap" aria-labelledby="roadmap-heading">
        <SectionHead index="05" label="EVOLUTION · 24 PHASES" title="From thesis tool to autonomous AppSec engineer." />
        <div className="sy-road" role="list">
          {ROADMAP.map((r) => (
            <div key={r.range} className={"sy-road-row sy-road-" + r.status} role="listitem">
              <div className="sy-road-range">{r.range}</div>
              <div className="sy-road-name">
                {r.name}
                <span className={"sy-road-tag sy-tag-" + r.status}>
                  {r.status === "done" ? "SHIPPED" : r.status === "current" ? "LIVE ENGINE" : r.status === "next" ? "NEXT" : "PLANNED"}
                </span>
              </div>
              <div className="sy-road-items">{r.items.map((it) => <span key={it}>{it}</span>)}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="sy-foot">
        <div className="sy-foot-l">
          <img
            src="/logo.jpg"
            alt="SecurePy AI logo"
            width="36"
            height="36"
            style={{ borderRadius: '4px', objectFit: 'cover', display: 'block' }}
            loading="lazy"
          />
          <div>
            <div className="sy-word">SecurePy<span className="sy-word-ai">_AI</span></div>
            <div className="sy-foot-sub">Sagar Porwal · National Forensic Sciences University, Delhi</div>
          </div>
        </div>
        <div className="sy-foot-r">
          <span>github.com/SagarPorwal10</span>
          <span>sagarporwalofficial@gmail.com</span>
          <span className="sy-foot-mono">$ securepy-ai --version → 1.0.0</span>
        </div>
      </footer>

      {/* Scanline overlay */}
      <div className="sy-noise" aria-hidden="true" />
    </div>
  );
}

/* ================================================================
   Design System & Styling
   ================================================================ */
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;600&family=Space+Grotesk:wght@500;700&display=swap');

:root{
  --ink:#0a0e14; --panel:#0d141c; --panel2:#0f1822; --line:rgba(140,160,180,.16);
  --txt:#dbe4ec; --mut:#8b98a5; --acc:#7ee787; --amb:#d29922; --red:#f85149; --cyn:#58c4dc;
  --mono:'IBM Plex Mono',ui-monospace,monospace; --disp:'Space Grotesk',sans-serif; --body:'IBM Plex Sans',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
.sy-root{background:var(--ink);color:var(--txt);font-family:var(--body);min-height:100vh;position:relative;overflow-x:hidden}
.sy-root ::selection{background:rgba(126,231,135,.25)}
.sy-root ::-webkit-scrollbar{width:10px;height:10px}
.sy-root ::-webkit-scrollbar-thumb{background:#1c2836;border-radius:5px}

/* noise + scanline */
.sy-noise{position:fixed;inset:0;pointer-events:none;z-index:60;opacity:.05;mix-blend-mode:overlay;
  background:repeating-linear-gradient(0deg,rgba(255,255,255,.5) 0 1px,transparent 1px 3px);}

/* status bar */
.sy-status{display:flex;gap:22px;align-items:center;padding:7px 22px;border-bottom:1px solid var(--line);
  font-family:var(--mono);font-size:11px;color:var(--mut);background:#0b1017;letter-spacing:.04em}
.sy-status b{color:var(--txt);font-weight:500}
.sy-status-item{display:flex;gap:7px;align-items:center}
.sy-right{margin-left:auto;color:var(--acc)}
.sy-live{width:7px;height:7px;border-radius:50%;background:#3a4654}
.sy-live.on{background:var(--acc);box-shadow:0 0 8px var(--acc);animation:sypulse 1.8s infinite}
.sy-live.off{background:var(--amb)}
@keyframes sypulse{50%{opacity:.35}}

/* nav */
.sy-nav{display:flex;align-items:center;gap:26px;padding:16px 22px;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(10,14,20,.92);backdrop-filter:blur(6px);z-index:50}
.sy-brand{display:flex;gap:10px;align-items:center;text-decoration:none;color:var(--txt)}
.sy-word{font-family:var(--disp);font-weight:700;font-size:17px;letter-spacing:.01em}
.sy-word-ai{color:var(--acc)}
.sy-links{display:flex;gap:22px;margin-left:auto;font-family:var(--mono);font-size:12px}
.sy-links a{color:var(--mut);text-decoration:none;transition:color .15s}
.sy-links a:hover{color:var(--acc)}
.sy-cta{font-family:var(--mono);font-size:12px;color:var(--acc);border:1px solid rgba(126,231,135,.4);padding:8px 14px;text-decoration:none;background:rgba(126,231,135,.06);transition:.15s}
.sy-cta:hover{background:rgba(126,231,135,.14)}

/* opening hero */
.sy-open{display:grid;grid-template-columns:1.05fr .95fr;gap:44px;padding:64px 22px 48px;max-width:1280px;margin:0 auto;align-items:start}
.sy-kicker{font-family:var(--mono);font-size:11px;letter-spacing:.22em;color:var(--acc);margin-bottom:22px}
.sy-h1{font-family:var(--disp);font-weight:700;font-size:clamp(40px,6vw,76px);line-height:1.02;letter-spacing:-.02em}
.sy-h1 em{font-style:italic;color:var(--acc)}
.sy-mask{display:inline-block;overflow:hidden;vertical-align:bottom}
.sy-mask-in{display:inline-block}
.sy-lede{color:var(--mut);font-size:15.5px;line-height:1.7;margin:26px 0 24px;max-width:56ch}
.sy-lede b{color:var(--txt)}
.sy-open-meta{display:flex;gap:10px;flex-wrap:wrap}
.sy-chip{font-family:var(--mono);font-size:11px;color:var(--mut);border:1px solid var(--line);padding:6px 11px}
.sy-chip-g{color:var(--acc);border-color:rgba(126,231,135,.4)}

/* terminal */
.sy-term{border:1px solid var(--line);background:#0b1017;box-shadow:0 20px 60px rgba(0,0,0,.45)}
.sy-term-bar{display:flex;gap:7px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--line)}
.sy-dot{width:10px;height:10px;border-radius:50%}
.sy-term-title{font-family:var(--mono);font-size:11px;color:var(--mut);margin-left:8px}
.sy-term-rerun{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--mut);background:none;border:1px solid var(--line);padding:3px 9px;cursor:pointer}
.sy-term-rerun:hover{color:var(--acc);border-color:rgba(126,231,135,.4)}
.sy-term-body{padding:16px 14px;font-family:var(--mono);font-size:12.5px;line-height:1.85;min-height:340px}
.sy-tl{display:flex;gap:10px;white-space:pre-wrap;word-break:break-word}
.sy-tg{width:12px;flex:0 0 auto;text-align:center}
.sy-tg-dim{color:#41506a}.sy-tg-warn{color:var(--red)}.sy-tg-ok{color:var(--acc)}.sy-tg-bad{color:var(--red)}.sy-tg-rev{color:var(--amb)}
.sy-cmd{color:var(--txt)}
.sy-caret{color:var(--acc);animation:syblink 1s steps(1) infinite}
@keyframes syblink{50%{opacity:0}}
.sy-open-strip{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);border-top:0}
.sy-open-strip>div{padding:14px 8px;text-align:center;font-family:var(--disp);font-weight:700;font-size:22px;border-right:1px solid var(--line)}
.sy-open-strip>div:last-child{border-right:0}
.sy-open-strip i{display:block;font-family:var(--mono);font-style:normal;font-size:10px;letter-spacing:.14em;color:var(--mut);margin-top:4px;text-transform:uppercase}

/* ticker */
.sy-ticker{border-top:1px solid var(--line);border-bottom:1px solid var(--line);overflow:hidden;background:#0b1017}
.sy-ticker-track{display:flex;width:max-content;animation:symar 30s linear infinite;padding:10px 0}
.sy-ticker:hover .sy-ticker-track{animation-play-state:paused}
@keyframes symar{to{transform:translateX(-50%)}}
.sy-ticker-item{font-family:var(--mono);font-size:11.5px;letter-spacing:.14em;color:var(--mut);padding:0 18px;white-space:nowrap}
.sy-ticker-sep{color:var(--acc);margin-left:18px}

/* sections */
.sy-sec{max-width:1280px;margin:0 auto;padding:72px 22px}
.sy-shead{margin-bottom:34px}
.sy-shead-top{display:flex;align-items:center;gap:14px;margin-bottom:14px}
.sy-idx{font-family:var(--mono);font-size:12px;color:var(--acc)}
.sy-slabel{font-family:var(--mono);font-size:11px;letter-spacing:.2em;color:var(--mut)}
.sy-rule{flex:1;height:1px;background:var(--line)}
.sy-h2{font-family:var(--disp);font-weight:700;font-size:clamp(26px,3.4vw,42px);letter-spacing:-.01em}

/* control center */
.sy-control-grid{display:grid;grid-template-columns:1fr 1fr;gap:26px}
.sy-control-card{border:1px solid var(--line);background:#0b1017;padding:24px}
.sy-card-title{font-family:var(--mono);font-size:11px;letter-spacing:.18em;color:var(--acc);margin-bottom:20px}
.sy-cform{display:flex;flex-direction:column;gap:16px}
.sy-clabel{font-family:var(--mono);font-size:11px;color:var(--mut);display:block;margin-bottom:6px}
.sy-cinput{width:100%;background:#0d141c;border:1px solid var(--line);color:var(--txt);font-family:var(--mono);font-size:12px;padding:10px 12px}
.sy-cinput:focus{outline:none;border-color:var(--acc)}
.sy-ctoggles{display:flex;flex-direction:column;gap:8px;margin:4px 0}
.sy-toggle{display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:12px;color:var(--txt);cursor:pointer}
.sy-toggle input{accent-color:var(--acc)}
.sy-run-btn{background:rgba(126,231,135,.1);border:1px solid var(--acc);color:var(--acc);font-family:var(--mono);font-size:13px;padding:13px;cursor:pointer;font-weight:500;transition:.15s}
.sy-run-btn:hover:not(:disabled){background:rgba(126,231,135,.2)}
.sy-run-btn:disabled{opacity:.5;cursor:wait}
.sy-cerr{color:var(--red);font-family:var(--mono);font-size:11.5px;padding:8px 0}
.sy-cmeta{font-family:var(--mono);font-size:11px;color:var(--mut);border-top:1px solid var(--line);padding-top:12px}
.sy-cmeta b{color:var(--txt)}

.sy-chist{max-height:330px;overflow-y:auto;border:1px solid var(--line);background:#0d141c}
.sy-hrow{display:flex;justify-content:space-between;align-items:center;width:100%;text-align:left;background:none;border:0;border-bottom:1px solid var(--line);padding:14px 16px;cursor:pointer;color:var(--txt);transition:background .15s}
.sy-hrow:hover{background:rgba(126,231,135,.04)}
.sy-hrow.on{background:rgba(126,231,135,.09);box-shadow:inset 2px 0 0 var(--acc)}
.sy-hrow-main b{display:block;font-size:13px;font-weight:600}
.sy-hrow-main i{display:block;font-style:normal;font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:3px}
.sy-htime{font-family:var(--mono);font-size:11px;color:var(--cyn)}

/* pipeline */
.sy-pipe{display:grid;grid-template-columns:.9fr 1.1fr;gap:26px;border:1px solid var(--line)}
.sy-pipe-list{border-right:1px solid var(--line)}
.sy-pipe-row{display:grid;grid-template-columns:44px 110px 1fr;gap:14px;align-items:center;width:100%;text-align:left;
  padding:15px 18px;background:none;border:0;border-bottom:1px solid var(--line);cursor:pointer;color:var(--mut);transition:background .15s}
.sy-pipe-row:last-child{border-bottom:0}
.sy-pipe-row:hover{background:rgba(126,231,135,.04)}
.sy-pipe-row.on{background:rgba(126,231,135,.07);color:var(--txt)}
.sy-pipe-n{font-family:var(--mono);font-size:12px;color:var(--acc)}
.sy-pipe-t{font-family:var(--disp);font-weight:700;font-size:15px}
.sy-pipe-bar{height:2px;background:rgba(140,160,180,.12)}
.sy-pipe-bar span{display:block;height:100%;background:var(--acc);transition:width .5s ease}
.sy-pipe-detail{padding:30px 28px;display:flex;align-items:center}
.sy-pipe-dn{font-family:var(--mono);font-size:12px;letter-spacing:.16em;color:var(--acc);margin-bottom:14px}
.sy-pipe-dd{color:var(--mut);font-size:15px;line-height:1.7;max-width:52ch}
.sy-pipe-tech{margin-top:18px;font-family:var(--mono);font-size:11px;color:var(--cyn);border:1px solid rgba(88,196,220,.3);display:inline-block;padding:5px 10px}

/* findings console */
.sy-filters{display:flex;gap:8px;margin-bottom:16px}
.sy-fbtn{font-family:var(--mono);font-size:11px;letter-spacing:.1em;color:var(--mut);background:none;border:1px solid var(--line);padding:7px 13px;cursor:pointer}
.sy-fbtn.on{color:var(--ink);background:var(--acc);border-color:var(--acc)}
.sy-console{display:grid;grid-template-columns:360px 1fr;border:1px solid var(--line)}
.sy-clist{border-right:1px solid var(--line);max-height:560px;overflow-y:auto}
.sy-crow{display:grid;grid-template-columns:78px 1fr 48px;gap:12px;align-items:center;width:100%;text-align:left;
  padding:15px 14px;background:none;border:0;border-bottom:1px solid var(--line);cursor:pointer;color:var(--txt)}
.sy-crow:last-child{border-bottom:0}
.sy-crow:hover{background:rgba(126,231,135,.04)}
.sy-crow.on{background:rgba(126,231,135,.08);box-shadow:inset 2px 0 0 var(--acc)}
.sy-sev{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-align:center;padding:4px 0}
.sy-sev-critical{color:var(--red);border:1px solid rgba(248,81,73,.5)}
.sy-sev-high{color:var(--amb);border:1px solid rgba(210,153,34,.5)}
.sy-sev-medium{color:var(--cyn);border:1px solid rgba(88,196,220,.5)}
.sy-sev-low,.sy-sev-info{color:var(--acc);border:1px solid rgba(126,231,135,.5)}
.sy-crow-main b{display:block;font-size:13.5px;font-weight:600}
.sy-crow-main i{display:block;font-style:normal;font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:3px}
.sy-conf{font-family:var(--mono);font-size:12px;color:var(--acc);text-align:right}
.sy-cdetail{padding:22px 24px;max-height:560px;overflow-y:auto}
.sy-cd-head{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;margin-bottom:16px}
.sy-cd-title{font-family:var(--disp);font-weight:700;font-size:20px}
.sy-cd-cwe{font-family:var(--mono);font-size:11px;color:var(--cyn);margin-left:8px}
.sy-cd-flow{font-family:var(--mono);font-size:11.5px;color:var(--mut);margin-top:7px}
.sy-cd-conf{display:flex;gap:12px;align-items:center}
.sy-ring{width:56px;height:56px}
.sy-cd-conf b{font-family:var(--disp);font-size:18px;display:block}
.sy-cd-conf i{font-style:normal;font-family:var(--mono);font-size:10px;color:var(--mut);letter-spacing:.1em}
.sy-cd-modes{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.sy-mbtn{font-family:var(--mono);font-size:11px;color:var(--mut);background:none;border:1px solid var(--line);padding:5px 12px;cursor:pointer}
.sy-mbtn.on{color:var(--acc);border-color:rgba(126,231,135,.45)}
.sy-cd-status{margin-left:auto;font-family:var(--mono);font-size:10px;letter-spacing:.1em;padding:4px 10px}
.sy-st-validated{color:var(--acc);border:1px solid rgba(126,231,135,.45)}
.sy-st-review{color:var(--amb);border:1px solid rgba(210,153,34,.45)}
.sy-st-rejected,.sy-st-no-patch{color:var(--red);border:1px solid rgba(248,81,73,.45)}
.sy-code{border:1px solid var(--line);background:#0b1017;font-family:var(--mono);font-size:12px;line-height:1.8;padding:12px 10px;max-height:250px;overflow:auto}
.sy-cl{white-space:pre-wrap;word-break:break-word;padding:0 6px}
.sy-cl-add{background:rgba(126,231,135,.09);color:#b7f4c0}
.sy-cl-del{background:rgba(248,81,73,.09);color:#f2a19b;text-decoration:line-through}
.sy-cl-ctx{color:var(--mut)}
.sy-cl-s{display:inline-block;width:16px;color:inherit}
.sy-cl-src{color:#f2a19b}.sy-cl-fix{color:#b7f4c0}
.sy-cl-no{display:inline-block;width:22px;color:#41506a;text-align:right;margin-right:10px}
.sy-checks{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
.sy-check{display:flex;gap:10px;align-items:center;border:1px solid var(--line);padding:9px 12px;font-size:12.5px;color:var(--mut)}
.sy-check-ic{width:20px;height:20px;display:grid;place-items:center;font-size:11px}
.sy-check-pass{color:var(--acc);border:1px solid rgba(126,231,135,.4)}
.sy-check-warn{color:var(--amb);border:1px solid rgba(210,153,34,.4)}
.sy-check-fail{color:var(--red);border:1px solid rgba(248,81,73,.4)}
.sy-check-st{margin-left:auto;font-family:var(--mono);font-size:10px;letter-spacing:.1em}
.sy-empty{padding:30px 20px;text-align:center;font-family:var(--mono);font-size:12px;color:var(--mut);line-height:1.7}

/* Phase 10.3: Remediation actions */
.sy-actions-box{margin-top:20px;border-top:1px dashed var(--line);padding-top:16px}
.sy-actions-title{font-family:var(--mono);font-size:10.5px;letter-spacing:.16em;color:var(--acc);margin-bottom:12px}
.sy-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sy-act-btn{font-family:var(--mono);font-size:11.5px;color:var(--txt);background:rgba(126,231,135,.06);border:1px solid rgba(126,231,135,.35);padding:9px 14px;cursor:pointer;transition:.15s}
.sy-act-btn:hover:not(:disabled){background:rgba(126,231,135,.16);border-color:var(--acc)}
.sy-act-btn:disabled{opacity:.5;cursor:wait}
.sy-act-commit{color:var(--acc);font-weight:500;border-color:rgba(126,231,135,.6)}
.sy-nopush{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--mut);border:1px dashed var(--line);padding:6px 10px}
.sy-notice-banner{margin-top:12px;padding:10px 14px;background:rgba(126,231,135,.08);border:1px solid var(--acc);color:var(--acc);font-family:var(--mono);font-size:12px;line-height:1.6}

/* research */
.sy-res-grid{display:grid;grid-template-columns:.9fr 1.1fr;gap:44px;align-items:start}
.sy-res-sticky{position:sticky;top:90px;border:1px solid var(--line);background:#0b1017;padding:18px}
.sy-res-cap{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:10px}
.sy-res-p{color:var(--mut);font-size:15px;line-height:1.75;margin-bottom:26px;max-width:60ch}
.sy-res-p b{color:var(--txt)}
.sy-res-rows{display:flex;flex-direction:column;border-top:1px solid var(--line)}
.sy-res-row{display:grid;grid-template-columns:86px 1fr;gap:16px;padding:16px 0;border-bottom:1px solid var(--line)}
.sy-res-k{font-family:var(--mono);font-size:11px;color:var(--acc);letter-spacing:.1em}
.sy-res-row p{color:var(--mut);font-size:14px;line-height:1.65}
.sy-res-cite{margin-top:20px;font-family:var(--mono);font-size:11.5px;color:var(--mut);border-left:2px solid var(--acc);padding-left:14px;line-height:1.7}

/* roadmap */
.sy-road{border-top:1px solid var(--line)}
.sy-road-row{display:grid;grid-template-columns:110px 240px 1fr;gap:20px;padding:22px 6px;border-bottom:1px solid var(--line);align-items:start;transition:background .15s}
.sy-road-row:hover{background:rgba(126,231,135,.03)}
.sy-road-range{font-family:var(--mono);font-size:13px;color:var(--mut)}
.sy-road-name{font-family:var(--disp);font-weight:700;font-size:17px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sy-road-tag{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;padding:3px 9px}
.sy-tag-done{color:var(--acc);border:1px solid rgba(126,231,135,.45)}
.sy-tag-current{color:var(--ink);background:var(--acc)}
.sy-tag-next{color:var(--cyn);border:1px solid rgba(88,196,220,.45)}
.sy-tag-future{color:var(--mut);border:1px solid var(--line)}
.sy-road-items{display:flex;gap:8px;flex-wrap:wrap}
.sy-road-items span{font-family:var(--mono);font-size:11px;color:var(--mut);border:1px solid var(--line);padding:5px 10px}
.sy-road-done .sy-road-range{color:var(--acc)}
.sy-road-current{background:rgba(126,231,135,.05)}

/* footer */
.sy-foot{display:flex;justify-content:space-between;gap:24px;align-items:center;padding:30px 22px;max-width:1280px;margin:0 auto;flex-wrap:wrap}
.sy-foot-l{display:flex;gap:12px;align-items:center}
.sy-foot-sub{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:4px}
.sy-foot-r{display:flex;gap:22px;font-family:var(--mono);font-size:11.5px;color:var(--mut);flex-wrap:wrap}
.sy-foot-mono{color:var(--acc)}

/* responsive */
@media(max-width:1000px){
  .sy-open{grid-template-columns:1fr}
  .sy-control-grid{grid-template-columns:1fr}
  .sy-pipe{grid-template-columns:1fr}
  .sy-pipe-list{border-right:0;border-bottom:1px solid var(--line)}
  .sy-console{grid-template-columns:1fr}
  .sy-clist{border-right:0;border-bottom:1px solid var(--line)}
  .sy-res-grid{grid-template-columns:1fr}
  .sy-res-sticky{position:static}
  .sy-road-row{grid-template-columns:70px 1fr}
  .sy-road-items{grid-column:1/-1}
  .hide-s{display:none}
  .sy-links{display:none}
}
@media(prefers-reduced-motion:reduce){
  .sy-ticker-track{animation:none}
  .sy-live,.sy-caret{animation:none}
  html{scroll-behavior:auto}
}
`;
