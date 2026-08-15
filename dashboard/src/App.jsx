import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";

/* ================================================================
   SecurePy AI — Security Operations Console
   Phase 10 Web Dashboard
   ================================================================ */

const ACCENT = "#7ee787";
const AMBER  = "#d29922";
const RED    = "#f85149";
const CYAN   = "#58c4dc";
const INK    = "#0a0e14";
const LINE   = "rgba(140,160,180,0.16)";
const MUT    = "#8b98a5";

const MONO = "'IBM Plex Mono', ui-monospace, monospace";
const DISP = "'Space Grotesk', sans-serif";
const BODY = "'IBM Plex Sans', system-ui, sans-serif";

/* ---- data ---- */
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

const FINDINGS = [
  {
    id: "SP-001", sev: "CRITICAL", cwe: "CWE-89", title: "SQL Injection", file: "app.py", line: 24,
    conf: 0.93, status: "VALIDATED", rule: "SEC102",
    flow: "request.args['username'] → f-string → db.execute()",
    before: ["def get_user_profile():", "    username = request.args.get(\"username\")", "    query = f\"SELECT * FROM users WHERE username = '{username}'\"", "    return db.execute(query).fetchone()"],
    after:  ["def get_user_profile():", "    username = request.args.get(\"username\")", "    # fix: parameterized query (CWE-89)", "    query = \"SELECT * FROM users WHERE username = ?\"", "    return db.execute(query, (username,)).fetchone()"],
    diff: [
      { t: "ctx", x: "def get_user_profile():" },
      { t: "ctx", x: "    username = request.args.get(\"username\")" },
      { t: "del", x: "    query = f\"SELECT * FROM users WHERE username = '{username}'\"" },
      { t: "add", x: "    query = \"SELECT * FROM users WHERE username = ?\"" },
      { t: "add", x: "    return db.execute(query, (username,)).fetchone()" },
      { t: "del", x: "    return db.execute(query).fetchone()" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","pass"],["Vulnerability re-scan","pass"],["No new vulnerabilities","pass"],["Unit tests","pass"]],
  },
  {
    id: "SP-002", sev: "HIGH", cwe: "CWE-798", title: "Hardcoded API Key", file: "utils/auth.py", line: 12,
    conf: 0.86, status: "VALIDATED", rule: "SEC101",
    flow: "literal secret → module API_KEY → outbound request",
    before: ["API_KEY = \"AKIA923848239482394\""],
    after:  ["import os", "# fix: secret from environment (CWE-798)", "API_KEY = os.environ.get(\"API_KEY\")"],
    diff: [
      { t: "del", x: "API_KEY = \"AKIA923848239482394\"" },
      { t: "add", x: "import os" },
      { t: "add", x: "API_KEY = os.environ.get(\"API_KEY\")" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","pass"],["Vulnerability re-scan","pass"],["No new vulnerabilities","pass"],["Unit tests","pass"]],
  },
  {
    id: "SP-003", sev: "MEDIUM", cwe: "CWE-78", title: "Command Injection", file: "scripts/run.py", line: 18,
    conf: 0.74, status: "REVIEW", rule: "SEC103",
    flow: "host (untrusted) → concat → os.system(shell)",
    before: ["def ping_host(host):", "    os.system(\"ping -c 1 \" + host)"],
    after:  ["import subprocess", "def ping_host(host):", "    # fix: arg list, no shell (CWE-78)", "    subprocess.run([\"ping\", \"-c\", \"1\", host], check=True)"],
    diff: [
      { t: "add", x: "import subprocess" },
      { t: "ctx", x: "def ping_host(host):" },
      { t: "del", x: "    os.system(\"ping -c 1 \" + host)" },
      { t: "add", x: "    subprocess.run([\"ping\", \"-c\", \"1\", host], check=True)" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","pass"],["Vulnerability re-scan","pass"],["No new vulnerabilities","pass"],["Unit tests","warn"]],
  },
  {
    id: "SP-004", sev: "HIGH", cwe: "CWE-502", title: "Insecure Deserialization", file: "core/loader.py", line: 31,
    conf: 0.48, status: "REJECTED", rule: "SEC104",
    flow: "user_blob → pickle.loads() → object graph",
    before: ["def load_session(user_blob):", "    return pickle.loads(user_blob)"],
    after:  ["import json", "def load_session(user_blob):", "    # fix: safe format (CWE-502)", "    return json.loads(user_blob)"],
    diff: [
      { t: "add", x: "import json" },
      { t: "ctx", x: "def load_session(user_blob):" },
      { t: "del", x: "    return pickle.loads(user_blob)" },
      { t: "add", x: "    return json.loads(user_blob)" },
    ],
    checks: [["Syntax validation","pass"],["AST logic preservation","warn"],["Vulnerability re-scan","pass"],["No new vulnerabilities","warn"],["Unit tests","fail"]],
  },
];

const ROADMAP = [
  { range: "01–08", name: "Core engine",       status: "done",    items: ["AST scanner","5 CWE rules","Context extraction","Local LLM","Prompt builder","Patch validator","Reports","CI policies"] },
  { range: "09",    name: "CI/CD integration", status: "current", items: ["GitHub Action","PR comments","SARIF upload","Baseline + diff-only"] },
  { range: "10–12", name: "Evidence",          status: "next",    items: ["Dashboard","SecurePy-VulnBench","Thesis + paper"] },
  { range: "13–16", name: "Product depth",     status: "future",  items: ["Test generation","Deep taint","Patch explanations","Repo memory / RAG"] },
  { range: "17–20", name: "Intelligence",      status: "future",  items: ["Exploit verification","Repair agent","SCA / IaC / secrets","Risk + compliance"] },
  { range: "21–24", name: "Autonomous",        status: "future",  items: ["IDE plugins","Multi-language","Enterprise","Self-healing SDLC"] },
];

const TERM_LINES = [
  ["$", "securepy-ai scan ./examples/flask_app --fix --model codellama:13b"],
  ["·", "ingest    24 python files collected"],
  ["·", "ast       parsing syntax trees …"],
  ["!", "SEC102  CWE-89   app.py:24        CRITICAL"],
  ["!", "SEC101  CWE-798  utils/auth.py:12 HIGH"],
  ["!", "SEC103  CWE-78   scripts/run.py:18 MEDIUM"],
  ["!", "SEC104  CWE-502  core/loader.py:31 HIGH"],
  ["·", "context   function scope + data-flow extracted"],
  ["·", "llm       generating patches (local, offline) …"],
  ["✓", "SP-001  patch valid   conf 0.93  → AUTO"],
  ["✓", "SP-002  patch valid   conf 0.86  → AUTO"],
  ["~", "SP-003  patch review  conf 0.74  → REVIEW"],
  ["✕", "SP-004  patch reject  conf 0.48  → MANUAL"],
  ["·", "report    sarif + json + html written to reports/"],
  ["$", "exit 1 — 2 blocking findings on threshold=high"],
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
function Terminal() {
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
    }, 260);
    return () => clearInterval(id);
  }, [run, prm]);
  const done = count >= TERM_LINES.length;
  return (
    <div className="sy-term">
      <div className="sy-term-bar">
        <span className="sy-dot" style={{ background: RED }} />
        <span className="sy-dot" style={{ background: AMBER }} />
        <span className="sy-dot" style={{ background: ACCENT }} />
        <span className="sy-term-title">sagar@nfsu — securepy-ai — 80×24</span>
        <button className="sy-term-rerun" onClick={() => setRun((r) => r + 1)}>↻ re-run</button>
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

/* AST tree (deterministic procedural SVG) */
function ASTTree() {
  const prm = usePRM();
  const { segs, alerts } = useMemo(() => {
    const segs = []; const alerts = [];
    let seed = 7;
    const rnd = () => (seed = (seed * 9301 + 49297) % 233280) / 233280;
    const grow = (x, y, ang, len, depth) => {
      if (depth <= 0 || len < 6) {
        if (rnd() < 0.5) alerts.push({ x, y, k: rnd() < 0.3 ? "red" : "amber" });
        return;
      }
      const x2 = x + Math.cos(ang) * len;
      const y2 = y + Math.sin(ang) * len;
      segs.push({ x1: x, y1: y, x2, y2, depth });
      grow(x2, y2, ang - 0.5 + rnd() * 0.3, len * 0.72, depth - 1);
      grow(x2, y2, ang + 0.5 - rnd() * 0.3, len * 0.72, depth - 1);
    };
    grow(200, 300, -Math.PI / 2, 62, 6);
    return { segs, alerts };
  }, []);
  return (
    <svg viewBox="0 0 400 320" className="sy-ast" aria-hidden="true" role="img" aria-label="Abstract Syntax Tree visualization with flagged vulnerability nodes">
      {segs.map((s, i) => (
        <line key={i} x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2}
          stroke={ACCENT} strokeOpacity={0.25 + s.depth * 0.09} strokeWidth={s.depth > 4 ? 1.6 : 0.8}
          className={prm ? "" : "sy-ast-line"} style={prm ? {} : { animationDelay: `${i * 14}ms` }} />
      ))}
      {alerts.map((a, i) => (
        <circle key={i} cx={a.x} cy={a.y} r={3} fill={a.k === "red" ? RED : AMBER} className={prm ? "" : "sy-ast-node"} />
      ))}
    </svg>
  );
}

/* logo mark (inline SVG — no external image needed) */
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

/* ---- App ---- */
export default function App() {
  const prm  = usePRM();
  const [step,   setStep]   = useState(0);
  const [sel,    setSel]    = useState(0);
  const [mode,   setMode]   = useState("diff");
  const [filter, setFilter] = useState("ALL");
  const f = FINDINGS[sel];

  const shown = FINDINGS.filter((x) => filter === "ALL" || x.sev === filter);

  return (
    <div className="sy-root">
      <style>{CSS}</style>

      {/* ── status bar ── */}
      <div className="sy-status" role="status" aria-label="System status">
        <span className="sy-status-item"><span className="sy-live" aria-hidden="true" />ollama · connected</span>
        <span className="sy-status-item">model <b>codellama:13b</b></span>
        <span className="sy-status-item hide-s">build <b>v1.0.0</b></span>
        <span className="sy-status-item hide-s">phase <b>9 / 24</b></span>
        <span className="sy-status-item sy-right">local · code never leaves host</span>
      </div>

      {/* ── nav ── */}
      <header className="sy-nav">
        <a className="sy-brand" href="#top" aria-label="SecurePy AI home">
          <Logo />
          <span className="sy-word">SecurePy<span className="sy-word-ai">_AI</span></span>
        </a>
        <nav className="sy-links" aria-label="Page sections">
          <a href="#pipeline">pipeline</a>
          <a href="#console">console</a>
          <a href="#research">research</a>
          <a href="#roadmap">roadmap</a>
        </nav>
        <a className="sy-cta" href="#console" aria-label="Jump to live scan console">run_scan --fix</a>
      </header>

      {/* ── hero: editorial + live terminal ── */}
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
            LLM, validates every patch against a security oracle — and gates your CI on confidence,
            not noise.
          </p>
          <div className="sy-open-meta" role="list" aria-label="Feature highlights">
            <span className="sy-chip" role="listitem">9 phases shipped</span>
            <span className="sy-chip" role="listitem">5 CWE engines</span>
            <span className="sy-chip" role="listitem">3 report formats</span>
            <span className="sy-chip sy-chip-g" role="listitem">privacy-first</span>
          </div>
        </div>
        <div className="sy-open-right">
          <Terminal />
          <div className="sy-open-strip" aria-label="Scan statistics">
            <div><CountUp to={24} /> <i>files</i></div>
            <div><CountUp to={4} /> <i>findings</i></div>
            <div><CountUp to={4} /> <i>patches</i></div>
            <div><CountUp to={2} /> <i>validated</i></div>
            <div><CountUp to={93} suffix="%" /> <i>top conf.</i></div>
          </div>
        </div>
      </section>

      {/* ── CWE ticker ── */}
      <div className="sy-ticker" aria-hidden="true">
        <div className="sy-ticker-track">
          {[...TICKER, ...TICKER].map((t, i) => (
            <span key={i} className="sy-ticker-item">{t}<span className="sy-ticker-sep">/</span></span>
          ))}
        </div>
      </div>

      {/* ── pipeline ── */}
      <section className="sy-sec" id="pipeline" aria-labelledby="pipeline-heading">
        <SectionHead index="01" label="DETECTION → REMEDIATION PIPELINE" title="Eight stages. One verified patch." />
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

      {/* ── findings workbench ── */}
      <section className="sy-sec" id="console" aria-labelledby="console-heading">
        <SectionHead index="02" label="REMEDIATION WORKBENCH" title="Every finding ships with a validated fix." />
        <div className="sy-filters" role="group" aria-label="Filter by severity">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((s) => (
            <button key={s}
              className={"sy-fbtn" + (filter === s ? " on" : "")}
              onClick={() => setFilter(s)}
              aria-pressed={filter === s}
              id={`filter-${s.toLowerCase()}`}>
              {s}
            </button>
          ))}
        </div>

        <div className="sy-console">
          <div className="sy-clist" role="listbox" aria-label="Security findings">
            {shown.map((x) => {
              const real = FINDINGS.indexOf(x);
              return (
                <button key={x.id}
                  className={"sy-crow" + (sel === real ? " on" : "")}
                  onClick={() => setSel(real)}
                  role="option"
                  aria-selected={sel === real}
                  id={`finding-${x.id.toLowerCase()}`}>
                  <span className={"sy-sev sy-sev-" + x.sev.toLowerCase()}>{x.sev}</span>
                  <span className="sy-crow-main">
                    <b>{x.title}</b>
                    <i>{x.file}:{x.line} · {x.cwe}</i>
                  </span>
                  <span className="sy-conf">{Math.round(x.conf * 100)}%</span>
                </button>
              );
            })}
          </div>

          <div className="sy-cdetail" aria-live="polite" aria-label="Finding details">
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
              <span className={"sy-cd-status sy-st-" + f.status.toLowerCase()}>{f.status}</span>
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
          </div>
        </div>
      </section>

      {/* ── research: sticky two-column ── */}
      <section className="sy-sec sy-research" id="research" aria-labelledby="research-heading">
        <div className="sy-res-grid">
          <div className="sy-res-sticky">
            {/* IMAGE SLOT A — real AST diagram photo */}
            <img
              src="/images/ast-diagram.jpg"
              alt="Abstract Syntax Tree with flagged vulnerability sinks (SQL SINK, CMD SINK, EXEC SINK highlighted in red)"
              style={{ width: '100%', display: 'block', borderRadius: 0 }}
              loading="lazy"
            />
            <div className="sy-res-cap">fig. 01 — abstract syntax tree with flagged sinks</div>
          </div>
          <div className="sy-res-body">
            <SectionHead index="03" label="RESEARCH POSITION" title="Beyond detection-only SAST." />
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

      {/* ── roadmap ── */}
      <section className="sy-sec" id="roadmap" aria-labelledby="roadmap-heading">
        <SectionHead index="04" label="EVOLUTION · 24 PHASES" title="From thesis tool to autonomous AppSec engineer." />
        <div className="sy-road" role="list">
          {ROADMAP.map((r) => (
            <div key={r.range} className={"sy-road-row sy-road-" + r.status} role="listitem">
              <div className="sy-road-range">{r.range}</div>
              <div className="sy-road-name">
                {r.name}
                <span className={"sy-road-tag sy-tag-" + r.status}>
                  {r.status === "done" ? "SHIPPED" : r.status === "current" ? "IN CI" : r.status === "next" ? "NEXT" : "PLANNED"}
                </span>
              </div>
              <div className="sy-road-items">{r.items.map((it) => <span key={it}>{it}</span>)}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── stats band ── */}
      <section className="sy-band" aria-label="Key metrics">
        <div><b><CountUp to={9} /></b><i>phases shipped</i></div>
        <div><b><CountUp to={5} /></b><i>detection engines</i></div>
        <div><b><CountUp to={5} /></b><i>validation layers</i></div>
        <div><b><CountUp to={3} /></b><i>report formats</i></div>
        <div><b><CountUp to={93} suffix="%" /></b><i>peak confidence</i></div>
        <div><b><CountUp to={24} /></b><i>phase horizon</i></div>
      </section>

      <footer className="sy-foot">
        <div className="sy-foot-l">
          {/* IMAGE SLOT B — real logo photo */}
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

      {/* scanline / noise overlay */}
      <div className="sy-noise" aria-hidden="true" />
    </div>
  );
}

/* ========== CSS ========== */
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
.sy-live{width:7px;height:7px;border-radius:50%;background:var(--acc);box-shadow:0 0 8px var(--acc);animation:sypulse 1.8s infinite}
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
.sy-clist{border-right:1px solid var(--line)}
.sy-crow{display:grid;grid-template-columns:78px 1fr 48px;gap:12px;align-items:center;width:100%;text-align:left;
  padding:15px 14px;background:none;border:0;border-bottom:1px solid var(--line);cursor:pointer;color:var(--txt)}
.sy-crow:last-child{border-bottom:0}
.sy-crow:hover{background:rgba(126,231,135,.04)}
.sy-crow.on{background:rgba(126,231,135,.08);box-shadow:inset 2px 0 0 var(--acc)}
.sy-sev{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-align:center;padding:4px 0}
.sy-sev-critical{color:var(--red);border:1px solid rgba(248,81,73,.5)}
.sy-sev-high{color:var(--amb);border:1px solid rgba(210,153,34,.5)}
.sy-sev-medium{color:var(--cyn);border:1px solid rgba(88,196,220,.5)}
.sy-crow-main b{display:block;font-size:13.5px;font-weight:600}
.sy-crow-main i{display:block;font-style:normal;font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:3px}
.sy-conf{font-family:var(--mono);font-size:12px;color:var(--acc);text-align:right}
.sy-cdetail{padding:22px 24px}
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
.sy-st-rejected{color:var(--red);border:1px solid rgba(248,81,73,.45)}
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

/* research */
.sy-res-grid{display:grid;grid-template-columns:.9fr 1.1fr;gap:44px;align-items:start}
.sy-res-sticky{position:sticky;top:90px;border:1px solid var(--line);background:#0b1017;padding:18px}
.sy-ast{width:100%;display:block}
.sy-ast-line{stroke-dasharray:120;stroke-dashoffset:120;animation:sydraw 1.2s ease forwards}
@keyframes sydraw{to{stroke-dashoffset:0}}
.sy-ast-node{animation:sypulse 2.2s infinite}
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

/* stats band */
.sy-band{display:grid;grid-template-columns:repeat(6,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#0b1017}
.sy-band>div{padding:30px 10px;text-align:center;border-right:1px solid var(--line)}
.sy-band>div:last-child{border-right:0}
.sy-band b{font-family:var(--disp);font-weight:700;font-size:34px;color:var(--acc);display:block}
.sy-band i{font-style:normal;font-family:var(--mono);font-size:10px;letter-spacing:.16em;color:var(--mut);text-transform:uppercase}

/* footer */
.sy-foot{display:flex;justify-content:space-between;gap:24px;align-items:center;padding:30px 22px;max-width:1280px;margin:0 auto;flex-wrap:wrap}
.sy-foot-l{display:flex;gap:12px;align-items:center}
.sy-foot-sub{font-family:var(--mono);font-size:11px;color:var(--mut);margin-top:4px}
.sy-foot-r{display:flex;gap:22px;font-family:var(--mono);font-size:11.5px;color:var(--mut);flex-wrap:wrap}
.sy-foot-mono{color:var(--acc)}

/* responsive */
@media(max-width:1000px){
  .sy-open{grid-template-columns:1fr}
  .sy-pipe{grid-template-columns:1fr}
  .sy-pipe-list{border-right:0;border-bottom:1px solid var(--line)}
  .sy-console{grid-template-columns:1fr}
  .sy-clist{border-right:0;border-bottom:1px solid var(--line)}
  .sy-res-grid{grid-template-columns:1fr}
  .sy-res-sticky{position:static}
  .sy-band{grid-template-columns:repeat(3,1fr)}
  .sy-band>div{border-bottom:1px solid var(--line)}
  .sy-road-row{grid-template-columns:70px 1fr}
  .sy-road-items{grid-column:1/-1}
  .hide-s{display:none}
  .sy-links{display:none}
}
@media(prefers-reduced-motion:reduce){
  .sy-ticker-track{animation:none}
  .sy-live,.sy-caret,.sy-ast-node{animation:none}
  .sy-ast-line{animation:none;stroke-dashoffset:0}
  html{scroll-behavior:auto}
}
`;
