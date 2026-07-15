import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../ui";
import { TOOLS, useToolStates, toolActions, installedCount } from "../tools";
import { activeOperatorCount, useOperators } from "../stores";
import { api, LlmStatus } from "../api";

function Metric({ icon, tag, label, value, color, bar, w }: any) {
  return (
    <div className={"md:col-span-3 glass-card p-md rounded-xl border-t-2 relative overflow-hidden group " + color.border}>
      {tag === "Active" && <div className="scanline" />}
      <div className="flex justify-between items-start mb-md">
        <Icon name={icon} className={color.text} />
        <span className="text-body-sm text-on-surface-variant font-mono-label">{tag}</span>
      </div>
      <h3 className="text-on-surface-variant text-body-sm font-mono-label uppercase mb-1">{label}</h3>
      <div className={"text-display-lg font-display-lg group-hover:scale-105 transition-transform duration-500 " + color.text}>{value}</div>
      <div className="mt-4 h-1 w-full bg-surface-variant rounded-full overflow-hidden"><div className={"h-full " + bar} style={{ width: w }} /></div>
    </div>
  );
}

interface Sev { critical: number; high: number; medium: number; low: number; info: number; total: number }
const ZERO: Sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

// Real event feed across all engagements (replaces the old random fake log terminal).
function Terminal({ lines }: { lines: string[] }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [lines]);
  return (
    <div className="md:col-span-7 glass-card rounded-xl overflow-hidden flex flex-col border border-outline-variant/20 h-[400px]">
      <div className="bg-surface-container-high px-md py-2 flex items-center justify-between border-b border-outline-variant/30">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-error/50" /><div className="w-2.5 h-2.5 rounded-full bg-tertiary/50" /><div className="w-2.5 h-2.5 rounded-full bg-secondary-container/50" /></div>
          <span className="ml-4 font-mono-label text-[11px] text-on-surface-variant/70 uppercase">root@hexacore:~/logs/command_feed</span>
        </div>
        <Icon name="terminal" className="text-on-surface-variant text-sm" />
      </div>
      <div ref={box} className="p-md font-code-block text-code-block text-primary/80 overflow-y-auto flex flex-col gap-1 h-full bg-surface-container-lowest">
        {lines.length === 0
          ? <p className="text-on-surface-variant/40">awaiting scan activity…</p>
          : lines.map((l, i) => <p key={i} className={l.includes("scope.denied") || l.includes("run.error") ? "text-error font-bold terminal-glow" : ""}>{l}</p>)}
      </div>
    </div>
  );
}

function Arsenal() {
  const states = useToolStates();
  const pct = Math.round((installedCount(states) / TOOLS.length) * 100);
  return (
    <div className="md:col-span-12 glass-card rounded-xl overflow-hidden">
      <div className="p-md border-b border-outline-variant/20 flex justify-between items-center">
        <div className="flex items-center gap-2"><Icon name="inventory_2" className="text-secondary-fixed" /><h3 className="font-mono-label text-mono-label text-on-surface uppercase">Tool Arsenal</h3></div>
        <div className="flex items-center gap-3 font-mono-label text-mono-label">
          <span className="text-on-surface-variant uppercase">Installed</span><span className="text-primary">{installedCount(states)}/{TOOLS.length}</span>
          <Link to="/tools" className="text-primary/70 hover:text-primary flex items-center gap-1">Library<Icon name="chevron_right" className="text-sm" /></Link>
        </div>
      </div>
      <div className="px-md pt-3"><div className="h-1 w-full bg-surface-variant rounded-full overflow-hidden"><div className="h-full bg-secondary-container transition-all duration-500" style={{ width: pct + "%" }} /></div></div>
      <div className="p-md grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-8 max-h-[420px] overflow-y-auto">
        {TOOLS.map((t) => {
          const st = states[t.id]; const on = st.status === "installed"; const busy = st.status === "installing" || st.status === "updating";
          return (
            <div key={t.id} className="flex items-center justify-between py-2 border-b border-outline-variant/10">
              <div className="flex items-center gap-3 min-w-0">
                <Icon name={t.icon} className={"text-lg " + (on ? "text-secondary-fixed" : "text-on-surface-variant/40")} />
                <div className="min-w-0"><p className="text-body-sm text-on-surface truncate">{t.name}</p><p className="font-mono-label text-[10px] text-on-surface-variant/50 truncate">{t.bin} • {t.cat}</p></div>
              </div>
              {busy ? <span className="shrink-0 font-mono-label text-[11px] text-primary animate-pulse">{st.status === "installing" ? "INSTALLING…" : "UPDATING…"}</span>
                : on ? <button onClick={() => toolActions.uninstall(t.id)} className="shrink-0 text-secondary-fixed hover:text-error font-mono-label text-[11px] flex items-center gap-1 transition-colors"><Icon name="check_circle" className="text-base" />INSTALLED</button>
                : <button onClick={() => toolActions.install(t.id)} className="shrink-0 bg-primary/10 text-primary hover:bg-primary hover:text-on-primary font-mono-label text-[11px] px-3 py-1 rounded-lg transition-all active:scale-95">INSTALL</button>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Real severity donut. Each segment length is proportional to its real count.
function SeverityDonut({ sev }: { sev: Sev }) {
  const C = 251.2; // 2πr, r=40
  const segs: [keyof Sev, string, string][] = [
    ["critical", "#ffb4ab", "Critical"],
    ["high", "#4fdbc8", "High"],
    ["medium", "#ffb95f", "Medium"],
    ["low", "#adc6ff", "Low"],
    ["info", "#8a9199", "Info"],
  ];
  let offset = 0;
  return (
    <div className="md:col-span-5 glass-card p-lg rounded-xl flex flex-col justify-center items-center min-h-[400px]">
      <h3 className="font-mono-label text-mono-label text-on-surface-variant uppercase self-start mb-lg">Severity Distribution</h3>
      <div className="relative w-64 h-64 flex items-center justify-center">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle className="opacity-20" cx="50" cy="50" r="40" fill="transparent" stroke="#8a9199" strokeWidth="12" />
          {sev.total > 0 && segs.map(([k, color]) => {
            const len = ((sev[k] as number) / sev.total) * C;
            const el = <circle key={k} cx="50" cy="50" r="40" fill="transparent" stroke={color} strokeWidth="12" strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset} />;
            offset += len;
            return el;
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center"><span className="font-headline-lg text-headline-lg text-on-surface">{sev.total}</span><span className="font-mono-label text-mono-label text-on-surface-variant">TOTAL</span></div>
      </div>
      <div className="grid grid-cols-2 gap-x-8 gap-y-2 mt-lg w-full">
        {segs.map(([k, color, label]) => (
          <div key={k} className="flex items-center gap-2"><span className="w-3 h-3 rounded-full" style={{ background: color }} /><span className="text-body-sm font-mono-label">{label}: {sev[k] as number}</span></div>
        ))}
      </div>
    </div>
  );
}

// Local-LLM (Ollama) health, live on the dashboard header.
function LlmPill({ llm }: { llm: LlmStatus | null }) {
  let color = "#8996a5", label = "LLM …", pulse = false;
  if (llm) {
    if (!llm.enabled) { color = "#8996a5"; label = "LLM off"; }
    else if (llm.reachable && llm.model_ready) { color = "#46d39a"; label = `LLM · ${llm.model}`; pulse = true; }
    else if (llm.reachable) { color = "#f2b34d"; label = "LLM · model not pulled"; }
    else { color = "#ff7d7d"; label = "LLM · Ollama down"; }
  }
  return (
    <div title={llm?.detail || "checking local LLM…"}
      className="px-3 py-1 bg-surface-container-high border border-outline-variant/30 rounded text-body-sm flex items-center gap-2 font-mono-label text-[11px] uppercase">
      <Icon name="smart_toy" className="text-sm" style={{ color }} />
      <span className={"w-2 h-2 rounded-full " + (pulse ? "animate-pulse" : "")} style={{ background: color }} />
      {label}
    </div>
  );
}

export default function HexacoreDashboard() {
  const ops = useOperators();
  const [stats, setStats] = useState({ engagements: 0, approvals: 0, loaded: false });
  const [sev, setSev] = useState<Sev>(ZERO);
  const [feed, setFeed] = useState<string[]>([]);
  const [llm, setLlm] = useState<LlmStatus | null>(null);

  const load = async () => {
    api.llmStatus().then(setLlm).catch(() => setLlm(null));
    try {
      const engs = await api.listEngagements();
      let approvals = 0;
      const agg = { ...ZERO };
      const lines: string[] = [];
      for (const e of engs) {
        const gs = await api.approvals(e.id).catch(() => []);
        approvals += (gs as any[]).length;
        const res = await api.findings(e.id).catch(() => ({ findings: [], counts: null }));
        if (res.counts) for (const k of Object.keys(agg) as (keyof Sev)[]) agg[k] += (res.counts as any)[k] ?? 0;
        const evs = await api.events(e.id).catch(() => ({ events: [] }));
        for (const ev of res.counts ? evs.events.slice(-8) : []) lines.push(`[${e.name}] ${ev.type} — ${ev.detail}`);
      }
      setStats({ engagements: engs.length, approvals, loaded: true });
      setSev(agg);
      setFeed(lines.slice(-20));
    } catch { setStats((s) => ({ ...s, loaded: true })); }
  };

  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, []);

  return (
    <>
      <div className="mb-lg flex flex-col md:flex-row md:items-end justify-between gap-md">
        <div className="min-w-0 md:flex-1">
          <p className="font-mono-label text-mono-label text-primary uppercase tracking-widest mb-1">System Status: Operational</p>
          <h2 className="font-headline-lg text-headline-lg text-on-surface">Dashboard Overview</h2>
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <LlmPill llm={llm} />
          <div className="px-3 py-1 bg-surface-container-high border border-outline-variant/30 rounded text-body-sm flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-secondary-container animate-pulse" /> Live Data Stream</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-gutter">
        <Metric icon="precision_manufacturing" tag="Active" label="Active Engagements" value={stats.loaded ? stats.engagements : "—"} w="40%" color={{ border: "border-t-secondary-container", text: "text-secondary-fixed" }} bar="bg-secondary-container" />
        <Metric icon="verified_user" tag="Pending" label="Pending Approvals" value={stats.loaded ? stats.approvals : "—"} w="50%" color={{ border: "border-t-tertiary", text: "text-tertiary" }} bar="bg-tertiary-container" />
        <Metric icon="report_problem" tag="Total" label="Vulnerabilities" value={stats.loaded ? sev.total : "—"} w="80%" color={{ border: "border-t-error", text: "text-error" }} bar="bg-error-container" />
        <Link to="/operators" className="md:col-span-3 glass-card p-md rounded-xl border-t-2 border-t-primary relative overflow-hidden group block hover:border-primary/40 transition-all">
          <div className="flex justify-between items-start mb-md"><Icon name="groups" className="text-primary" /><Icon name="chevron_right" className="text-on-surface-variant/50 text-base" /></div>
          <h3 className="text-on-surface-variant text-body-sm font-mono-label uppercase mb-1">Active Operators</h3>
          <div className="text-display-lg font-display-lg text-primary group-hover:scale-105 transition-transform duration-500">{activeOperatorCount()}</div>
          <div className="mt-4 flex -space-x-2">
            {ops.filter((o) => o.status === "online").slice(0, 4).map((o) => (
              <div key={o.id} className="w-6 h-6 rounded-full border border-background bg-surface-container-high flex items-center justify-center font-mono-label text-[9px] text-on-surface-variant">{o.name.split(" ").map((n) => n[0]).join("")}</div>
            ))}
          </div>
        </Link>

        <SeverityDonut sev={sev} />
        <Terminal lines={feed} />
        <Arsenal />
      </div>
    </>
  );
}
