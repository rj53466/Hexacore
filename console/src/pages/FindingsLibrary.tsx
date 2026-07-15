import { useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { Icon } from "../ui";
import { api, ApiFinding } from "../api";

type Sev = "critical" | "high" | "medium" | "low" | "info";
const SEVS: Sev[] = ["critical", "high", "medium", "low", "info"];
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEV_STYLE: Record<Sev, string> = {
  critical: "bg-error/20 text-error border-error/30",
  high: "bg-tertiary/20 text-tertiary border-tertiary/30",
  medium: "bg-primary/20 text-primary border-primary/30",
  low: "bg-secondary/20 text-secondary border-secondary/30",
  info: "bg-surface-container-high text-on-surface-variant border-outline-variant/30",
};

// A real finding, tagged with the engagement it came from.
interface Row extends ApiFinding { engagement: string; engagementId: string }

export default function FindingsLibrary() {
  const [rowsAll, setRowsAll] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [advOpen, setAdvOpen] = useState(false);
  const [fSev, setFSev] = useState<Set<string>>(new Set());
  const [fTool, setFTool] = useState<Set<string>>(new Set());

  const load = async () => {
    setLoading(true);
    setErr(null);
    try {
      const engs = await api.listEngagements();
      const all: Row[] = [];
      for (const e of engs) {
        const res = await api.findings(e.id).catch(() => ({ findings: [] as ApiFinding[], counts: null }));
        for (const f of res.findings) all.push({ ...f, engagement: e.name, engagementId: e.id });
      }
      all.sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0));
      setRowsAll(all);
    } catch (e) {
      setErr(String(e).replace("Error: ", ""));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const tools = useMemo(() => [...new Set(rowsAll.map((f) => f.source))], [rowsAll]);

  const toggle = <T,>(set: Dispatch<SetStateAction<Set<T>>>, v: T) =>
    set((s) => { const n = new Set(s); n.has(v) ? n.delete(v) : n.add(v); return n; });

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return rowsAll.filter((f) =>
      (!query || [f.title, ...(f.cve || []), f.cwe || "", f.affected_asset, f.source, f.description, f.engagement].join(" ").toLowerCase().includes(query)) &&
      (fSev.size === 0 || fSev.has(f.severity)) &&
      (fTool.size === 0 || fTool.has(f.source)));
  }, [rowsAll, q, fSev, fTool]);

  const activeFilters = fSev.size + fTool.size;
  const clearAll = () => { setFSev(new Set()); setFTool(new Set()); setQ(""); };
  const chip = (active: boolean) => "px-2.5 py-1 rounded-full font-mono-label text-[11px] cursor-pointer transition-all border " +
    (active ? "bg-primary/20 text-primary border-primary/40" : "bg-surface-container-low text-on-surface-variant border-outline-variant/30 hover:border-outline");

  return (
    <>
      <div className="flex items-end justify-between mb-lg">
        <div className="min-w-0 flex-1"><h2 className="text-headline-lg font-headline-lg text-on-surface">Findings</h2><p className="text-body-sm text-on-surface-variant">Real findings across all engagements.</p></div>
        <button onClick={load} className="text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1 font-mono-label text-mono-label"><Icon name="refresh" className="text-base" />REFRESH</button>
      </div>

      <div className="glass-panel p-4 rounded-xl mb-6 border border-outline-variant/20 flex flex-col gap-3 shadow-xl">
        <div className="flex flex-col md:flex-row gap-3 items-center">
          <div className="relative w-full md:flex-grow group">
            <Icon name="search" className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant group-focus-within:text-primary" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, CVE, CWE, target, tool…"
              className="w-full bg-surface-container-lowest border border-outline-variant/40 rounded-lg py-2.5 pl-10 pr-4 text-on-surface focus:outline-none focus:ring-1 focus:ring-primary transition-all" />
          </div>
          <button onClick={() => setAdvOpen((o) => !o)} className={"flex items-center gap-2 rounded-lg py-2.5 px-4 text-body-sm transition-all border " + (advOpen || activeFilters ? "bg-primary/10 text-primary border-primary/40" : "bg-surface-container-high border-outline-variant/40 hover:text-primary")}>
            <Icon name="filter_alt" className="text-sm" />Filters{activeFilters > 0 && <span className="bg-primary text-on-primary rounded-full px-1.5 text-[10px] font-bold">{activeFilters}</span>}
          </button>
          {(activeFilters > 0 || q) && <button onClick={clearAll} className="text-on-surface-variant hover:text-error text-body-sm flex items-center gap-1"><Icon name="close" className="text-sm" />Clear</button>}
        </div>
        {advOpen && (
          <div className="border-t border-outline-variant/20 pt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div><p className="font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest mb-2">Severity</p><div className="flex flex-wrap gap-1.5">{SEVS.map((v) => <span key={v} className={chip(fSev.has(v))} onClick={() => toggle(setFSev, v as string)}>{v}</span>)}</div></div>
            <div><p className="font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest mb-2">Tool</p><div className="flex flex-wrap gap-1.5">{tools.length ? tools.map((v) => <span key={v} className={chip(fTool.has(v))} onClick={() => toggle(setFTool, v)}>{v}</span>) : <span className="text-[11px] text-on-surface-variant/40">none yet</span>}</div></div>
          </div>
        )}
      </div>

      <div className="bg-surface-container-lowest border border-outline-variant/10 rounded-2xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface-container-high/50 border-b border-outline-variant/20 text-left">
                {["Vulnerability", "Sev", "Target", "Tool", "Engagement"].map((h) => <th key={h} className="px-4 py-4 font-mono-label text-on-surface-variant uppercase tracking-widest text-[11px]">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10">
              {rows.map((f, i) => (
                <tr key={f.dedup_key + i} className="hover:bg-primary/5 transition-colors group">
                  <td className="px-4 py-4"><div className="flex flex-col"><span className="text-body-sm font-semibold text-on-surface group-hover:text-primary transition-colors">{f.title}</span><span className="text-[11px] font-mono-label text-on-surface-variant/60">{[...(f.cve || []), f.cwe].filter(Boolean).join(" • ")}</span></div></td>
                  <td className="px-4 py-4"><span className={"inline-flex items-center px-2 py-0.5 rounded font-mono-label text-[10px] font-bold border uppercase " + (SEV_STYLE[f.severity as Sev] ?? SEV_STYLE.info)}>{f.severity}</span></td>
                  <td className="px-4 py-4"><span className="text-body-sm text-on-surface font-mono-label break-all">{f.affected_asset}</span></td>
                  <td className="px-4 py-4"><span className="text-body-sm text-on-surface-variant">{f.source}</span></td>
                  <td className="px-4 py-4"><span className="text-body-sm text-on-surface-variant">{f.engagement}</span></td>
                </tr>
              ))}
              {!loading && rows.length === 0 && <tr><td colSpan={5} className="px-6 py-10 text-center font-mono-label text-mono-label text-on-surface-variant/60">{err ? `Could not load findings: ${err}` : rowsAll.length === 0 ? "No findings yet. Run a scan from Engagements." : "No findings match your filters"}</td></tr>}
              {loading && <tr><td colSpan={5} className="px-6 py-10 text-center font-mono-label text-mono-label text-on-surface-variant/60"><Icon name="progress_activity" className="animate-spin align-middle" /> Loading…</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="px-6 py-4 bg-surface-container-high/30 border-t border-outline-variant/20 flex items-center justify-between">
          <span className="text-body-sm text-on-surface-variant">Showing {rows.length} of {rowsAll.length} findings{activeFilters ? ` (${activeFilters} filter${activeFilters > 1 ? "s" : ""})` : ""}</span>
        </div>
      </div>
    </>
  );
}
