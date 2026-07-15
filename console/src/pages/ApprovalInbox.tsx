import { useEffect, useState } from "react";
import { Icon, toast } from "../ui";
import { api } from "../api";

interface Gate { token: string; capability: string; target: string; justification: string; engagement: string }

export default function ApprovalInbox() {
  const [live, setLive] = useState<Gate[]>([]);
  const [decided, setDecided] = useState<Record<string, "APPROVED" | "DENIED">>({});
  const [counts, setCounts] = useState({ approved: 0, denied: 0 });
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const engs = await api.listEngagements();
      const all: Gate[] = [];
      for (const e of engs) {
        const gs = await api.approvals(e.id).catch(() => []);
        for (const g of gs as any[]) all.push({
          token: g.resume_token ?? g.token, capability: g.capability ?? "action",
          target: g.target ?? "—", justification: g.justification ?? g.reason ?? "", engagement: e.name,
        });
      }
      setLive(all);
    } catch { /* not logged in / API down — leave empty, no fake fallback */ }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const resolve = async (g: Gate, approve: boolean) => {
    try {
      await api.resolveApproval(g.token, approve ? "approve" : "deny");
      setDecided((d) => ({ ...d, [g.token]: approve ? "APPROVED" : "DENIED" }));
      setCounts((c) => ({ approved: c.approved + (approve ? 1 : 0), denied: c.denied + (approve ? 0 : 1) }));
      toast("Request " + (approve ? "approved" : "denied"), approve ? "ok" : "error");
    } catch (e) { toast("Failed: " + String(e).replace("Error: ", ""), "error"); }
  };

  const DecidedBadge = ({ v }: { v: "APPROVED" | "DENIED" }) => {
    const ok = v === "APPROVED";
    return (
      <div className="flex-1 flex items-center justify-center gap-2 h-14 rounded-xl font-mono-label font-bold"
        style={{ color: ok ? "#4fdbc8" : "#ffb4ab", border: `1px solid ${ok ? "#4fdbc8" : "#ffb4ab"}55`, background: `${ok ? "#4fdbc8" : "#ffb4ab"}14` }}>
        <Icon name={ok ? "check_circle" : "cancel"} />{v}
      </div>
    );
  };

  const pending = live.filter((g) => !decided[g.token]).length;

  return (
    <div className="cyber-grid -mx-md md:-mx-xl px-md md:px-xl pt-2 pb-4 rounded-xl">
      <div className="mb-lg flex flex-col md:flex-row md:items-end justify-between gap-md">
        <div className="min-w-0 md:flex-1">
          <h1 className="font-headline-lg text-headline-lg text-on-surface mb-xs uppercase tracking-tight">Approval Inbox</h1>
        </div>
        <div className="shrink-0 flex items-center gap-sm">
          <button onClick={load} className="text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1 font-mono-label text-mono-label"><Icon name="refresh" className="text-base" />REFRESH</button>
          <div className="flex items-center gap-sm bg-surface-container-low px-md py-sm rounded-xl border border-outline-variant/20">
            <Icon name="warning" fill className="text-tertiary-fixed" />
            <span className="font-mono-label text-mono-label text-tertiary-fixed">{pending} PENDING AUTHORIZATIONS</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-lg">
        <div className="lg:col-span-8 space-y-lg">
          {live.length > 0 ? (
            live.map((g) => (
              <div key={g.token} className="glass-panel rounded-xl overflow-hidden relative">
                <div className="h-1.5 w-full bg-error shadow-[0_0_15px_rgba(255,180,171,0.5)]" />
                <div className="p-md md:p-lg">
                  <div className="flex items-center justify-between mb-xs">
                    <div className="flex items-center gap-xs text-error"><Icon name="priority_high" className="text-sm" /><span className="font-mono-label text-mono-label uppercase font-bold">Action Requested</span></div>
                    <span className="font-mono-label text-[11px] text-on-surface-variant">{g.engagement}</span>
                  </div>
                  <h2 className="font-headline-md text-headline-md text-on-surface mb-md">{g.capability}</h2>
                  <div className="bg-surface-container-low p-md rounded-lg border border-outline-variant/30 mb-lg">
                    <span className="font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest block mb-1">Target Asset</span>
                    <code className="font-code-block text-code-block text-secondary-fixed break-all">{g.target}</code>
                  </div>
                  {g.justification && <div className="bg-surface-container-lowest p-md border-l-4 border-primary rounded-r-lg mb-lg"><p className="font-body-md text-body-md italic text-on-surface">"{g.justification}"</p></div>}
                  <div className="flex flex-col sm:flex-row gap-md border-t border-outline-variant/30 pt-lg">
                    {decided[g.token] ? <DecidedBadge v={decided[g.token]} /> : <>
                      <button onClick={() => resolve(g, true)} className="flex-1 bg-secondary-container text-on-secondary-container h-14 rounded-xl flex items-center justify-center gap-sm font-bold transition-all hover:brightness-110 active:scale-[0.98]"><Icon name="check_circle" />APPROVE</button>
                      <button onClick={() => resolve(g, false)} className="flex-1 bg-error text-on-error h-14 rounded-xl flex items-center justify-center gap-sm font-bold transition-all hover:brightness-110 active:scale-[0.98]"><Icon name="cancel" />DENY</button>
                    </>}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="glass-panel rounded-xl p-xl text-center text-on-surface-variant/60 font-mono-label text-mono-label flex flex-col items-center gap-2">
              <Icon name="verified_user" className="text-4xl text-outline" />
              {loading ? "Loading pending approvals…" : "No pending approvals. Gated actions appear here when a scan requests one."}
            </div>
          )}
        </div>

        <div className="lg:col-span-4 space-y-lg">
          <div className="glass-panel rounded-xl p-md">
            <h4 className="font-mono-label text-mono-label text-on-surface mb-md flex items-center gap-sm"><Icon name="analytics" className="text-sm" />GATEKEEPER METRICS (THIS SESSION)</h4>
            <div className="grid grid-cols-2 gap-sm">
              <div className="text-center p-sm bg-surface-container-low rounded-lg"><span className="block text-headline-md text-secondary">{counts.approved}</span><span className="text-[10px] uppercase font-mono-label text-on-surface-variant">Approved</span></div>
              <div className="text-center p-sm bg-surface-container-low rounded-lg"><span className="block text-headline-md text-error">{counts.denied}</span><span className="text-[10px] uppercase font-mono-label text-on-surface-variant">Denied</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
