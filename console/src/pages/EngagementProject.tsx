import { useEffect, useRef, useState } from "react";
import { Icon, toast } from "../ui";
import { api, Engagement } from "../api";
import { useSettings, saveSettings, EngagementSettings, DEFAULT_SETTINGS } from "../stores";

/* ---------------- target classification ---------------- */
type TType = "IP" | "CIDR" | "URL" | "Domain" | "Hostname";
interface Target { id: string; value: string; type: TType; }

function classify(raw: string): TType | null {
  const v = raw.trim();
  if (!v) return null;
  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) return validOctets(v.split("/")[0]) && +v.split("/")[1] <= 32 ? "CIDR" : null;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return validOctets(v) ? "IP" : null;
  if (/^https?:\/\/[^\s]+$/i.test(v)) return "URL";
  if (/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(v)) return "Domain";
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(v)) return "Hostname";
  return null;
}
const validOctets = (ip: string) => ip.split(".").every((o) => +o >= 0 && +o <= 255);
const hostOf = (url: string) => { try { return new URL(url).hostname; } catch { return url; } };
const TYPE_ICON: Record<TType, string> = { IP: "lan", CIDR: "hub", URL: "link", Domain: "language", Hostname: "dns" };

/* build backend scope + seeds from the target list */
function toScope(targets: Target[], ceiling: string) {
  const domains = new Set<string>(), cidrs = new Set<string>(), seedHosts = new Set<string>(), seedDomains = new Set<string>();
  for (const t of targets) {
    if (t.type === "CIDR") {
      cidrs.add(t.value);
      // A /32 names exactly one host (e.g. loopback) -- seed it too, or the engine has scope
      // authorization but nothing to actually scan and the run silently no-ops.
      const single = t.value.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/32$/);
      if (single) seedHosts.add(single[1]);
    }
    else if (t.type === "IP") { cidrs.add(t.value + "/32"); seedHosts.add(t.value); }
    else if (t.type === "URL") { const h = hostOf(t.value); if (/^\d/.test(h)) { cidrs.add(h + "/32"); seedHosts.add(h); } else { domains.add(h); seedDomains.add(h); } }
    else { domains.add(t.value); seedDomains.add(t.value); } // Domain, Hostname
  }
  return {
    scope: { allow_domains: [...domains], allow_cidrs: [...cidrs], deny_list: [], max_action_class: ceiling },
    seeds: { domains: [...seedDomains], hosts: [...seedHosts] },
  };
}

/* ---------------- Add Target + New Engagement ---------------- */
function NewEngagement({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [meta, setMeta] = useState({ name: "", client: "", ceiling: "active-scan", autonomy: "supervised", auth_name: "", auth_email: "" });
  const [targets, setTargets] = useState<Target[]>([]);
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const setM = (k: string, v: string) => setMeta((x) => ({ ...x, [k]: v }));

  const draftType = classify(draft);
  const addTarget = () => {
    const type = classify(draft);
    if (!type) { toast("Invalid target format", "error"); return; }
    if (targets.some((t) => t.value === draft.trim())) { toast("Target already added", "warn"); return; }
    if (editing) { setTargets((ts) => ts.map((t) => (t.id === editing ? { ...t, value: draft.trim(), type } : t))); setEditing(null); }
    else setTargets((ts) => [...ts, { id: crypto.randomUUID(), value: draft.trim(), type }]);
    setDraft("");
  };
  const editTarget = (t: Target) => { setDraft(t.value); setEditing(t.id); };
  const delTarget = (id: string) => { setTargets((ts) => ts.filter((t) => t.id !== id)); if (editing === id) { setEditing(null); setDraft(""); } };

  const create = async () => {
    if (!meta.name) { toast("Engagement name required", "warn"); return; }
    if (!targets.length) { toast("Add at least one target", "warn"); return; }
    const { scope, seeds } = toScope(targets, meta.ceiling);
    const body = {
      name: meta.name, client: meta.client || "Internal Lab",
      scope, autonomy_profile: meta.autonomy, seeds,
      authorization: meta.auth_name ? { authorizer_name: meta.auth_name, authorizer_email: meta.auth_email || "owner@localhost", method: "click-sign" } : undefined,
    };
    setBusy(true);
    try {
      await api.createEngagement(body);
      toast(`Engagement created with ${targets.length} target(s)`, "ok");
      setMeta({ name: "", client: "", ceiling: "active-scan", autonomy: "supervised", auth_name: "", auth_email: "" });
      setTargets([]); setDraft(""); setOpen(false); onCreated();
    } catch (e) { toast("Create failed: " + String(e).replace("Error: ", ""), "error"); }
    finally { setBusy(false); }
  };

  const input = "bg-surface-container-lowest border border-outline-variant/40 rounded-lg py-2 px-3 text-on-surface text-body-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all w-full";
  const lbl = "font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest block mb-1";

  return (
    <div className="glass-panel rounded-xl mb-lg overflow-hidden">
      <button onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between p-md hover:bg-surface-container-high/30 transition-colors">
        <span className="flex items-center gap-2 font-mono-label text-mono-label text-on-surface uppercase"><Icon name="add_location_alt" className="text-primary" />Add Target — New Engagement</span>
        <Icon name={open ? "expand_less" : "expand_more"} className="text-on-surface-variant" />
      </button>
      {open && (
        <div className="p-md border-t border-outline-variant/20 space-y-md">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
            <div><label className={lbl}>Engagement name *</label><input className={input} value={meta.name} onChange={(e) => setM("name", e.target.value)} placeholder="Operation Aurora" /></div>
            <div><label className={lbl}>Client</label><input className={input} value={meta.client} onChange={(e) => setM("client", e.target.value)} placeholder="Internal Lab" /></div>
          </div>

          {/* Target builder */}
          <div>
            <label className={lbl}>Targets * (IP, Domain, URL, CIDR, Hostname)</label>
            <div className="flex gap-sm">
              <div className="relative flex-grow">
                <Icon name={draftType ? TYPE_ICON[draftType] : "help"} className={"absolute left-3 top-1/2 -translate-y-1/2 text-sm " + (draftType ? "text-secondary-fixed" : draft ? "text-error" : "text-on-surface-variant")} />
                <input className={input + " pl-9 font-mono-label"} value={draft} onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addTarget())}
                  placeholder="example-lab.test · 10.0.0.5 · 127.0.0.1/32 · https://app.test" />
              </div>
              <button onClick={addTarget} className="px-4 rounded-lg bg-primary text-on-primary font-mono-label text-mono-label hover:brightness-110 active:scale-95 transition-all flex items-center gap-1">
                <Icon name={editing ? "check" : "add"} className="text-base" />{editing ? "SAVE" : "ADD"}
              </button>
            </div>
            <p className={"text-[11px] mt-1 " + (draft && !draftType ? "text-error" : "text-on-surface-variant/50")}>
              {draft ? (draftType ? `Detected: ${draftType}` : "Unrecognized format") : "Press Enter or ADD. Loopback needs an exact /32."}
            </p>
            {targets.length > 0 && (
              <div className="mt-md space-y-1.5">
                {targets.map((t) => (
                  <div key={t.id} className="flex items-center justify-between bg-surface-container-low border border-outline-variant/20 rounded-lg px-3 py-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon name={TYPE_ICON[t.type]} className="text-secondary-fixed text-base" />
                      <code className="font-code-block text-code-block text-on-surface truncate">{t.value}</code>
                      <span className="font-mono-label text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant">{t.type}</span>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button onClick={() => editTarget(t)} className="p-1.5 rounded hover:bg-surface-container-high text-on-surface-variant hover:text-primary transition-colors"><Icon name="edit" className="text-base" /></button>
                      <button onClick={() => delTarget(t.id)} className="p-1.5 rounded hover:bg-error/10 text-on-surface-variant hover:text-error transition-colors"><Icon name="delete" className="text-base" /></button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
            <div><label className={lbl}>Action ceiling</label><select className={input + " cursor-pointer"} value={meta.ceiling} onChange={(e) => setM("ceiling", e.target.value)}>{["passive", "active-scan", "active-exploit"].map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
            <div><label className={lbl}>Autonomy</label><select className={input + " cursor-pointer"} value={meta.autonomy} onChange={(e) => setM("autonomy", e.target.value)}>{["scan-only", "supervised", "assisted"].map((c) => <option key={c} value={c}>{c}</option>)}</select></div>
            <div><label className={lbl}>Authorizer name</label><input className={input} value={meta.auth_name} onChange={(e) => setM("auth_name", e.target.value)} placeholder="Lab Owner (required to start)" /></div>
            <div><label className={lbl}>Authorizer email</label><input className={input} value={meta.auth_email} onChange={(e) => setM("auth_email", e.target.value)} placeholder="owner@localhost" /></div>
          </div>
          <div className="flex justify-end gap-sm">
            <button onClick={() => setOpen(false)} className="px-4 py-2 rounded-lg border border-outline-variant/40 text-on-surface-variant text-sm hover:bg-surface-container-high transition-colors">Cancel</button>
            <button disabled={busy} onClick={create} className="px-5 py-2 rounded-lg bg-primary text-on-primary text-sm font-bold hover:brightness-110 active:scale-95 transition-all disabled:opacity-60 flex items-center gap-2"><Icon name="rocket_launch" className="text-base" />{busy ? "Creating..." : "Create Engagement"}</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- Settings modal ---------------- */
function SettingsModal({ engId, name, onClose }: { engId: string; name: string; onClose: () => void }) {
  const saved = useSettings(engId);
  const [s, setS] = useState<EngagementSettings>(saved);
  const set = (k: keyof EngagementSettings, v: any) => setS((x) => ({ ...x, [k]: v }));
  const input = "bg-surface-container-lowest border border-outline-variant/40 rounded-lg py-2 px-3 text-on-surface text-body-sm focus:outline-none focus:ring-1 focus:ring-primary w-full";
  const lbl = "font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest block mb-1";

  const save = async () => {
    saveSettings(engId, s);
    if (s.notifyWebhook) { try { await api.setTenantConfig(s.notifyWebhook); } catch { /* webhook is best-effort */ } }
    toast("Settings saved", "ok"); onClose();
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="glass-card rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="sticky top-0 bg-surface-container-highest/90 backdrop-blur-xl px-lg py-md border-b border-outline-variant/30 flex items-center justify-between">
          <div><h3 className="font-headline-md text-headline-md text-on-surface">Engagement Settings</h3><p className="font-mono-label text-[11px] text-on-surface-variant">{name}</p></div>
          <button onClick={onClose} className="text-on-surface-variant hover:text-on-surface"><Icon name="close" /></button>
        </div>
        <div className="p-lg space-y-lg">
          <section>
            <h4 className="font-mono-label text-mono-label text-primary uppercase tracking-widest mb-md">Notifications</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
              <div><label className={lbl}>Alert webhook (Slack/HTTP)</label><input className={input} value={s.notifyWebhook} onChange={(e) => set("notifyWebhook", e.target.value)} placeholder="https://hooks.slack.com/…" /></div>
            </div>
          </section>
        </div>
        <div className="sticky bottom-0 bg-surface-container-highest/90 backdrop-blur-xl px-lg py-md border-t border-outline-variant/30 flex justify-between gap-sm">
          <button onClick={() => setS(DEFAULT_SETTINGS)} className="px-4 py-2 rounded-lg text-on-surface-variant text-sm hover:text-on-surface">Reset defaults</button>
          <div className="flex gap-sm">
            <button onClick={onClose} className="px-4 py-2 rounded-lg border border-outline-variant/40 text-on-surface-variant text-sm hover:bg-surface-container-high">Cancel</button>
            <button onClick={save} className="px-5 py-2 rounded-lg bg-primary text-on-primary text-sm font-bold hover:brightness-110 active:scale-95 transition-all">Save Settings</button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------------- Live feed (WebSocket) ---------------- */
interface LiveEvent { type: string; phase: string; detail: string; payload?: Record<string, unknown> }
const EV_COLOR: Record<string, string> = {
  "phase.changed": "text-primary",
  "command.started": "text-on-surface-variant",
  "command.finished": "text-secondary-fixed",
  "finding.created": "text-tertiary",
  "scope.denied": "text-error",
  "gate.requested": "text-tertiary",
  "runner.status": "text-on-surface-variant/70",
  "run.complete": "text-secondary-fixed",
  "run.error": "text-error",
};

function LiveFeedModal({ engId, name, onClose }: { engId: string; name: string; onClose: () => void }) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [status, setStatus] = useState<"connecting" | "live" | "done" | "closed">("connecting");
  const doneRef = useRef(false);
  const feedRef = useRef<HTMLDivElement>(null);

  // Opening the socket kicks off the run server-side if it never ran, then streams events.
  // The server replays the full recorded history on each (re)connect, so a reconnect after a
  // dropped socket just re-syncs — we reset the list on connect and let the replay refill it.
  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let retryTimer: number | undefined;
    let closed = false;

    const connect = () => {
      setStatus("connecting");
      setEvents([]);
      ws = new WebSocket(api.wsUrl(engId));
      ws.onopen = () => { retry = 0; setStatus("live"); };
      ws.onmessage = (e) => {
        const msg: LiveEvent = JSON.parse(e.data);
        setEvents((x) => [...x, msg]);
        if (msg.type === "run.complete" || msg.type === "run.error") {
          doneRef.current = true;
          setStatus("done");
        }
      };
      ws.onclose = (ev) => {
        if (closed || doneRef.current) return;
        // Auth/not-found closes (4401/4404) are terminal — don't reconnect into a loop.
        if (ev.code >= 4400 && ev.code < 4500) { setStatus("closed"); return; }
        retry += 1;
        setStatus("connecting");
        retryTimer = window.setTimeout(connect, Math.min(1000 * retry, 5000));
      };
      ws.onerror = () => ws?.close();
    };
    connect();
    return () => { closed = true; if (retryTimer) clearTimeout(retryTimer); ws?.close(); };
  }, [engId]);

  useEffect(() => { feedRef.current?.scrollTo(0, feedRef.current.scrollHeight); }, [events]);

  const STATUS_PILL: Record<string, { cls: string; label: string }> = {
    connecting: { cls: "text-tertiary", label: "connecting" },
    live: { cls: "text-secondary-fixed", label: "live" },
    done: { cls: "text-on-surface-variant", label: "complete" },
    closed: { cls: "text-error", label: "disconnected" },
  };
  const pill = STATUS_PILL[status];

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="glass-card rounded-xl w-full max-w-3xl max-h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="bg-surface-container-highest/90 backdrop-blur-xl px-lg py-md border-b border-outline-variant/30 flex items-center justify-between">
          <div>
            <h3 className="font-headline-md text-headline-md text-on-surface flex items-center gap-2"><Icon name="sensors" className="text-primary" />Live Scan Feed</h3>
            <p className="font-mono-label text-[11px] text-on-surface-variant">{name}</p>
          </div>
          <div className="flex items-center gap-md">
            <span className={"flex items-center gap-1.5 font-mono-label text-[11px] uppercase " + pill.cls}>
              <span className={"w-1.5 h-1.5 rounded-full " + (status === "live" ? "bg-secondary-fixed animate-pulse" : status === "closed" ? "bg-error" : "bg-current")} />{pill.label}
            </span>
            <button onClick={onClose} className="text-on-surface-variant hover:text-on-surface"><Icon name="close" /></button>
          </div>
        </div>
        <div ref={feedRef} className="flex-1 overflow-y-auto p-md font-code-block text-code-block space-y-1">
          {events.length === 0 ? (
            <div className="text-on-surface-variant/50 p-lg text-center">Waiting for events…</div>
          ) : events.map((ev, i) => (
            <div key={i} className="flex gap-2 items-baseline">
              <span className="font-mono-label text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant shrink-0 uppercase">{ev.phase}</span>
              <span className={"shrink-0 " + (EV_COLOR[ev.type] ?? "text-on-surface-variant")}>{ev.type}</span>
              <span className="text-on-surface truncate">{ev.detail}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ---------------- Engagements list ---------------- */
export default function EngagementProject() {
  const [engs, setEngs] = useState<Engagement[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [pdfBusy, setPdfBusy] = useState<string | null>(null);
  const [settingsFor, setSettingsFor] = useState<Engagement | null>(null);
  const [liveFor, setLiveFor] = useState<Engagement | null>(null);

  const load = () => api.listEngagements().then(setEngs).catch(() => {});
  useEffect(() => { load(); }, []);

  const run = async (id: string) => {
    setRunning(id);
    try { const r = await api.runEngagement(id); toast(`Run complete — ${r.counts?.total ?? 0} findings`, "ok"); load(); }
    catch (e) { toast("Run failed: " + String(e).replace("Error: ", ""), "error"); }
    finally { setRunning(null); }
  };
  const report = async (id: string) => {
    setPdfBusy(id);
    try { await api.downloadReport(id, "html"); toast("Report downloaded", "ok"); }
    catch (e) { toast("Report failed: " + String(e).replace("Error: ", ""), "error"); }
    finally { setPdfBusy(null); }
  };
  const kill = async (id: string) => {
    if (!confirm("Trip the kill switch for this engagement?")) return;
    try { await api.kill(id); toast("Engagement halted", "error"); load(); }
    catch (e) { toast("Kill failed: " + String(e).replace("Error: ", ""), "error"); }
  };

  return (
    <>
      <div className="flex items-center justify-between mb-lg">
        <h2 className="text-headline-lg font-headline-lg text-on-surface">Engagements</h2>
        <button onClick={load} className="text-on-surface-variant hover:text-primary transition-colors flex items-center gap-1 font-mono-label text-mono-label"><Icon name="refresh" className="text-base" />REFRESH</button>
      </div>

      <NewEngagement onCreated={load} />

      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="p-md border-b border-outline-variant/20 bg-surface-container/40"><h3 className="font-mono-label text-mono-label text-on-surface uppercase">Active Engagements ({engs.length})</h3></div>
        {engs.length === 0 ? (
          <div className="p-xl text-center text-on-surface-variant/60 font-mono-label text-mono-label flex flex-col items-center gap-2">
            <Icon name="radar" className="text-4xl text-outline" />No engagements yet. Add a target above to begin.
            <span className="text-[11px] text-on-surface-variant/40">(needs the API running: python serve.py)</span>
          </div>
        ) : (
          <div className="divide-y divide-outline-variant/10">
            {engs.map((e) => {
              const scopeList = [...e.scope.allow_domains, ...e.scope.allow_cidrs];
              return (
                <div key={e.id} className="p-md flex flex-wrap items-center justify-between gap-md hover:bg-surface-container-high/20 transition-colors">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2"><span className="text-body-md font-semibold text-on-surface">{e.name}</span><span className="font-mono-label text-[10px] px-2 py-0.5 rounded-full bg-surface-container-high text-on-surface-variant uppercase">{e.status}</span></div>
                    <div className="font-mono-label text-[11px] text-on-surface-variant/60 mt-0.5">{e.client} • ceiling {e.scope.max_action_class} • {scopeList.length} target(s): {scopeList.join(", ") || "none"}</div>
                  </div>
                  <div className="flex items-center gap-sm">
                    <button onClick={() => setLiveFor(e)} className="px-4 py-2 rounded-lg bg-secondary-container/30 text-secondary-fixed text-sm font-bold flex items-center gap-2 border border-secondary-fixed/30 hover:brightness-110 active:scale-95 transition-all"><Icon name="sensors" className="text-lg" />Live</button>
                    <button disabled={running === e.id} onClick={() => run(e.id)} className="px-4 py-2 rounded-lg bg-primary-container text-on-primary-container text-sm font-bold flex items-center gap-2 hover:brightness-110 active:scale-95 transition-all disabled:opacity-60"><Icon name={running === e.id ? "progress_activity" : "play_arrow"} className={"text-lg " + (running === e.id ? "animate-spin" : "")} />{running === e.id ? "Running..." : "Run"}</button>
                    <button disabled={pdfBusy === e.id} onClick={() => report(e.id)} className="px-4 py-2 rounded-lg bg-surface-variant text-on-surface-variant text-sm font-bold flex items-center gap-2 border border-outline-variant/30 hover:text-on-surface active:scale-95 transition-all disabled:opacity-60"><Icon name="description" className="text-lg" />Report</button>
                    <button onClick={() => setSettingsFor(e)} title="Settings" className="p-2 rounded-lg bg-surface-container-high text-on-surface-variant hover:text-primary transition-all active:scale-95"><Icon name="settings" className="text-lg" /></button>
                    <button onClick={() => kill(e.id)} title="Kill" className="p-2 rounded-lg bg-error/10 text-error hover:bg-error hover:text-on-error transition-all active:scale-95"><Icon name="dangerous" className="text-lg" /></button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {settingsFor && <SettingsModal engId={settingsFor.id} name={settingsFor.name} onClose={() => setSettingsFor(null)} />}
      {liveFor && <LiveFeedModal engId={liveFor.id} name={liveFor.name} onClose={() => { setLiveFor(null); load(); }} />}
    </>
  );
}
