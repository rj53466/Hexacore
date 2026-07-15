import { useState } from "react";
import { Icon, toast } from "../ui";
import { TOOLS, useToolStates, toolActions, installedCount, Tool, ToolStatus } from "../tools";

const CATS: Tool["cat"][] = ["Recon", "Scan", "Verify", "Enum", "Cloud", "API"];

const STATUS_PILL: Record<ToolStatus, { cls: string; label: string; dot?: string }> = {
  installed: { cls: "bg-secondary-container/20 text-secondary-fixed", label: "INSTALLED", dot: "bg-secondary-fixed" },
  not_installed: { cls: "bg-surface-container-high text-on-surface-variant", label: "NOT INSTALLED" },
  installing: { cls: "bg-primary/20 text-primary", label: "INSTALLING…" },
  updating: { cls: "bg-tertiary/20 text-tertiary", label: "UPDATING…" },
  failed: { cls: "bg-error/20 text-error", label: "FAILED", dot: "bg-error" },
};

export default function ToolsLibrary() {
  const states = useToolStates();
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const match = (t: Tool) => !query || (t.name + " " + t.bin + " " + t.cat + " " + t.id + " " + t.desc).toLowerCase().includes(query);
  const shown = TOOLS.filter(match);

  const act = (fn: () => void, msg: string, kind: "ok" | "warn" | "error" = "ok") => { fn(); toast(msg, kind); };

  return (
    <>
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-md mb-xl">
        <div className="min-w-0 md:flex-1">
          <h2 className="font-headline-lg text-headline-lg-mobile md:text-headline-lg text-on-surface mb-xs">Tools Library</h2>
        </div>
        <div className="shrink-0 flex items-center gap-sm w-full md:w-auto">
          <div className="relative flex-grow md:w-80">
            <Icon name="search" className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-sm" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search modules..."
              className="w-full bg-surface-container-low border border-outline-variant rounded-lg pl-10 pr-4 py-2 font-body-sm text-on-surface focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all" />
          </div>
          <div className="glass-panel px-3 py-2 rounded-lg flex items-center gap-2 font-mono-label text-mono-label whitespace-nowrap">
            <Icon name="inventory_2" className="text-base text-secondary-fixed" />
            <span className="text-on-surface-variant">INSTALLED</span>
            <span className="text-primary">{installedCount(states)} / {TOOLS.length}</span>
          </div>
        </div>
      </div>

      {shown.length === 0 && <div className="py-xl text-center font-mono-label text-mono-label text-on-surface-variant/60">No modules match “{q}”</div>}

      {CATS.map((cat) => {
        const items = shown.filter((t) => t.cat === cat);
        if (!items.length) return null;
        const nInst = items.filter((t) => states[t.id]?.status === "installed").length;
        return (
          <div key={cat} className="mb-lg">
            <div className="flex items-center gap-3 mb-md">
              <h3 className="font-mono-label text-mono-label text-primary uppercase tracking-[0.2em]">{cat}</h3>
              <span className="font-mono-label text-[11px] text-on-surface-variant/60">{nInst}/{items.length} installed</span>
              <div className="flex-grow h-px bg-outline-variant/20" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-lg">
              {items.map((t) => {
                const st = states[t.id];
                const on = st.status === "installed";
                const busy = st.status === "installing" || st.status === "updating";
                const pill = STATUS_PILL[st.status];
                return (
                  <div key={t.id} className="glass-panel rounded-xl p-lg flex flex-col group hover:border-primary/40 transition-all duration-300">
                    <div className="flex justify-between items-start mb-md">
                      <div className={"w-12 h-12 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform " + (on ? "bg-primary/10 text-primary" : "bg-surface-container-high text-on-surface-variant")}>
                        <Icon name={t.icon} className={"text-3xl " + (busy ? "animate-pulse" : "")} />
                      </div>
                      <span className={"font-mono-label text-mono-label px-2 py-1 rounded flex items-center gap-1 " + pill.cls}>
                        {pill.dot && <span className={"w-1.5 h-1.5 rounded-full " + pill.dot} />}{pill.label}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mb-xs">
                      <h3 className="font-headline-md text-headline-md text-on-surface">{t.name}</h3>
                      {on && !st.enabled && <span className="font-mono-label text-[10px] px-1.5 py-0.5 rounded bg-outline-variant/30 text-on-surface-variant">DISABLED</span>}
                    </div>
                    <p className="font-body-sm text-body-sm text-on-surface-variant mb-lg flex-grow">{t.desc}</p>
                    <div className="flex items-center justify-between mt-auto gap-2">
                      <span className="text-xs font-mono-label text-on-surface-variant/60 truncate">{t.bin} • v{st.version}</span>
                      <div className="flex items-center gap-1.5">
                        {st.status === "not_installed" && (
                          <button onClick={() => act(() => toolActions.install(t.id), "Installing " + t.name)} className="bg-primary text-on-primary hover:brightness-110 font-mono-label text-mono-label px-4 py-2 rounded-lg transition-all active:scale-95">INSTALL</button>
                        )}
                        {st.status === "failed" && (
                          <button onClick={() => act(() => toolActions.retry(t.id), "Retrying " + t.name, "warn")} className="bg-error/20 text-error hover:bg-error hover:text-on-error font-mono-label text-mono-label px-4 py-2 rounded-lg transition-all active:scale-95">RETRY</button>
                        )}
                        {busy && <button disabled className="bg-surface-variant text-on-surface-variant font-mono-label text-mono-label px-4 py-2 rounded-lg opacity-70">…</button>}
                        {on && (<>
                          <button title={st.enabled ? "Disable" : "Enable"} onClick={() => st.enabled ? act(() => toolActions.disable(t.id), t.name + " disabled", "warn") : act(() => toolActions.enable(t.id), t.name + " enabled")}
                            className={"p-2 rounded-lg transition-all active:scale-95 " + (st.enabled ? "bg-secondary-container/20 text-secondary-fixed" : "bg-surface-container-high text-on-surface-variant")}>
                            <Icon name={st.enabled ? "toggle_on" : "toggle_off"} className="text-lg" />
                          </button>
                          <button title="Update" onClick={() => act(() => toolActions.update(t.id), "Updating " + t.name)} className="p-2 rounded-lg bg-surface-container-high text-on-surface-variant hover:text-primary transition-all active:scale-95"><Icon name="update" className="text-lg" /></button>
                          {t.bin !== "built-in" && <button title="Uninstall" onClick={() => act(() => toolActions.uninstall(t.id), t.name + " uninstalled", "warn")} className="p-2 rounded-lg bg-surface-variant text-on-surface-variant hover:bg-error/20 hover:text-error transition-all active:scale-95"><Icon name="delete" className="text-lg" /></button>}
                        </>)}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </>
  );
}
