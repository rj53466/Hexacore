import { useState, useSyncExternalStore } from "react";
import type { CSSProperties, ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { api, clearToken } from "./api";

/* ---------- System state (Running / Paused / Stopped) ---------- */
export type SysState = "running" | "paused" | "stopped";
let sysState: SysState = "running";
const sysListeners = new Set<() => void>();
export function setSysState(s: SysState) { sysState = s; sysListeners.forEach((l) => l()); }
export function useSysState(): SysState {
  return useSyncExternalStore((l) => { sysListeners.add(l); return () => sysListeners.delete(l); }, () => sysState, () => sysState);
}
const SYS_STYLE: Record<SysState, { cls: string; dot: string }> = {
  running: { cls: "text-secondary-fixed", dot: "bg-secondary-fixed animate-pulse" },
  paused: { cls: "text-tertiary", dot: "bg-tertiary" },
  stopped: { cls: "text-error", dot: "bg-error" },
};

/* ---------- Icon ---------- */
export function Icon({ name, fill, className, style }: { name: string; fill?: boolean; className?: string; style?: CSSProperties }) {
  return (
    <span className={"material-symbols-outlined " + (className ?? "")}
      style={{ ...(fill ? { fontVariationSettings: "'FILL' 1" } : {}), ...style }}>{name}</span>
  );
}

/* ---------- Toast (module-level, one host) ---------- */
let pushToast: ((msg: string, kind?: "ok" | "warn" | "error") => void) | null = null;
export function toast(msg: string, kind: "ok" | "warn" | "error" = "ok") { pushToast?.(msg, kind); }

export function ToastHost() {
  const [items, setItems] = useState<{ id: number; msg: string; kind: string }[]>([]);
  pushToast = (msg, kind = "ok") => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, msg, kind }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 2600);
  };
  const color = (k: string) => (k === "error" ? "#ffb4ab" : k === "warn" ? "#ffb95f" : "#4fdbc8");
  return (
    <div className="hx-toast-host">
      {items.map((i) => (
        <div key={i.id} className="hx-toast" style={{ borderLeft: `3px solid ${color(i.kind)}`, border: `1px solid ${color(i.kind)}55`, borderLeftWidth: 3 }}>{i.msg}</div>
      ))}
    </div>
  );
}

/* ---------- Kill switch ---------- */
function KillSwitch() {
  const [armed, setArmed] = useState(false);
  return (
    <button
      className="bg-error text-on-error px-4 py-2 font-mono-label text-mono-label rounded-lg border border-error/50 transition-all active:scale-95 hover:brightness-110 flex items-center gap-2 uppercase tracking-widest font-bold"
      onClick={async () => {
        if (armed) return;
        if (!confirm("SECURITY ALERT: Trigger platform-wide KILL SWITCH?\nRevokes active keys and halts every scanning engine.")) return;
        setArmed(true);
        setSysState("stopped");
        try { await api.kill(); toast("Kill switch engaged — engines halted", "error"); }
        catch (e) { toast("No active engagement to kill (" + String(e).replace("Error: ", "") + ")", "warn"); }
        document.body.style.transition = "filter .4s";
        document.body.style.filter = "grayscale(1) brightness(.6)";
        setTimeout(() => { document.body.style.filter = ""; setArmed(false); }, 2500);
      }}
    >
      <Icon name="dangerous" className="text-base" /> KILL SWITCH
    </button>
  );
}

/* ---------- Top bar ---------- */
function TopBar() {
  const sys = useSysState();
  const style = SYS_STYLE[sys];
  return (
    <header className="fixed top-0 w-full z-50 bg-surface-container-highest/70 backdrop-blur-xl border-b border-outline-variant/30 shadow-sm flex justify-between items-center px-md h-16">
      <div className="flex items-center gap-sm">
        <Icon name="security" fill className="text-primary" />
        <h1 className="font-headline-lg-mobile text-headline-lg-mobile text-primary tracking-tighter">HEXACORE</h1>
        <span className={"ml-2 hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-full bg-surface-container-low border border-outline-variant/30 font-mono-label text-[11px] uppercase " + style.cls}>
          <span className={"w-1.5 h-1.5 rounded-full " + style.dot} />{sys}
        </span>
      </div>
      <div className="flex items-center gap-md">
        {sys !== "running" && (
          <button onClick={() => { setSysState("running"); document.body.style.filter = ""; toast("System resumed", "ok"); }}
            className="hidden sm:flex font-mono-label text-mono-label text-secondary-fixed hover:brightness-110 transition-colors items-center gap-1" title="Resume system">
            <Icon name="play_circle" className="text-base" /> RESUME
          </button>
        )}
        <button className="hidden sm:flex font-mono-label text-mono-label text-on-surface-variant hover:text-primary transition-colors items-center gap-1"
          onClick={() => { clearToken(); location.reload(); }} title="Sign out">
          <Icon name="logout" className="text-base" /> LOGOUT
        </button>
        <KillSwitch />
      </div>
    </header>
  );
}

/* ---------- Bottom nav ---------- */
const NAV = [
  { to: "/", icon: "dashboard", label: "Dashboard" },
  { to: "/engagements", icon: "precision_manufacturing", label: "Engagements" },
  { to: "/tools", icon: "build", label: "Tools" },
  { to: "/findings", icon: "troubleshoot", label: "Findings" },
  { to: "/approvals", icon: "verified_user", label: "Approvals" },
];

function BottomNav() {
  return (
    <nav className="fixed bottom-0 w-full z-50 bg-surface-container-lowest/80 backdrop-blur-2xl border-t border-outline-variant/20 flex justify-around items-center pt-2 pb-safe px-2 h-20">
      {NAV.map((n) => (
        <NavLink key={n.to} to={n.to} end={n.to === "/"}
          className={({ isActive }) =>
            "flex flex-col items-center justify-center rounded-full px-4 py-1 transition-transform active:-translate-y-0.5 " +
            (isActive ? "bg-secondary-container/20 text-secondary-fixed" : "text-on-surface-variant/60 hover:text-secondary")}>
          {({ isActive }) => (<><Icon name={n.icon} fill={isActive} /><span className="font-mono-label text-mono-label">{n.label}</span></>)}
        </NavLink>
      ))}
    </nav>
  );
}

/* ---------- Shell ---------- */
export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-background text-on-surface overflow-x-hidden">
      <TopBar />
      <main className="pt-20 pb-28 px-md md:px-xl max-w-container-max mx-auto w-full">{children}</main>
      <BottomNav />
      <ToastHost />
    </div>
  );
}
