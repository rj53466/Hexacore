import { createContext, useContext, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { api, getToken, session, setToken } from "./api";
import { Shell, Icon } from "./ui";
import { syncToolStates } from "./tools";

import HexacoreDashboard from "./pages/HexacoreDashboard";
import ApprovalInbox from "./pages/ApprovalInbox";
import EngagementProject from "./pages/EngagementProject";
import FindingsLibrary from "./pages/FindingsLibrary";
import ToolsLibrary from "./pages/ToolsLibrary";
import Operators from "./pages/Operators";

const TenantContext = createContext<any>(null);
export const useTenant = () => useContext(TenantContext);

function Login({ onDone }: { onDone: () => void }) {
  const [u, setU] = useState("operator");
  const [p, setP] = useState("operator-dev");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setErr(""); setBusy(true);
    try { const r = await api.login(u.trim(), p.trim()); setToken(r.access_token); syncToolStates(); onDone(); }
    catch (e) { setErr(String(e).replace("Error: ", "")); }
    finally { setBusy(false); }
  };

  const inputCls = "w-full bg-surface-container-lowest border border-outline-variant/40 rounded-lg px-3.5 py-3 text-on-surface text-body-md placeholder:text-on-surface-variant/40 focus:outline-none focus:ring-2 focus:ring-primary/60 focus:border-primary transition-all";

  return (
    <div className="min-h-screen w-full bg-background text-on-surface cyber-grid grid place-items-center p-4">
      <div className="glass-card rounded-2xl shadow-2xl p-8 sm:p-10 flex flex-col" style={{ width: "min(92vw, 420px)" }}>
        <div className="flex items-center gap-2 justify-center">
          <Icon name="security" fill className="text-primary" style={{ fontSize: 34 }} />
          <h1 className="font-headline-lg text-headline-lg text-primary tracking-tight">HEXACORE</h1>
        </div>
        <p className="text-on-surface-variant text-center text-body-sm mt-2 mb-8">Authorized penetration testing only</p>

        <label className="font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest mb-1.5">Operator</label>
        <input autoFocus autoComplete="username" className={inputCls} value={u} onChange={(e) => setU(e.target.value)} placeholder="operator" onKeyDown={(e) => e.key === "Enter" && submit()} />

        <label className="font-mono-label text-[11px] text-on-surface-variant uppercase tracking-widest mb-1.5 mt-5">Passphrase</label>
        <input type="password" autoComplete="current-password" className={inputCls} value={p} onChange={(e) => setP(e.target.value)} placeholder="••••••••" onKeyDown={(e) => e.key === "Enter" && submit()} />

        <button disabled={busy} onClick={submit}
          className="w-full bg-primary text-on-primary py-3 rounded-lg font-mono-label text-mono-label uppercase tracking-widest mt-8 hover:brightness-110 transition-all active:scale-[0.98] disabled:opacity-60 flex items-center justify-center gap-2">
          {busy ? "AUTHENTICATING…" : "SIGN IN"}
        </button>

        {err && (
          <div className="mt-4 flex items-center justify-center gap-2 text-error text-body-sm bg-error/10 border border-error/30 rounded-lg py-2 px-3">
            <Icon name="error" className="text-base" />{err}
          </div>
        )}
        <p className="text-on-surface-variant/40 font-mono-label text-[10px] text-center mt-6">DEV LOGIN — operator / operator-dev</p>
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const me = session();
  if (!authed) return <Login onDone={() => setAuthed(true)} />;

  return (
    <TenantContext.Provider value={me}>
      <BrowserRouter>
        <Shell>
          <Routes>
            <Route path="/" element={<HexacoreDashboard />} />
            <Route path="/engagements" element={<EngagementProject />} />
            <Route path="/tools" element={<ToolsLibrary />} />
            <Route path="/findings" element={<FindingsLibrary />} />
            <Route path="/approvals" element={<ApprovalInbox />} />
            <Route path="/operators" element={<Operators />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </Shell>
      </BrowserRouter>
    </TenantContext.Provider>
  );
}
