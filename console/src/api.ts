// Thin typed client for the HexaCore API.
let API = import.meta.env.VITE_API as string;
if (!API) {
  if (window.location.port === "5173") {
    API = `http://${window.location.hostname}:8000`;
  } else {
    API = "";
  }
}

let token = localStorage.getItem("hexa_token") || "";

export function setToken(t: string) {
  token = t;
  localStorage.setItem("hexa_token", t);
}
export function getToken() {
  return token;
}
export function clearToken() {
  token = "";
  localStorage.removeItem("hexa_token");
}

async function req(path: string, method = "GET", body?: unknown) {
  const res = await fetch(API + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error((detail as { detail?: string }).detail || `${res.status}`);
  }
  return res.json();
}

export interface Session {
  sub: string;
  role: "viewer" | "operator" | "owner";
  tenant_id: string;
}

// Decode tenant/role from the JWT payload — no extra endpoint needed.
export function session(): Session | null {
  if (!token) return null;
  try {
    const p = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { sub: p.sub, role: p.role ?? "viewer", tenant_id: p.tenant_id ?? "default" };
  } catch {
    return null;
  }
}

export interface Engagement {
  id: string;
  name: string;
  client: string;
  status: string;
  autonomy_profile: string;
  scope: { max_action_class: string; allow_domains: string[]; allow_cidrs: string[] };
}

export interface SeverityCounts { total: number; critical: number; high: number; medium: number; low: number; info: number }
export interface ApiFinding {
  title: string; severity: string; source: string; affected_asset: string;
  description: string; cvss_vector: string | null; cwe: string | null;
  cve: string[]; attack_techniques: string[]; remediation: string;
  evidence: Record<string, unknown>; dedup_key: string;
}
export interface LiveEventDTO { type: string; phase: string; detail: string; payload?: Record<string, unknown> }
export interface LlmStatus {
  profile: string; enabled: boolean; reachable: boolean;
  model: string; model_ready: boolean; detail: string; host?: string;
}

export interface Schedule {
  id: string;
  cron: string;
  target_engagement_id: string;
  enabled: boolean;
  next_run: string | null;
}

export interface MonitorDelta {
  new: number;
  fixed: number;
  persisting: number;
  new_by_severity: Record<string, number>;
  alert: boolean;
  new_high_or_critical: number;
}
export interface Monitoring {
  schedule_id: string;
  runs: number;
  delta: MonitorDelta | null;
}
export interface Trend {
  schedule_id: string;
  points: Array<{ id: string; name: string; at: string; counts: { total: number; critical: number; high: number } }>;
}

export const api = {
  login: (username: string, password: string) =>
    req("/auth/login", "POST", { username, password }),
  createEngagement: (body: unknown) => req("/engagements", "POST", body),
  runEngagement: (id: string) => req(`/engagements/${id}/run`, "POST", {}),
  listEngagements: (): Promise<Engagement[]> => req("/engagements"),
  getEngagement: (id: string): Promise<Engagement> => req(`/engagements/${id}`),
  kill: (id?: string) => req("/kill", "POST", { engagement_id: id ?? null }),
  shutdown: () => req("/system/shutdown", "POST", {}),
  approvals: (id: string) => req(`/engagements/${id}/approvals`),
  findings: (id: string): Promise<{ findings: ApiFinding[]; counts: SeverityCounts | null }> =>
    req(`/engagements/${id}/findings`),
  events: (id: string): Promise<{ events: LiveEventDTO[] }> => req(`/engagements/${id}/events`),
  createSchedule: (id: string, cron: string): Promise<Schedule> =>
    req(`/engagements/${id}/schedule`, "POST", { cron }),
  listSchedules: (): Promise<Schedule[]> => req("/schedules"),
  disableSchedule: (sid: string): Promise<Schedule> => req(`/schedules/${sid}/disable`, "POST", {}),
  monitoring: (sid: string): Promise<Monitoring> => req(`/schedules/${sid}/monitoring`),
  trend: (sid: string): Promise<Trend> => req(`/schedules/${sid}/trend`),
  resolveApproval: (tokenStr: string, decision: "approve" | "deny") =>
    req(`/approvals/${tokenStr}`, "POST", { decision, decided_by: "console" }),
  // Fetch the report WITH the auth header, then save the blob. A plain <a> link can't carry the
  // JWT (raw navigation sends no header -> 401), and a ?token= in the URL would leak into history/logs.
  downloadReport: async (id: string, fmt: string) => {
    const res = await fetch(`${API}/engagements/${id}/report?format=${fmt}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error((d as { detail?: string }).detail || `${res.status}`);
    }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `report.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
  wsUrl: (id: string) => {
    const base = API || window.location.origin;
    return `${base.replace(/^http/, "ws")}/engagements/${id}/ws?token=${encodeURIComponent(token)}`;
  },
  getTenantConfig: (): Promise<{ alert_webhook: string | null }> => req("/tenant/config"),
  setTenantConfig: (alert_webhook: string): Promise<{ alert_webhook: string }> => req("/tenant/config", "POST", { alert_webhook }),
  llmStatus: (): Promise<LlmStatus> => req("/llm/status"),
  getToolStatus: (): Promise<Record<string, boolean>> => req("/tools/status"),
  installTool: (id: string): Promise<{ status: string }> => req(`/tools/${id}/install`, "POST"),
};
