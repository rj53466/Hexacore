import { useSyncExternalStore } from "react";

/* ---------------- Engagement settings (per engagement, persisted) ---------------- */
export interface EngagementSettings {
  notifyWebhook: string;
}

export const DEFAULT_SETTINGS: EngagementSettings = {
  notifyWebhook: "",
};

const SKEY = "hexacore_settings";
type SettingsMap = Record<string, EngagementSettings>;
function readSettings(): SettingsMap { try { return JSON.parse(localStorage.getItem(SKEY) || "{}"); } catch { return {}; } }
let settings = readSettings();
const sListeners = new Set<() => void>();

export function useSettings(engId: string): EngagementSettings {
  const map = useSyncExternalStore((l) => { sListeners.add(l); return () => sListeners.delete(l); }, () => settings, () => settings);
  return { ...DEFAULT_SETTINGS, ...(map[engId] || {}) };
}
export function saveSettings(engId: string, s: EngagementSettings) {
  settings = { ...settings, [engId]: s };
  localStorage.setItem(SKEY, JSON.stringify(settings));
  sListeners.forEach((l) => l());
}

/* ---------------- Operators (seeded, persisted) ---------------- */
export interface Operator {
  id: string; name: string; role: "owner" | "operator" | "viewer";
  status: "online" | "idle" | "offline"; engagement: string; lastActivity: string;
}
// No backend /operators endpoint exists, so there is no real roster to show — start empty
// rather than inventing people. (Key bumped to drop any previously-seeded dummy operators.)
const OKEY = "hexacore_operators_v2";
const OP_SEED: Operator[] = [];
function readOps(): Operator[] { try { const r = localStorage.getItem(OKEY); if (r === null) { localStorage.setItem(OKEY, JSON.stringify(OP_SEED)); return OP_SEED; } return JSON.parse(r); } catch { return OP_SEED; } }
let operators = readOps();
const oListeners = new Set<() => void>();
export function useOperators(): Operator[] {
  return useSyncExternalStore((l) => { oListeners.add(l); return () => oListeners.delete(l); }, () => operators, () => operators);
}
export function activeOperatorCount() { return operators.filter((o) => o.status === "online").length; }
