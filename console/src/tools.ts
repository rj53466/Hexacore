// HexaCore tool arsenal — the real adapter registry (tools/hexacore_tools/adapters), surfaced to the UI.
// Lifecycle state is client-side (localStorage) until a real /tools endpoint exists — see report.
import { useSyncExternalStore } from "react";
import { api } from "./api";

export interface Tool {
  id: string;
  name: string;
  bin: string;
  cat: "Recon" | "Scan" | "Verify" | "Enum" | "Cloud" | "API";
  icon: string;
  desc: string;
}

export type ToolStatus = "not_installed" | "installing" | "installed" | "updating" | "failed";
export interface ToolState { status: ToolStatus; enabled: boolean; version: string; }

export const TOOLS: Tool[] = [
  { id: "recon.subdomains", name: "Subfinder", bin: "subfinder", cat: "Recon", icon: "travel_explore", desc: "Passive subdomain enumeration across dozens of OSINT sources." },
  { id: "recon.http_probe", name: "HTTP Probe", bin: "httpx", cat: "Recon", icon: "language", desc: "Fast HTTP/S probing — live hosts, titles, status, tech fingerprints." },
  { id: "recon.dns", name: "DNS Resolver", bin: "dnsx", cat: "Recon", icon: "dns", desc: "Bulk DNS resolution and record enumeration (A/AAAA/CNAME/TXT)." },
  { id: "recon.tech", name: "WhatWeb", bin: "whatweb", cat: "Recon", icon: "widgets", desc: "Web technology fingerprinting — CMS, frameworks, servers." },
  { id: "recon.ct_logs", name: "CT Log Miner", bin: "curl", cat: "Recon", icon: "receipt_long", desc: "Certificate-transparency log mining via crt.sh for hidden hosts." },
  { id: "scan.ports", name: "Nmap Port Scan", bin: "nmap", cat: "Scan", icon: "radar", desc: "SYN + service/version detection with safe NSE scripts." },
  { id: "scan.web_nuclei", name: "Nuclei", bin: "nuclei", cat: "Scan", icon: "bug_report", desc: "Template-driven vulnerability scanning across the web surface." },
  { id: "scan.tls", name: "TLS Auditor", bin: "testssl.sh", cat: "Scan", icon: "lock", desc: "TLS/SSL configuration and cipher audit (testssl.sh)." },
  { id: "scan.web_dir", name: "FFUF Fuzzer", bin: "ffuf", cat: "Scan", icon: "manage_search", desc: "High-speed content and directory discovery fuzzing." },
  { id: "scan.web_nikto", name: "Nikto", bin: "nikto", cat: "Scan", icon: "policy", desc: "Classic web server misconfiguration and known-issue scanner." },
  { id: "verify.web_sqli", name: "SQLmap", bin: "sqlmap", cat: "Verify", icon: "storage", desc: "Automated SQL injection detection and exploitation." },
  { id: "verify.msf_check", name: "Metasploit Check", bin: "msfconsole", cat: "Verify", icon: "terminal", desc: "Safe check-mode validation of exploit modules." },
  { id: "verify.idor", name: "IDOR Verifier", bin: "built-in", cat: "Verify", icon: "vpn_key", desc: "Insecure direct object reference detection and confirmation." },
  { id: "verify.ssrf", name: "SSRF Verifier", bin: "built-in", cat: "Verify", icon: "cloud_sync", desc: "Server-side request forgery probing with out-of-band checks." },
  { id: "verify.adcs_find", name: "Certipy", bin: "certipy", cat: "Verify", icon: "workspace_premium", desc: "AD Certificate Services misconfiguration discovery (ESC1-8)." },
  { id: "enum.netexec", name: "NetExec", bin: "nxc", cat: "Enum", icon: "lan", desc: "Network protocol enumeration and credential spraying (CME successor)." },
  { id: "enum.bloodhound", name: "BloodHound", bin: "bloodhound-python", cat: "Enum", icon: "account_tree", desc: "Active Directory attack-path collection and graph analysis." },
  { id: "enum.linux_persistence", name: "LinPEAS", bin: "linpeas.sh", cat: "Enum", icon: "pest_control", desc: "Linux privilege-escalation and persistence enumeration." },
  { id: "scan.cloud.scoutsuite", name: "ScoutSuite", bin: "scout", cat: "Cloud", icon: "cloud", desc: "Multi-cloud (AWS/GCP/Azure) security posture assessment." },
  { id: "enum.cloud.cloudfox", name: "CloudFox", bin: "cloudfox", cat: "Cloud", icon: "cloud_circle", desc: "Cloud attack-surface enumeration for offensive operators." },
  { id: "scan.api.kiterunner", name: "Kiterunner", bin: "kr", cat: "API", icon: "api", desc: "Context-aware API endpoint discovery and route brute-forcing." },
];

// Key bumped to drop any previously-seeded optimistic "installed" dummy states.
const KEY = "hexacore_tool_states_v2";

type StateMap = Record<string, ToolState>;

// Start everything "not_installed" — real status is filled in by syncToolStates()
// from the backend /tools/status (which shutil.which()'s each binary on this host).
function seed(): StateMap {
  const m: StateMap = {};
  for (const t of TOOLS) m[t.id] = { status: "not_installed", enabled: false, version: "" };
  return m;
}
function read(): StateMap {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw === null) { const s = seed(); localStorage.setItem(KEY, JSON.stringify(s)); return s; }
    const parsed = JSON.parse(raw) as StateMap;
    // backfill any tool added since last persist
    for (const t of TOOLS) if (!parsed[t.id]) parsed[t.id] = { status: "not_installed", enabled: false, version: "1.0.0" };
    return parsed;
  } catch { return seed(); }
}

let states = read();
const listeners = new Set<() => void>();
function commit(next: StateMap) { states = next; localStorage.setItem(KEY, JSON.stringify(next)); listeners.forEach((l) => l()); }
function patch(id: string, p: Partial<ToolState>) { commit({ ...states, [id]: { ...states[id], ...p } }); }

export async function syncToolStates() {
  try {
    const status = await api.getToolStatus();
    const next = { ...states };
    let changed = false;
    for (const t of TOOLS) {
      const isInstalled = !!status[t.id];
      const newStatus = isInstalled ? "installed" : "not_installed";
      if (next[t.id].status !== newStatus && next[t.id].status !== "installing") {
        next[t.id] = { ...next[t.id], status: newStatus, enabled: isInstalled ? true : next[t.id].enabled };
        changed = true;
      }
    }
    if (changed) commit(next);
  } catch (e) {
    console.error("Failed to sync tool status", e);
  }
}

// Kick off initial sync
syncToolStates();

export function useToolStates(): StateMap {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => states, () => states);
}

const bump = (v: string) => { const p = v.split("."); p[2] = String((+p[2] || 0) + 1); return p.join("."); };

export const toolActions = {
  async install(id: string) {
    patch(id, { status: "installing" });
    try {
      await api.installTool(id);
      patch(id, { status: "installed", enabled: true });
    } catch (e) {
      patch(id, { status: "failed" });
      console.error(e);
    }
  },
  uninstall(id: string) { patch(id, { status: "not_installed", enabled: false }); },
  update(id: string) {
    patch(id, { status: "updating" });
    setTimeout(() => patch(id, { status: "installed", version: bump(states[id].version) }), 1000);
  },
  enable(id: string) { patch(id, { enabled: true }); },
  disable(id: string) { patch(id, { enabled: false }); },
  retry(id: string) { toolActions.install(id); },
};

export function installedCount(m: StateMap) { return TOOLS.filter((t) => m[t.id]?.status === "installed").length; }
