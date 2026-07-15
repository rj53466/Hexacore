import { useOperators, Operator } from "../stores";

const DOT: Record<Operator["status"], string> = { online: "bg-secondary-fixed", idle: "bg-tertiary", offline: "bg-outline" };
const ROLE: Record<Operator["role"], string> = { owner: "text-primary", operator: "text-secondary-fixed", viewer: "text-on-surface-variant" };

export default function Operators() {
  const ops = useOperators();
  const online = ops.filter((o) => o.status === "online").length;
  return (
    <>
      <div className="flex items-end justify-between mb-lg">
        <div><h2 className="text-headline-lg font-headline-lg text-on-surface">Operators</h2><p className="text-body-sm text-on-surface-variant">{online} online · {ops.length} total</p></div>
        <div className="glass-panel px-3 py-2 rounded-lg flex items-center gap-2 font-mono-label text-mono-label"><span className="w-2 h-2 rounded-full bg-secondary-fixed animate-pulse" /><span className="text-secondary-fixed">{online} ACTIVE</span></div>
      </div>

      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface-container-high/50 border-b border-outline-variant/20 text-left">
                {["Operator", "Role", "Status", "Active Engagement", "Last Activity"].map((h) => <th key={h} className="px-6 py-4 font-mono-label text-on-surface-variant uppercase tracking-widest text-[11px]">{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant/10">
              {ops.map((o) => (
                <tr key={o.id} className="hover:bg-primary/5 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-full bg-surface-container-high flex items-center justify-center font-mono-label text-[11px] text-on-surface-variant">{o.name.split(" ").map((n) => n[0]).join("")}</div>
                      <span className="text-body-md text-on-surface">{o.name}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4"><span className={"font-mono-label text-mono-label uppercase " + ROLE[o.role]}>{o.role}</span></td>
                  <td className="px-6 py-4"><div className="flex items-center gap-2"><span className={"w-2 h-2 rounded-full " + DOT[o.status] + (o.status === "online" ? " animate-pulse" : "")} /><span className="text-body-sm text-on-surface-variant capitalize">{o.status}</span></div></td>
                  <td className="px-6 py-4"><span className="text-body-sm text-on-surface font-mono-label">{o.engagement}</span></td>
                  <td className="px-6 py-4"><span className="text-body-sm text-on-surface-variant">{o.lastActivity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <p className="mt-md font-mono-label text-[11px] text-on-surface-variant/40">Operators are seeded client-side. Backend model + `/operators` endpoint proposed in the completion report.</p>
    </>
  );
}
