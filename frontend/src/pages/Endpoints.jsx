import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState([]);
  const [commands, setCommands] = useState([]);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [cmdAgent, setCmdAgent] = useState(null);
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");

  const refresh = async () => {
    const [eps, cmds] = await Promise.allSettled([api.endpoints(), api.listCommands(30)]);
    setEndpoints(eps.status === "fulfilled" ? eps.value.items || [] : endpoints);
    setCommands(cmds.status === "fulfilled" ? cmds.value.items || [] : commands);
    if (eps.status !== "fulfilled") setError(eps.reason.message);
  };
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10000);
    return () => clearInterval(t);
  }, []);

  const sendCommand = async () => {
    if (!cmdAgent) return;
    setBusy(`cmd:${cmdAgent}`);
    setError("");
    setMessage("");
    try {
      const res = await api.sendCommand(cmdAgent, cmdAction, cmdTarget.trim(), cmdNote.trim());
      setMessage(`Command #${res.id} queued for ${res.agent_id} (${res.action} ${res.target})`);
      setCmdAgent(null);
      setCmdTarget("");
      setCmdNote("");
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  if (!endpoints.length && !commands.length && !error) return <Loading label="Loading endpoints" />;

  return (
    <div className="space-y-6 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Endpoints</h1>
        <p className="mt-1 text-[13px] text-slate-400">Remote agents, online status and the command channel</p>
      </div>

      {message && (
        <div className="rounded-xl border p-4 text-sm" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
          {message}
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="mb-4 flex items-center justify-between gap-2">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Connected Endpoints
          </h3>
          <span className="text-xs text-slate-500">
            {endpoints.length === 0 ? "No agents reporting yet" : `${endpoints.length} agent${endpoints.length === 1 ? "" : "s"}`}
          </span>
        </div>
        {endpoints.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.03]">
              <svg className="h-5 w-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
              </svg>
            </div>
            <h4 className="text-[13px] font-semibold text-slate-300">No Agents Connected</h4>
            <p className="mt-1 max-w-xs text-xs text-slate-500">No remote agents have reported yet. Set one up from <span className="font-mono text-cyan-400">Agent Setup</span>, or ingest directly via <span className="font-mono text-cyan-400">POST /api/ingest</span> with an X-Agent-Key.</p>
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {endpoints.map((ep) => {
              const online = Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000;
              return (
                <div key={ep.agent_id} className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5 transition-all hover:border-white/[0.12] hover:bg-white/[0.035]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[13px] font-semibold text-slate-100">{ep.hostname}</span>
                    <span
                      className={`shrink-0 rounded-lg px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${
                        online
                          ? "rounded-lg border border-emerald-500/30 bg-emerald-500/[0.1] text-emerald-400"
                          : "rounded-lg border border-rose-500/30 bg-rose-500/[0.1] text-rose-400"
                      }`}
                    >
                      {online ? "ONLINE" : "OFFLINE"}
                    </span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{ep.agent_id}</p>
                  {ep.org ? (
                    <span className="mt-1 inline-block max-w-full truncate rounded-md bg-violet-500/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-violet-300" title={`Organization: ${ep.org}`}>
                      {ep.org}
                    </span>
                  ) : null}
                  <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                    <div className="rounded-xl bg-white/[0.03] px-3 py-2 ring-1 ring-white/[0.04]">
                      <p className="text-[12px] font-bold text-cyan-400">{ep.records}</p>
                      <p className="text-[9px] uppercase tracking-wider text-slate-500">records</p>
                    </div>
                    <div className="rounded-xl bg-white/[0.03] px-3 py-2 ring-1 ring-white/[0.04]">
                      <p className="text-[12px] font-bold text-slate-200">{ep.events}</p>
                      <p className="text-[9px] uppercase tracking-wider text-slate-500">events</p>
                    </div>
                    <div className="rounded-xl bg-white/[0.03] px-3 py-2 ring-1 ring-white/[0.04]">
                      <p className="text-[12px] font-bold text-amber-400">{ep.alerts}</p>
                      <p className="text-[9px] uppercase tracking-wider text-slate-500">alerts</p>
                    </div>
                  </div>
                  <p className="mt-2 text-[10px] text-slate-500">
                    last seen{" "}
                    {new Date(ep.last_seen).toLocaleString([], {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>

                  {cmdAgent === ep.agent_id ? (
                    <div className="mt-3 rounded-xl border border-cyan-500/15 bg-cyan-500/[0.04] p-4">
                      <select
                        value={cmdAction}
                        onChange={(e) => setCmdAction(e.target.value)}
                        className="mb-2 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                      >
                        <option value="block_ip">Block IP (firewall)</option>
                        <option value="kill_process">Kill Process</option>
                        <option value="quarantine">Quarantine File</option>
                        <option value="isolate">Isolate Endpoint</option>
                        <option value="disable_account">Disable Account</option>
                        <option value="escalate">Escalate / Review</option>
                      </select>
                      {cmdAction !== "escalate" && (
                        <input
                          value={cmdTarget}
                          onChange={(e) => setCmdTarget(e.target.value)}
                          placeholder={cmdAction === "block_ip" ? "e.g. 185.220.101.45" : cmdAction === "isolate" ? "e.g. WS-ALPHA (optional)" : "e.g. miner.exe or C:\\Users\\...\\malware.exe"}
                          className="mb-2 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 font-mono text-xs text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                        />
                      )}
                      <input
                        value={cmdNote}
                        onChange={(e) => setCmdNote(e.target.value)}
                        placeholder="note (optional)"
                        className="mb-3 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                      />
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={sendCommand}
                          disabled={busy === `cmd:${ep.agent_id}`}
                          className="flex-1 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[12px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] disabled:opacity-50"
                        >
                          {busy === `cmd:${ep.agent_id}` ? "Sending..." : "Send Command"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setCmdAgent(null)}
                          className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-2.5 text-[12px] text-slate-300 transition-all hover:bg-white/[0.06]"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setCmdAgent(ep.agent_id);
                        setCmdAction("block_ip");
                        setCmdTarget("");
                        setCmdNote("");
                        setError("");
                      }}
                      disabled={!online}
                      className="mt-3 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-2.5 text-[12px] font-semibold text-slate-300 transition-all hover:border-cyan-500/30 hover:bg-cyan-500/[0.06] hover:text-cyan-300 disabled:opacity-40"
                    >
                      Send Command
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="mb-4 flex items-center justify-between gap-2">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Agent Command History
          </h3>
          <span className="text-xs text-slate-500">
            {commands.length === 0 ? "No commands issued yet" : `latest ${commands.length}`}
          </span>
        </div>
        {commands.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.03]">
              <svg className="h-5 w-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
              </svg>
            </div>
            <h4 className="text-[13px] font-semibold text-slate-300">No Commands Issued</h4>
            <p className="mt-1 max-w-xs text-xs text-slate-500">Queue a remote action on an endpoint above — the agent picks it up within 15s and reports back.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/[0.06] text-[10px] uppercase tracking-[0.08em] text-slate-500/70">
                  <th className="pb-2 pr-3 text-left font-medium">#</th>
                  <th className="pb-2 pr-3 text-left font-medium">Agent</th>
                  <th className="pb-2 pr-3 text-left font-medium">Action</th>
                  <th className="pb-2 pr-3 text-left font-medium">Target</th>
                  <th className="pb-2 pr-3 text-left font-medium">Status</th>
                  <th className="pb-2 pr-3 text-left font-medium">Detail</th>
                  <th className="pb-2 text-left font-medium">Queued</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {commands.map((c) => (
                  <tr key={c.id}>
                    <td className="py-2.5 pr-3 font-mono text-xs text-slate-400">{c.id}</td>
                    <td className="py-2.5 pr-3 font-mono text-xs text-slate-300">{c.agent_id}</td>
                    <td className="py-2.5 pr-3 font-mono text-xs text-cyan-300">{c.action}</td>
                    <td className="max-w-[200px] truncate py-2.5 pr-3 font-mono text-xs text-slate-300">{c.target || "—"}</td>
                    <td className="py-2.5 pr-3">
                      <span
                        className={`rounded-lg px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${
                          c.status === "success"
                            ? "border border-emerald-500/30 bg-emerald-500/[0.1] text-emerald-400"
                            : c.status === "failed"
                              ? "border border-rose-500/30 bg-rose-500/[0.1] text-rose-400"
                              : "border border-amber-500/30 bg-amber-500/[0.1] text-amber-400"
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="max-w-[220px] truncate py-2.5 pr-3 text-xs text-slate-500">{c.detail || "—"}</td>
                    <td className="py-2.5 text-xs text-slate-500">
                      {new Date(c.created_at).toLocaleString([], {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-xs font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
