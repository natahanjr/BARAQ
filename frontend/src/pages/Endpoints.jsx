import { useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
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
      <PageHeader
        title="Endpoints"
        subtitle="Remote agents, online status and the command channel"
      />

      {message && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          ✓ {message}
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      {/* Connected endpoints */}
      <Card>
        <div className="mb-4 flex items-center justify-between gap-2">
          <h3 className="text-base font-semibold text-white">Connected Endpoints</h3>
          <span className="text-[11px] text-slate-500">
            {endpoints.length === 0 ? "No agents reporting yet" : `${endpoints.length} agent${endpoints.length === 1 ? "" : "s"}`}
          </span>
        </div>
        {endpoints.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-700/60 bg-slate-900/40 px-4 py-6 text-center text-xs text-slate-500">
            No remote agents have reported yet. Set one up from{" "}
            <span className="font-mono text-cyan-500/80">Agent Setup</span>, or ingest directly via{" "}
            <span className="font-mono text-cyan-500/80">POST /api/ingest</span> with an
            X-Agent-Key.
          </p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {endpoints.map((ep) => {
              const online = Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000;
              return (
                <div key={ep.agent_id} className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-sm font-semibold text-slate-100">{ep.hostname}</span>
                    <span
                      className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                        online ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
                      }`}
                    >
                      {online ? "ONLINE" : "OFFLINE"}
                    </span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{ep.agent_id}</p>
                  {ep.org ? (
                    <span className="mt-1 inline-block max-w-full truncate rounded bg-violet-500/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-violet-300" title={`Organization: ${ep.org}`}>
                      {ep.org}
                    </span>
                  ) : null}
                  <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                    <div className="rounded bg-slate-800/50 py-1.5">
                      <p className="text-xs font-bold text-cyan-400">{ep.records}</p>
                      <p className="text-[9px] uppercase tracking-wider text-slate-500">records</p>
                    </div>
                    <div className="rounded bg-slate-800/50 py-1.5">
                      <p className="text-xs font-bold text-slate-200">{ep.events}</p>
                      <p className="text-[9px] uppercase tracking-wider text-slate-500">events</p>
                    </div>
                    <div className="rounded bg-slate-800/50 py-1.5">
                      <p className="text-xs font-bold text-amber-400">{ep.alerts}</p>
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
                    <div className="mt-3 space-y-2 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-2.5">
                      <select
                        value={cmdAction}
                        onChange={(e) => setCmdAction(e.target.value)}
                        className="w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-xs text-slate-200 outline-none focus:border-cyan-500"
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
                          className="w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 font-mono text-[11px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500"
                        />
                      )}
                      <input
                        value={cmdNote}
                        onChange={(e) => setCmdNote(e.target.value)}
                        placeholder="note (optional)"
                        className="w-full rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-[11px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500"
                      />
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={sendCommand}
                          disabled={busy === `cmd:${ep.agent_id}`}
                          className="flex-1 rounded-md bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
                        >
                          {busy === `cmd:${ep.agent_id}` ? "Sending..." : "Send Command"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setCmdAgent(null)}
                          className="rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:bg-slate-700"
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
                      className="mt-3 w-full rounded-md border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-colors hover:border-cyan-500/50 hover:text-cyan-300 disabled:opacity-40"
                    >
                      Send Command
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Recent commands */}
      <Card>
        <div className="mb-4 flex items-center justify-between gap-2">
          <h3 className="text-base font-semibold text-white">Agent Command History</h3>
          <span className="text-[11px] text-slate-500">
            {commands.length === 0 ? "No commands issued yet" : `latest ${commands.length}`}
          </span>
        </div>
        {commands.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-700/60 bg-slate-900/40 px-4 py-6 text-center text-xs text-slate-500">
            Queue a remote action on an endpoint above — the agent picks it up within {`15s`} and reports back.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                  <th className="pb-2 pr-3 font-medium">#</th>
                  <th className="pb-2 pr-3 font-medium">Agent</th>
                  <th className="pb-2 pr-3 font-medium">Action</th>
                  <th className="pb-2 pr-3 font-medium">Target</th>
                  <th className="pb-2 pr-3 font-medium">Status</th>
                  <th className="pb-2 pr-3 font-medium">Detail</th>
                  <th className="pb-2 font-medium">Queued</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {commands.map((c) => (
                  <tr key={c.id}>
                    <td className="py-2 pr-3 font-mono text-slate-400">{c.id}</td>
                    <td className="py-2 pr-3 font-mono text-slate-300">{c.agent_id}</td>
                    <td className="py-2 pr-3 font-mono text-cyan-300">{c.action}</td>
                    <td className="max-w-[200px] truncate py-2 pr-3 font-mono text-slate-300">{c.target || "—"}</td>
                    <td className="py-2 pr-3">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                          c.status === "success"
                            ? "bg-emerald-500/15 text-emerald-400"
                            : c.status === "failed"
                              ? "bg-red-500/15 text-red-400"
                              : "bg-amber-500/15 text-amber-400"
                        }`}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="max-w-[220px] truncate py-2 pr-3 text-slate-500">{c.detail || "—"}</td>
                    <td className="py-2 text-slate-500">
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
      </Card>
    </div>
  );
}