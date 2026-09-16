import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, Badge, Button, SearchInput } from "../components/ui/index.js";

const ACTIONS = [
  { id: "block_ip", label: "Block IP" },
  { id: "kill_process", label: "Kill Process" },
  { id: "quarantine", label: "Quarantine" },
  { id: "isolate", label: "Isolate Endpoint" },
  { id: "disable_account", label: "Disable Account" },
  { id: "escalate", label: "Escalate" },
];

function EndpointDetail({ endpoint, alerts, onClose, onSendCommand }) {
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const epAlerts = alerts.filter((a) =>
    a.source?.toLowerCase().includes(endpoint.hostname?.toLowerCase()) ||
    a.agent_id === endpoint.agent_id
  );

  const sendCommand = async () => {
    setBusy(true);
    try {
      await onSendCommand(endpoint.agent_id, cmdAction, cmdTarget.trim(), cmdNote.trim());
      setMessage("Command sent!");
      setCmdTarget("");
      setCmdNote("");
    } catch (e) {
      setMessage("Failed: " + e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5 pb-10">
      <div className="flex items-center gap-3">
        <button onClick={onClose} className="rounded-[var(--radius-md)] border border-[var(--border-subtle)] px-3 py-1.5 text-[12px] text-[var(--fg-secondary)] hover:text-[var(--accent-cyan)]">Back</button>
        <PageHeader title={endpoint.hostname} subtitle={`Agent: ${endpoint.agent_id}`} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Status</p>
          <p className={`mt-1 text-2xl font-bold ${Date.now() - new Date(endpoint.last_seen).getTime() < 2 * 60 * 1000 ? "text-emerald-400" : "text-red-400"}`}>
            {Date.now() - new Date(endpoint.last_seen).getTime() < 2 * 60 * 1000 ? "ONLINE" : "OFFLINE"}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Records</p>
          <p className="mt-1 text-2xl font-bold text-cyan-400">{endpoint.records || 0}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Events</p>
          <p className="mt-1 text-2xl font-bold text-blue-400">{endpoint.events || 0}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Alerts</p>
          <p className="mt-1 text-2xl font-bold text-orange-400">{endpoint.alerts || 0}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Department</p>
          <p className="mt-1 text-2xl font-bold text-violet-400">{endpoint.org || "N/A"}</p>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <h3 className="text-[14px] font-semibold text-slate-200 mb-3">Quick Actions</h3>
        <div className="grid grid-cols-3 gap-2">
          <select value={cmdAction} onChange={(e) => setCmdAction(e.target.value)}
            className="rounded-[var(--radius-md)] border border-slate-600 bg-slate-800 px-3 py-2 text-[12px] text-white outline-none">
            {ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
          <input value={cmdTarget} onChange={(e) => setCmdTarget(e.target.value)}
            placeholder="Target (IP, process, file)"
            className="rounded-[var(--radius-md)] border border-slate-600 bg-slate-800 px-3 py-2 text-[12px] text-white outline-none" />
          <input value={cmdNote} onChange={(e) => setCmdNote(e.target.value)}
            placeholder="Note (optional)"
            className="rounded-[var(--radius-md)] border border-slate-600 bg-slate-800 px-3 py-2 text-[12px] text-white outline-none" />
        </div>
        <button onClick={sendCommand} disabled={busy}
          className="mt-3 rounded-[var(--radius-md)] bg-cyan-600 px-4 py-2 text-[12px] font-semibold text-white hover:bg-cyan-500 disabled:opacity-50">
          {busy ? "Sending..." : "Send Command"}
        </button>
        {message && <p className="mt-2 text-[12px] text-emerald-400">{message}</p>}
      </Card>

      {/* Alerts from this agent */}
      <Card padding={false}>
        <div className="px-5 pt-4 pb-3">
          <h3 className="text-[14px] font-semibold text-slate-200">Alerts from this Endpoint</h3>
          <p className="mt-0.5 text-[11px] text-slate-400">{epAlerts.length} alert{epAlerts.length === 1 ? "" : "s"}</p>
        </div>
        {epAlerts.length === 0 ? (
          <div className="py-12 text-center text-[13px] text-slate-500">No alerts from this endpoint</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-t border-slate-700/50">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Severity</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Rule</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Source</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Time</th>
                </tr>
              </thead>
              <tbody>
                {epAlerts.slice(0, 20).map((a, i) => (
                  <tr key={a.id || i} className="border-t border-slate-700/30 hover:bg-slate-800/30">
                    <td className="px-5 py-2.5">
                      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase ${
                        a.severity === "critical" ? "border-red-500/30 text-red-400" :
                        a.severity === "high" ? "border-orange-500/30 text-orange-400" :
                        a.severity === "medium" ? "border-blue-400/30 text-blue-400" :
                        "border-slate-500/30 text-slate-400"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          a.severity === "critical" ? "bg-red-400" :
                          a.severity === "high" ? "bg-orange-400" :
                          a.severity === "medium" ? "bg-blue-400" :
                          "bg-slate-400"
                        }`} />
                        {a.severity}
                      </span>
                    </td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-slate-200">{a.rule_name || a.rule || "—"}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-slate-400">{a.source || "—"}</td>
                    <td className="px-5 py-2.5 text-[11px] text-slate-400">{new Date(a.timestamp || a.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
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

function Endpoints() {
  const [endpoints, setEndpoints] = useState([]);
  const [commands, setCommands] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [cmdAgent, setCmdAgent] = useState(null);
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [eps, cmds, alts] = await Promise.allSettled([
        api.endpoints(),
        api.listCommands(30),
        api.get ? api.get("/api/alerts?limit=200") : Promise.resolve({ items: [] }),
      ]);
      setEndpoints(eps.status === "fulfilled" ? eps.value?.items || [] : []);
      setCommands(cmds.status === "fulfilled" ? cmds.value?.items || [] : []);
      setAlerts(alts.status === "fulfilled" ? alts.value?.items || alts.value || [] : []);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10000);
    return () => clearInterval(t);
  }, [refresh]);

  const sendCommand = async (agentId, action, target, note) => {
    const res = await api.sendCommand(agentId, action, target, note);
    refresh();
    return res;
  };

  if (loading) return <Loading label="Loading endpoints" />;

  if (selectedEndpoint) {
    const ep = endpoints.find((e) => e.agent_id === selectedEndpoint);
    if (ep) {
      return <EndpointDetail endpoint={ep} alerts={alerts} onClose={() => setSelectedEndpoint(null)} onSendCommand={sendCommand} />;
    }
  }

  const filtered = endpoints.filter((ep) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return ep.hostname?.toLowerCase().includes(q) || ep.agent_id?.toLowerCase().includes(q) || ep.org?.toLowerCase().includes(q);
  });

  const onlineCount = endpoints.filter((ep) => Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000).length;
  const totalRecords = endpoints.reduce((sum, ep) => sum + (ep.records || 0), 0);
  const totalAlerts = endpoints.reduce((sum, ep) => sum + (ep.alerts || 0), 0);

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Agent Fleet"
        subtitle="Monitor and control all endpoints across departments"
      />

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Total Agents</p>
          <p className="mt-1 text-2xl font-bold text-white">{endpoints.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Online</p>
          <p className="mt-1 text-2xl font-bold text-emerald-400">{onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Offline</p>
          <p className="mt-1 text-2xl font-bold text-red-400">{endpoints.length - onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Total Records</p>
          <p className="mt-1 text-2xl font-bold text-cyan-400">{totalRecords}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Total Alerts</p>
          <p className="mt-1 text-2xl font-bold text-orange-400">{totalAlerts}</p>
        </Card>
      </div>

      {message && (
        <div className="rounded-[var(--radius-lg)] border border-emerald-500/25 bg-emerald-500/[0.06] p-3 text-[12px] text-emerald-400">{message}</div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <SearchInput value={search} onChange={setSearch} placeholder="Search by hostname, agent ID, or department..." className="sm:w-96" />

      {/* Endpoints Grid */}
      {filtered.length === 0 ? (
        <Card>
          <div className="py-12 text-center text-[13px] text-slate-500">
            No agents connected. Deploy an agent using the deployment guide.
          </div>
        </Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((ep) => {
            const online = Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000;
            return (
              <Card key={ep.agent_id} hover onClick={() => setSelectedEndpoint(ep.agent_id)} className="cursor-pointer">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-[13px] font-semibold text-white">{ep.hostname}</span>
                  <Badge severity={online ? "info" : "critical"} size="sm">{online ? "ONLINE" : "OFFLINE"}</Badge>
                </div>
                <p className="mt-1 truncate font-mono text-[10px] text-slate-400">{ep.agent_id}</p>
                {ep.org && <Badge severity="low" size="sm">{ep.org}</Badge>}

                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-[var(--radius-md)] bg-slate-800/50 px-2 py-1.5">
                    <p className="text-[12px] font-bold text-cyan-400">{ep.records || 0}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">records</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-slate-800/50 px-2 py-1.5">
                    <p className="text-[12px] font-bold text-blue-400">{ep.events || 0}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">events</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-slate-800/50 px-2 py-1.5">
                    <p className="text-[12px] font-bold text-orange-400">{ep.alerts || 0}</p>
                    <p className="text-[9px] uppercase tracking-wider text-slate-500">alerts</p>
                  </div>
                </div>

                <p className="mt-2 text-[10px] text-slate-500">
                  Last seen {new Date(ep.last_seen).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </p>

                <p className="mt-2 text-center text-[10px] text-cyan-500/60">Click to view details</p>
              </Card>
            );
          })}
        </div>
      )}

      {/* Command History */}
      <Card padding={false}>
        <div className="px-5 pt-4 pb-3">
          <h3 className="text-[14px] font-semibold text-slate-200">Command History</h3>
          <p className="mt-0.5 text-[11px] text-slate-400">{commands.length} command{commands.length === 1 ? "" : "s"}</p>
        </div>
        {commands.length === 0 ? (
          <div className="py-12 text-center text-[13px] text-slate-500">No commands issued</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-t border-slate-700/50">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">#</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Agent</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Action</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Target</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Status</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Detail</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Queued</th>
                </tr>
              </thead>
              <tbody>
                {commands.map((c) => (
                  <tr key={c.id} className="border-t border-slate-700/30 hover:bg-slate-800/30">
                    <td className="px-5 py-2.5 font-mono text-[11px] text-slate-400">{c.id}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-slate-300">{c.agent_id}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-cyan-400">{c.action}</td>
                    <td className="max-w-[200px] truncate px-5 py-2.5 font-mono text-[11px] text-slate-300">{c.target || "—"}</td>
                    <td className="px-5 py-2.5"><Badge severity={c.status === "success" ? "info" : c.status === "failed" ? "critical" : "medium"} size="sm">{c.status}</Badge></td>
                    <td className="max-w-[220px] truncate px-5 py-2.5 text-[11px] text-slate-400">{c.detail || "—"}</td>
                    <td className="px-5 py-2.5 text-[11px] text-slate-400">{new Date(c.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
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

export default memo(Endpoints);
