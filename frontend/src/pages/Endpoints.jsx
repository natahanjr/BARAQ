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

function EndpointDetail({ endpoint, alerts, commands, onClose, onSendCommand }) {
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const hostname = endpoint.host || endpoint.hostname || endpoint.agent_id;
  const records = endpoint.records_total ?? endpoint.records ?? 0;
  const events = endpoint.events_total ?? endpoint.events ?? 0;
  const alertsCount = endpoint.alerts_total ?? endpoint.alerts ?? 0;
  const online = Date.now() - new Date(endpoint.last_seen).getTime() < 2 * 60 * 1000;

  const epAlerts = alerts.filter((a) => {
    const src = (a.source || "").toLowerCase();
    const host = hostname.toLowerCase();
    const aid = (endpoint.agent_id || "").toLowerCase();
    return src.includes(host) || src.includes(aid) || (a.agent_id || "").toLowerCase() === aid;
  });

  const epCommands = commands.filter((c) => c.agent_id === endpoint.agent_id);

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
        <div>
          <h1 className="text-[20px] font-bold text-[var(--fg-primary)]">{hostname}</h1>
          <p className="text-[12px] text-[var(--fg-muted)]">Agent: {endpoint.agent_id} | Org: {endpoint.org || "N/A"}</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Status</p>
          <p className={`mt-1 text-2xl font-bold ${online ? "text-[var(--status-healthy)]" : "text-[var(--severity-critical)]"}`}>
            {online ? "ONLINE" : "OFFLINE"}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Records</p>
          <p className="mt-1 text-2xl font-bold text-[var(--accent-cyan)]">{records}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Events</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{events}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Alerts</p>
          <p className="mt-1 text-2xl font-bold text-[var(--severity-high)]">{alertsCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">OS</p>
          <p className="mt-1 text-[14px] font-bold text-[var(--fg-primary)] truncate">{endpoint.os_info || "Windows"}</p>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <h3 className="text-[14px] font-semibold text-[var(--fg-primary)] mb-3">Send Command</h3>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <select value={cmdAction} onChange={(e) => setCmdAction(e.target.value)}
            className="rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[12px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40">
            {ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
          <input value={cmdTarget} onChange={(e) => setCmdTarget(e.target.value)}
            placeholder="Target (IP, process, file)"
            className="rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[12px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
          <input value={cmdNote} onChange={(e) => setCmdNote(e.target.value)}
            placeholder="Note (optional)"
            className="rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[12px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
        </div>
        <button onClick={sendCommand} disabled={busy || !online}
          className="mt-3 rounded-[var(--radius-md)] bg-[var(--accent-cyan)] px-4 py-2 text-[12px] font-semibold text-white hover:opacity-90 disabled:opacity-40">
          {busy ? "Sending..." : "Send Command"}
        </button>
        {message && <p className="mt-2 text-[12px] text-[var(--status-healthy)]">{message}</p>}
      </Card>

      {/* Alerts from this agent */}
      <Card padding={false}>
        <div className="px-5 pt-4 pb-3">
          <h3 className="text-[14px] font-semibold text-[var(--fg-primary)]">Alerts from this Endpoint</h3>
          <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{epAlerts.length} alert{epAlerts.length === 1 ? "" : "s"}</p>
        </div>
        {epAlerts.length === 0 ? (
          <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No alerts from this endpoint</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-t border-[var(--border-subtle)]">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Severity</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Rule</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Source</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Time</th>
                </tr>
              </thead>
              <tbody>
                {epAlerts.slice(0, 20).map((a, i) => (
                  <tr key={a.id || i} className="border-t border-[var(--border-subtle)]/50 hover:bg-[var(--bg-inset)]">
                    <td className="px-5 py-2.5">
                      <Badge severity={a.severity || "info"} size="sm">{a.severity || "info"}</Badge>
                    </td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--fg-primary)]">{a.rule_name || a.rule || "—"}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--fg-muted)]">{a.source || "—"}</td>
                    <td className="px-5 py-2.5 text-[11px] text-[var(--fg-muted)]">{new Date(a.timestamp || a.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Command History for this agent */}
      <Card padding={false}>
        <div className="px-5 pt-4 pb-3">
          <h3 className="text-[14px] font-semibold text-[var(--fg-primary)]">Commands Sent to this Endpoint</h3>
          <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{epCommands.length} command{epCommands.length === 1 ? "" : "s"}</p>
        </div>
        {epCommands.length === 0 ? (
          <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No commands sent</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-t border-[var(--border-subtle)]">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Action</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Target</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Status</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Time</th>
                </tr>
              </thead>
              <tbody>
                {epCommands.map((c) => (
                  <tr key={c.id} className="border-t border-[var(--border-subtle)]/50 hover:bg-[var(--bg-inset)]">
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--accent-cyan)]">{c.action}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--fg-secondary)]">{c.target || "—"}</td>
                    <td className="px-5 py-2.5"><Badge severity={c.status === "success" ? "info" : c.status === "failed" ? "critical" : "medium"} size="sm">{c.status}</Badge></td>
                    <td className="px-5 py-2.5 text-[11px] text-[var(--fg-muted)]">{new Date(c.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
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
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [selected, setSelected] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [eps, cmds, alts] = await Promise.allSettled([
        api.endpoints(),
        api.listCommands(30),
        api.get("/api/alerts?limit=200"),
      ]);
      setEndpoints(eps.status === "fulfilled" ? eps.value?.items || [] : []);
      setCommands(cmds.status === "fulfilled" ? cmds.value?.items || [] : []);
      setAlerts(alts.status === "fulfilled" ? (alts.value?.items || alts.value || []) : []);
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

  if (selected) {
    const ep = endpoints.find((e) => e.agent_id === selected);
    if (ep) {
      return <EndpointDetail endpoint={ep} alerts={alerts} commands={commands} onClose={() => setSelected(null)} onSendCommand={sendCommand} />;
    }
  }

  const filtered = endpoints.filter((ep) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (ep.host || "").toLowerCase().includes(q) || (ep.agent_id || "").toLowerCase().includes(q) || (ep.org || "").toLowerCase().includes(q);
  });

  const onlineCount = endpoints.filter((ep) => Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000).length;
  const totalRecords = endpoints.reduce((sum, ep) => sum + (ep.records_total ?? 0), 0);
  const totalAlerts = endpoints.reduce((sum, ep) => sum + (ep.alerts_total ?? 0), 0);

  return (
    <div className="space-y-5 pb-10">
      <PageHeader title="Agent Fleet" subtitle="Monitor and control all endpoints across departments" />

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Total Agents</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{endpoints.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Online</p>
          <p className="mt-1 text-2xl font-bold text-[var(--status-healthy)]">{onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Offline</p>
          <p className="mt-1 text-2xl font-bold text-[var(--severity-critical)]">{endpoints.length - onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Total Records</p>
          <p className="mt-1 text-2xl font-bold text-[var(--accent-cyan)]">{totalRecords}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Total Alerts</p>
          <p className="mt-1 text-2xl font-bold text-[var(--severity-high)]">{totalAlerts}</p>
        </Card>
      </div>

      {message && (
        <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">{message}</div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <SearchInput value={search} onChange={setSearch} placeholder="Search by hostname, agent ID, or department..." className="sm:w-96" />

      {/* Endpoints Grid */}
      {filtered.length === 0 ? (
        <Card>
          <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">
            No agents connected. Deploy an agent using the deployment guide.
          </div>
        </Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((ep) => {
            const online = Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000;
            const hostname = ep.host || ep.agent_id;
            const records = ep.records_total ?? 0;
            const events = ep.events_total ?? 0;
            const alertsCount = ep.alerts_total ?? 0;
            return (
              <Card
                key={ep.agent_id}
                hover
                className="cursor-pointer"
                onClick={() => setSelected(ep.agent_id)}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-[13px] font-semibold text-[var(--fg-primary)]">{hostname}</span>
                  <Badge severity={online ? "info" : "critical"} size="sm">{online ? "ONLINE" : "OFFLINE"}</Badge>
                </div>
                <p className="mt-1 truncate font-mono text-[10px] text-[var(--fg-muted)]">{ep.agent_id}</p>
                {ep.org && <span className="mt-1 inline-block rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2 py-0.5 text-[10px] text-[var(--fg-muted)]">{ep.org}</span>}

                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--accent-cyan)]">{records}</p>
                    <p className="text-[9px] uppercase tracking-wider text-[var(--fg-muted)]">records</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--fg-primary)]">{events}</p>
                    <p className="text-[9px] uppercase tracking-wider text-[var(--fg-muted)]">events</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--severity-high)]">{alertsCount}</p>
                    <p className="text-[9px] uppercase tracking-wider text-[var(--fg-muted)]">alerts</p>
                  </div>
                </div>

                <div className="mt-2 flex items-center justify-between">
                  <p className="text-[10px] text-[var(--fg-muted)]">
                    Last seen {new Date(ep.last_seen).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </p>
                  <p className="text-[10px] text-[var(--accent-cyan)] opacity-60">Click to view details</p>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Command History */}
      <Card padding={false}>
        <div className="px-5 pt-4 pb-3">
          <h3 className="text-[14px] font-semibold text-[var(--fg-primary)]">Command History</h3>
          <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{commands.length} command{commands.length === 1 ? "" : "s"}</p>
        </div>
        {commands.length === 0 ? (
          <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No commands issued</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-t border-[var(--border-subtle)]">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">#</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Agent</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Action</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Target</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Status</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Detail</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Queued</th>
                </tr>
              </thead>
              <tbody>
                {commands.map((c) => (
                  <tr key={c.id} className="border-t border-[var(--border-subtle)]/50 hover:bg-[var(--bg-inset)]">
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--fg-muted)]">{c.id}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--fg-secondary)]">{c.agent_id}</td>
                    <td className="px-5 py-2.5 font-mono text-[11px] text-[var(--accent-cyan)]">{c.action}</td>
                    <td className="max-w-[200px] truncate px-5 py-2.5 font-mono text-[11px] text-[var(--fg-secondary)]">{c.target || "—"}</td>
                    <td className="px-5 py-2.5"><Badge severity={c.status === "success" ? "info" : c.status === "failed" ? "critical" : "medium"} size="sm">{c.status}</Badge></td>
                    <td className="max-w-[220px] truncate px-5 py-2.5 text-[11px] text-[var(--fg-muted)]">{c.detail || "—"}</td>
                    <td className="px-5 py-2.5 text-[11px] text-[var(--fg-muted)]">{new Date(c.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
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
