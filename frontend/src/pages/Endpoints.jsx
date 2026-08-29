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

function Endpoints() {
  const [endpoints, setEndpoints] = useState([]);
  const [commands, setCommands] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [cmdAgent, setCmdAgent] = useState(null);
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [eps, cmds] = await Promise.allSettled([api.endpoints(), api.listCommands(30)]);
      setEndpoints(eps.status === "fulfilled" ? eps.value?.items || [] : []);
      setCommands(cmds.status === "fulfilled" ? cmds.value?.items || [] : []);
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

  const sendCommand = async () => {
    if (!cmdAgent) return;
    setBusy(`cmd:${cmdAgent}`);
    setError("");
    setMessage("");
    try {
      const res = await api.sendCommand(cmdAgent, cmdAction, cmdTarget.trim(), cmdNote.trim());
      setMessage(`Command #${res.id} queued for ${res.agent_id}`);
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

  if (loading) return <Loading label="Loading endpoints" />;

  const filtered = endpoints.filter((ep) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return ep.hostname?.toLowerCase().includes(q) || ep.agent_id?.toLowerCase().includes(q);
  });

  const onlineCount = endpoints.filter((ep) => Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000).length;

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Endpoints"
        subtitle="Remote agents, online status and the command channel"
      />

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Agents</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{endpoints.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Online</p>
          <p className="mt-1 text-2xl font-bold text-[var(--status-healthy)]">{onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Offline</p>
          <p className="mt-1 text-2xl font-bold text-[var(--severity-critical)]">{endpoints.length - onlineCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Commands</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{commands.length}</p>
        </Card>
      </div>

      {message && (
        <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">{message}</div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <SearchInput value={search} onChange={setSearch} placeholder="Search endpoints..." className="sm:w-80" />

      {/* Endpoints Grid */}
      {filtered.length === 0 ? (
        <Card>
          <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">
            No agents connected. Set one up from Agent Setup.
          </div>
        </Card>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((ep) => {
            const online = Date.now() - new Date(ep.last_seen).getTime() < 2 * 60 * 1000;
            return (
              <Card key={ep.agent_id} hover>
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-[13px] font-semibold text-[var(--fg-primary)]">{ep.hostname}</span>
                  <Badge severity={online ? "info" : "critical"} size="sm">{online ? "ONLINE" : "OFFLINE"}</Badge>
                </div>
                <p className="mt-1 truncate font-mono text-[10px] text-[var(--fg-muted)]">{ep.agent_id}</p>
                {ep.org && <Badge severity="low" size="sm">{ep.org}</Badge>}

                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--accent-cyan)]">{ep.records}</p>
                    <p className="text-[9px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">records</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--fg-primary)]">{ep.events}</p>
                    <p className="text-[9px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">events</p>
                  </div>
                  <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-2 py-1.5">
                    <p className="text-[12px] font-bold text-[var(--severity-high)]">{ep.alerts}</p>
                    <p className="text-[9px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">alerts</p>
                  </div>
                </div>

                <p className="mt-2 text-[10px] text-[var(--fg-muted)]">
                  Last seen {new Date(ep.last_seen).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </p>

                {cmdAgent === ep.agent_id ? (
                  <div className="mt-3 rounded-[var(--radius-lg)] border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/[0.04] p-3 space-y-2">
                    <select
                      value={cmdAction}
                      onChange={(e) => setCmdAction(e.target.value)}
                      className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[12px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40"
                    >
                      {ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
                    </select>
                    {cmdAction !== "escalate" && (
                      <input
                        value={cmdTarget}
                        onChange={(e) => setCmdTarget(e.target.value)}
                        placeholder="Target (IP, process, file path)"
                        className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 font-mono text-[11px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40"
                      />
                    )}
                    <input
                      value={cmdNote}
                      onChange={(e) => setCmdNote(e.target.value)}
                      placeholder="Note (optional)"
                      className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[12px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40"
                    />
                    <div className="flex gap-2">
                      <Button onClick={sendCommand} disabled={busy === `cmd:${ep.agent_id}`} size="xs" className="flex-1">
                        {busy === `cmd:${ep.agent_id}` ? "Sending..." : "Send"}
                      </Button>
                      <Button variant="ghost" size="xs" onClick={() => setCmdAgent(null)}>Cancel</Button>
                    </div>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => { setCmdAgent(ep.agent_id); setCmdAction("block_ip"); setCmdTarget(""); setCmdNote(""); }}
                    disabled={!online}
                    className="mt-3 w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 text-[11px] font-semibold text-[var(--fg-secondary)] transition-colors hover:border-[var(--accent-cyan)]/30 hover:text-[var(--accent-cyan)] disabled:opacity-40"
                  >
                    Send Command
                  </button>
                )}
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
                <tr>
                  <th>#</th>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Detail</th>
                  <th>Queued</th>
                </tr>
              </thead>
              <tbody>
                {commands.map((c) => (
                  <tr key={c.id}>
                    <td className="font-mono text-[11px] text-[var(--fg-muted)]">{c.id}</td>
                    <td className="font-mono text-[11px] text-[var(--fg-secondary)]">{c.agent_id}</td>
                    <td className="font-mono text-[11px] text-[var(--accent-cyan)]">{c.action}</td>
                    <td className="max-w-[200px] truncate font-mono text-[11px] text-[var(--fg-secondary)]">{c.target || "—"}</td>
                    <td><Badge severity={c.status === "success" ? "info" : c.status === "failed" ? "critical" : "medium"} size="sm">{c.status}</Badge></td>
                    <td className="max-w-[220px] truncate text-[11px] text-[var(--fg-muted)]">{c.detail || "—"}</td>
                    <td className="text-[11px] text-[var(--fg-muted)]">{new Date(c.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
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
