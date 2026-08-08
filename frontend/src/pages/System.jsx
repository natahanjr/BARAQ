import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import StatCard from "../components/StatCard.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const ACTION_STYLES = {
  primary: "bg-gradient-to-r from-cyan-600 to-cyan-500 text-white hover:from-cyan-500 hover:to-cyan-400",
  secondary: "border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700",
  ml: "bg-gradient-to-r from-violet-600 to-violet-500 text-white hover:from-violet-500 hover:to-violet-400",
};

function ActionButton({ busy, kind, onClick, children, variant = "primary" }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!!busy}
      className={`w-full rounded-lg px-4 py-2.5 text-sm font-semibold transition-all disabled:opacity-50 ${
        ACTION_STYLES[variant]
      }`}
    >
      {busy === kind ? "Processing..." : children}
    </button>
  );
}

function formatUptime(totalSeconds) {
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = Math.floor(totalSeconds % 60);
  const pad = (n) => String(n).padStart(2, "0");
  return d > 0
    ? `${d}d ${pad(h)}h ${pad(m)}m ${pad(s)}s`
    : `${pad(h)}:${pad(m)}:${pad(s)}`;
}

function UptimeTimer({ uptimeSeconds }) {
  const [now, setNow] = useState(Date.now());
  const bootRef = useRef(null);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  //: Latch the earliest observed boot time so status polls can never rewind
  //: the counter; it only advances (or holds if the server restarts).
  useEffect(() => {
    if (bootRef.current === null) {
      bootRef.current = Date.now() - (uptimeSeconds || 0) * 1000;
      return;
    }
    const candidate = Date.now() - (uptimeSeconds || 0) * 1000;
    if (candidate < bootRef.current) bootRef.current = candidate;
  }, [uptimeSeconds]);
  const bootedAt = bootRef.current ?? Date.now() - (uptimeSeconds || 0) * 1000;
  const elapsed = Math.max(0, Math.floor((now - bootedAt) / 1000));
  return (
    <span className="font-mono tabular-nums" title={`${elapsed}s elapsed`}>
      {formatUptime(elapsed)}
    </span>
  );
}

function ResultBox({ result }) {
  if (!result) return null;
  return (
    <Card tone="emerald">
      <h3 className="mb-4 text-base font-semibold text-white">Pipeline Result</h3>
      <div className="grid grid-cols-2 gap-3 text-sm text-slate-400 md:grid-cols-4">
        <div className="rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Collected</p>
          <p className="mt-1 font-mono text-xl font-bold text-cyan-400">{result.collected}</p>
        </div>
        <div className="rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Events</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_events}</p>
        </div>
        <div className="rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Processes</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_processes}</p>
        </div>
        <div className="rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Connections</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_connections}</p>
        </div>
        <div className="rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Findings</p>
          <p className="mt-1 font-mono text-xl font-bold text-amber-400">{result.findings?.length ?? 0}</p>
        </div>
        <div className="col-span-2 rounded-lg bg-slate-800/40 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Alerts Created</p>
          <p className="mt-1 font-mono text-xl font-bold text-red-400">{result.alerts_created}</p>
        </div>
      </div>
      {result.findings?.length > 0 && (
        <div className="mt-4 max-h-48 space-y-1 overflow-y-auto">
          {result.findings.map((f, i) => (
            <p
              key={i}
              className="rounded-lg border border-slate-800/50 bg-slate-900/60 px-3 py-2 font-mono text-[11px] text-slate-400"
            >
              {f.rule} → {f.mitre_id} ({f.mitre_tactic}) · {f.severity} · score {f.score}
            </p>
          ))}
        </div>
      )}
    </Card>
  );
}

function KpiRow({ label, value, color }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-slate-800/50 bg-slate-900/50 px-3 py-2">
      <span className="text-xs text-slate-400">{label}</span>
      <span className={`text-xs font-semibold ${color}`}>{value ?? "—"}</span>
    </div>
  );
}

export default function System() {
  const [status, setStatus] = useState(null);
  const [ml, setMl] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [commands, setCommands] = useState([]);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [cmdAgent, setCmdAgent] = useState(null);
  const [cmdAction, setCmdAction] = useState("block_ip");
  const [cmdTarget, setCmdTarget] = useState("");
  const [cmdNote, setCmdNote] = useState("");

  const refresh = async () => {
    const [st, ml, eps, cmds] = await Promise.allSettled([
      api.systemStatus(),
      api.mlStatus(),
      api.endpoints(),
      api.listCommands(30),
    ]);
    setStatus(st.status === "fulfilled" ? st.value : status);
    setMl(ml.status === "fulfilled" ? ml.value : ml);
    setEndpoints(eps.status === "fulfilled" ? eps.value.items || [] : endpoints);
    setCommands(cmds.status === "fulfilled" ? cmds.value.items || [] : commands);
    if (st.status !== "fulfilled") setError(st.reason.message);
  };
  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10000);
    return () => clearInterval(t);
  }, []);

  const run = async (kind, body) => {
    setBusy(kind);
    setError("");
    setMessage("");
    setResult(null);
    try {
      const res = await api[kind](body ?? undefined);
      setResult(res.pipeline ?? res);
      setMessage(res.message ?? "Done");
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const trainMl = async () => {
    setBusy("mlTrain");
    setError("");
    setMessage("");
    setResult(null);
    try {
      const res = await api.mlTrain({ force: true, sync: true });
      setResult(null);
      setMessage(
        res.trained === false && res.status === "kept-existing"
          ? "Models unchanged (no improvement)"
          : res.status === "ok"
            ? `Trained on ${res.samples ?? "?"} samples · streams ${(res.streams ?? []).join(", ")}`
            : res.message ?? "Done"
      );
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const sendCommand = async () => {
    if (!cmdAgent) return;
    setBusy(`cmd:${cmdAgent}`);
    setError("");
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

  if (!status) return <Loading label="Loading system status" />;

  const summary = status.summary || {};
  const trained = Boolean(ml?.ready);

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="System Control"
        subtitle="Manage collection, ML training, and system operations"
      />

      {/* Status cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Application" value={status.application} sub={`v${status.version}`} accent="text-cyan-400" />
        <StatCard
          label="Database"
          value={status.database?.includes("postgres") ? "PostgreSQL + psycopg3" : "SQLite"}
          sub={status.database?.includes("postgres") ? "psycopg3 (not psycopg2)" : "local SQLite"}          accent="text-slate-100"
        />
        <StatCard
          label="Collection"
          value={status.collecting ? "ACTIVE" : "IDLE"}
          sub="15s scheduler"
          accent={status.collecting ? "text-emerald-400" : "text-red-400"}
        />
        <StatCard
          label="Uptime"
          value={<UptimeTimer uptimeSeconds={status.uptime_seconds || 0} />}
          sub="live timer · d h m s"
          accent="text-slate-100"
        />
      </div>

      {message && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          ✓ {message}
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Live collection */}
        <Card>
          <h3 className="text-base font-semibold text-white">Live Collection</h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            Collect real host telemetry from the live system and push it through the detection
            pipeline.
          </p>
          <div className="mt-5">
            <ActionButton busy={busy} kind="collect" onClick={() => run("collect")} variant="primary">
              Collect Live Host Data
            </ActionButton>
          </div>
        </Card>

        {/* ML training */}
        <Card tone="violet">
          <h3 className="text-base font-semibold text-white">Machine Learning</h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            Isolation Forest + supervised anomaly detection
          </p>

          <div className="mt-4 space-y-2 text-xs">
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="flex items-center gap-2 text-slate-400">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    trained ? (ml?.stale ? "bg-amber-400" : "bg-emerald-400") : "bg-red-400"
                  }`}
                />
                {trained ? (ml?.stale ? "Stale" : "Trained") : "Not trained"}
              </span>
              <span className={`font-semibold ${trained ? (ml?.stale ? "text-amber-400" : "text-emerald-400") : "text-red-400"}`}>
                {trained ? (ml?.stale ? "retrain" : "ready") : "no"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Samples</span>
              <span className="font-mono text-slate-200">{ml?.samples ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3 rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Streams</span>
              <span className="truncate font-mono text-slate-200">
                {(ml?.streams ?? []).join(", ") || "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Supervised</span>
              <span className="font-mono text-slate-200">{ml?.supervised ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Supervised streams</span>
              <span className="truncate font-mono text-slate-200">
                {ml?.supervised_streams && Object.keys(ml.supervised_streams).length > 0
                  ? Object.entries(ml.supervised_streams)
                      .map(([stream, name]) => `${stream}: ${name}`)
                      .join(", ")
                  : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Drift</span>
              <span className={`font-semibold ${ml?.drift ? "text-amber-400" : "text-emerald-400"}`}>
                {ml?.drift ? "drifted" : "clean"}
              </span>
            </div>
            {ml?.drift_reason && (
              <p className="rounded-lg bg-amber-500/10 px-3 py-1.5 text-[10px] text-amber-400">
                {ml.drift_reason}
              </p>
            )}
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Feature version</span>
              <span className="font-mono text-slate-200">v{ml?.feature_version ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
              <span className="text-slate-400">Persisted bundle</span>
              <span className={`font-semibold ${ml?.persisted ? "text-emerald-400" : "text-slate-500"}`}>
                {ml?.persisted ? "yes" : "no"}
              </span>
            </div>
            <div className="rounded-lg bg-slate-800/40 px-3 py-2">
              <p className="text-slate-400">Anomaly thresholds (deployed score)</p>
              <div className="mt-1.5 space-y-1">
                {(ml?.thresholds
                  ? Object.entries(ml.thresholds).filter(([, t]) => t !== undefined)
                  : []
                ).map(([stream, threshold]) => (
                  <div key={stream} className="flex items-center gap-2">
                    <span className="w-16 font-mono text-slate-500">{stream}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-900/70">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-violet-600 to-cyan-500"
                        style={{ width: `${Math.round(Number(threshold) * 100)}%` }}
                      />
                    </div>
                    <span className="w-12 text-right font-mono text-slate-300">{threshold}</span>
                  </div>
                ))}
              </div>
            </div>
            {ml?.staleness_reason && ml?.staleness_reason !== "fresh" && (
              <p className="rounded-lg bg-amber-500/10 px-3 py-1.5 text-[10px] text-amber-400">
                {ml.staleness_reason}
              </p>
            )}
            {ml?.trained_at && (
              <p className="text-right text-[10px] text-slate-500">
                trained {new Date(ml.trained_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
              </p>
            )}
          </div>

          <div className="mt-5 grid gap-2">
            <ActionButton busy={busy} kind="mlTrain" onClick={trainMl} variant="ml">
              Train Model (manual)
            </ActionButton>
            <ActionButton busy={busy} kind="mlAnalyze" onClick={() => run("mlAnalyze")} variant="secondary">
              Analyze Recent Events
            </ActionButton>
          </div>
        </Card>

        {/* KPIs */}
        <Card>
          <h3 className="mb-4 text-base font-semibold text-white">Current KPIs</h3>
          <div className="space-y-2">
            <KpiRow label="Security score" value={summary.security_score?.toFixed(1)} color="text-cyan-300" />
            <KpiRow label="Total events" value={summary.total_events?.toLocaleString()} color="text-slate-200" />
            <KpiRow label="Active alerts" value={summary.active_alerts} color="text-amber-300" />
            <KpiRow label="Critical threats" value={summary.critical_threats} color="text-red-300" />
            <KpiRow label="Anomalies (ML)" value={summary.anomalies_detected} color="text-violet-300" />
            <KpiRow label="Events last hour" value={summary.events_last_hour} color="text-slate-200" />
            <KpiRow label="System status" value={summary.system_status} color="text-emerald-300" />
          </div>
        </Card>
      </div>

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
            Remote agents ingest via <span className="font-mono text-cyan-500/80">POST /api/ingest</span> with an
            X-Agent-Key. See <span className="font-mono text-slate-400">scripts/agent.py</span>.
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

      <ResultBox result={result} />
    </div>
  );
}
