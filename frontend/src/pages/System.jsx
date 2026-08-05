import { useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import StatCard from "../components/StatCard.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { RefreshIcon } from "../components/icons.jsx";

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
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = () => {
    api.systemStatus().then(setStatus).catch(() => {});
    api.mlStatus().then(setMl).catch(() => {});
    api.endpoints().then((r) => setEndpoints(r.items || [])).catch(() => {});
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

  if (!status) return <Loading label="Loading system status" />;

  const summary = status.summary || {};
  const trained = Boolean(ml?.ready);

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="System Control"
        subtitle="Manage collection, ML training, and system operations"
        actions={
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-800/60 px-3.5 py-2 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700/60"
          >
            <RefreshIcon className="h-4 w-4" />
            Refresh
          </button>
        }
      />

      {/* Status cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Application" value={status.application} sub={`v${status.version}`} accent="text-cyan-400" />
        <StatCard label="Database" value={status.database} sub="local SQLite" accent="text-slate-100" />
        <StatCard
          label="Collection"
          value={status.collecting ? "ACTIVE" : "IDLE"}
          sub="15s scheduler"
          accent={status.collecting ? "text-emerald-400" : "text-red-400"}
        />
        <StatCard
          label="Uptime"
          value={`${Math.floor((status.uptime_seconds || 0) / 60)} min`}
          sub={`${status.uptime_seconds ?? 0}s elapsed`}
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
                <span className={`h-1.5 w-1.5 rounded-full ${trained ? "bg-emerald-400" : "bg-amber-400"}`} />
                Trained
              </span>
              <span className={`font-semibold ${trained ? "text-emerald-400" : "text-amber-400"}`}>
                {trained ? "yes" : "no"}
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
          </div>

          <div className="mt-5 grid gap-2">
            <ActionButton busy={busy} kind="mlTrain" onClick={() => run("mlTrain")} variant="ml">
              Train Model
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
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <ResultBox result={result} />
    </div>
  );
}
