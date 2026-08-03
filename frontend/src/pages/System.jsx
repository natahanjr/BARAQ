import { useEffect, useState } from "react";
import { api } from "../api.js";
import StatCard from "../components/StatCard.jsx";
import { Loading } from "../components/Feedback.jsx";

function ResultBox({ result }) {
  if (!result) return null;
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
      <h3 className="mb-2 text-sm font-semibold text-slate-300">Pipeline result</h3>
      <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 md:grid-cols-4">
        <p>Collected: <span className="font-mono text-slate-200">{result.collected}</span></p>
        <p>Events: <span className="font-mono text-slate-200">{result.saved_events}</span></p>
        <p>Processes: <span className="font-mono text-slate-200">{result.saved_processes}</span></p>
        <p>Connections: <span className="font-mono text-slate-200">{result.saved_connections}</span></p>
        <p>Findings: <span className="font-mono text-slate-200">{result.findings?.length ?? 0}</span></p>
        <p className="col-span-2">Alerts created: <span className="font-mono text-amber-300">{result.alerts_created}</span></p>
      </div>
      {result.findings?.length > 0 && (
        <div className="mt-3 max-h-48 space-y-1 overflow-y-auto">
          {result.findings.map((f, i) => (
            <p key={i} className="rounded bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-400">
              {f.rule} → {f.mitre_id} ({f.mitre_tactic}) · {f.severity} · score {f.score}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

export default function System() {
  const [status, setStatus] = useState(null);
  const [ml, setMl] = useState(null);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = () => {
    api.systemStatus().then(setStatus).catch(() => {});
    api.mlStatus().then(setMl).catch(() => {});
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

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Application" value={status.application} sub={`v${status.version}`} accent="text-cyan-400" />
        <StatCard label="Database" value={status.database} sub="local SQLite" accent="text-slate-100" />
        <StatCard label="Collection" value={status.collecting ? "ACTIVE" : "IDLE"} sub="15s scheduler" accent={status.collecting ? "text-emerald-400" : "text-red-400"} />
        <StatCard label="Uptime" value={`${Math.floor((status.uptime_seconds || 0) / 60)} min`} sub={`${status.uptime_seconds ?? 0}s`} accent="text-slate-100" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-300">Live collection</h2>
          <p className="mt-1 text-xs text-slate-500">
            Collect real host telemetry from the live system for the detection pipeline.
          </p>
          <div className="mt-4 grid gap-2">
            <button
              onClick={() => run("collect")}
              disabled={!!busy}
              className="rounded-md bg-slate-700 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-600 disabled:opacity-40"
            >
              {busy === "collect" ? "Collecting..." : "◉ Collect live host data"}
            </button>
          </div>
          {message && <p className="mt-3 text-xs text-emerald-300">{message}</p>}
          {error && <p className="mt-3 text-xs text-red-300">{error}</p>}
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-300">Machine learning (Isolation Forest)</h2>
          {ml && (
            <div className="mt-3 space-y-2 text-xs text-slate-400">
              <p>Trained: <span className={ml.trained ? "text-emerald-300" : "text-amber-300"}>{ml.ready ? "yes" : "no"}</span></p>
              <p>Samples: <span className="font-mono text-slate-200">{ml.samples ?? "—"}</span></p>
              <p>Behavior streams: <span className="font-mono text-slate-200">{(ml.streams ?? []).join(", ") || "—"}</span></p>
              <p>Supervised model: <span className="font-mono text-slate-200">{ml.supervised ?? "—"}</span></p>
              <p>XGBoost available: <span className={ml.has_xgboost ? "text-emerald-300" : "text-slate-500"}>{ml.has_xgboost ? "yes" : "no (sklearn fallback)"}</span></p>
            </div>
          )}
          <div className="mt-4 grid gap-2">
            <button
              onClick={() => run("mlTrain")}
              disabled={!!busy}
              className="rounded-md bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-40"
            >
              {busy === "mlTrain" ? "Training..." : "◈ Train model"}
            </button>
            <button
              onClick={() => run("mlAnalyze")}
              disabled={!!busy}
              className="rounded-md bg-slate-700 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-600 disabled:opacity-40"
            >
              {busy === "mlAnalyze" ? "Analyzing..." : "◈ Analyze recent events"}
            </button>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="text-sm font-semibold text-slate-300">Current KPIs</h2>
          <div className="mt-3 space-y-1.5 text-xs">
            {[
              ["Security score", summary.security_score, "text-cyan-300"],
              ["Total events", summary.total_events, "text-slate-200"],
              ["Active alerts", summary.active_alerts, "text-amber-300"],
              ["Critical threats", summary.critical_threats, "text-red-300"],
              ["Anomalies (ML)", summary.anomalies_detected, "text-violet-300"],
              ["Events last hour", summary.events_last_hour, "text-slate-200"],
              ["System status", summary.system_status, "text-emerald-300"],
            ].map(([k, v, c]) => (
              <div key={k} className="flex justify-between rounded bg-slate-950/50 px-3 py-1.5">
                <span className="text-slate-500">{k}</span>
                <span className={`font-mono font-semibold ${c}`}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <ResultBox result={result} />
    </div>
  );
}
