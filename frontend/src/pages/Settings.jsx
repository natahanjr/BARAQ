import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const inputCls =
  "w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10";

const ACTION_STYLES = {
  primary: "rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]",
  secondary: "rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-[13px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]",
  ml: "rounded-xl border border-violet-500/25 bg-violet-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-violet-400 transition-all hover:bg-violet-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(139,92,246,0.2)]",
};

function ActionButton({ busy, kind, onClick, children, variant = "primary" }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!!busy}
      className={`w-full rounded-xl px-4 py-2.5 text-[13px] font-semibold transition-all disabled:opacity-50 ${
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
    <div className="rounded-2xl border border-emerald-500/10 bg-emerald-500/[0.03] p-6">
      <h3 className="mb-4 text-[15px] font-semibold text-white">Pipeline Result</h3>
      <div className="grid grid-cols-2 gap-3 text-[13px] text-slate-400 md:grid-cols-4">
        <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Collected</p>
          <p className="mt-1 font-mono text-xl font-bold text-cyan-400">{result.collected}</p>
        </div>
        <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Events</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_events}</p>
        </div>
        <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Processes</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_processes}</p>
        </div>
        <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Connections</p>
          <p className="mt-1 font-mono text-xl font-bold text-slate-200">{result.saved_connections}</p>
        </div>
        <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Findings</p>
          <p className="mt-1 font-mono text-xl font-bold text-amber-400">{result.findings?.length ?? 0}</p>
        </div>
        <div className="col-span-2 rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
          <p className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">Alerts Created</p>
          <p className="mt-1 font-mono text-xl font-bold text-red-400">{result.alerts_created}</p>
        </div>
      </div>
      {result.findings?.length > 0 && (
        <div className="mt-4 max-h-48 space-y-1 overflow-y-auto">
          {result.findings.map((f, i) => (
            <p
              key={i}
              className="rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5 font-mono text-[13px] text-slate-400"
            >
              {f.rule} → {f.mitre_id} ({f.mitre_tactic}) · {f.severity} · score {f.score}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function KpiRow({ label, value, color }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
      <span className="text-[13px] text-slate-400">{label}</span>
      <span className={`text-[13px] font-semibold ${color}`}>{value ?? "—"}</span>
    </div>
  );
}

function SystemAdminPanel() {
  const [status, setStatus] = useState(null);
  const [ml, setMl] = useState(null);
  const [dq, setDq] = useState(null);
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = async () => {
    const [st, m, q] = await Promise.allSettled([api.systemStatus(), api.mlStatus(), api.dataQuality()]);
    setStatus(st.status === "fulfilled" ? st.value : status);
    setMl(m.status === "fulfilled" ? m.value : ml);
    setDq(q.status === "fulfilled" ? q.value : dq);
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

  const repairDataQuality = async () => {
    if (!window.confirm("Run the data-quality repair sequence now? It clears the Security/System event logs, restarts the EventLog service and retrains the ML models.")) return;
    setBusy("dataQualityRepair");
    setError("");
    setMessage("");
    setResult(null);
    try {
      const res = await api.dataQualityRepair({ reason: "manual (dashboard)" });
      setResult(res);
      setMessage(res.triggered === false ? "Repair skipped (cooldown active)" : "Repair sequence finished");
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
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5">
          <p className="text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">Application</p>
          <p className="mt-1 font-mono text-[15px] font-bold text-cyan-400">{status.application}</p>
          <p className="mt-0.5 text-[13px] text-slate-500">v{status.version}</p>
        </div>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5">
          <p className="text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">Database</p>
          <p className="mt-1 font-mono text-[15px] font-bold text-slate-100">{status.database?.includes("postgres") ? "PostgreSQL + psycopg3" : "SQLite"}</p>
          <p className="mt-0.5 text-[13px] text-slate-500">{status.database?.includes("postgres") ? "psycopg3 (not psycopg2)" : "local SQLite"}</p>
        </div>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5">
          <p className="text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">Collection</p>
          <p className={`mt-1 font-mono text-[15px] font-bold ${status.collecting ? "text-emerald-400" : "text-red-400"}`}>{status.collecting ? "ACTIVE" : "IDLE"}</p>
          <p className="mt-0.5 text-[13px] text-slate-500">15s scheduler</p>
        </div>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5">
          <p className="text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">Uptime</p>
          <p className="mt-1 font-mono text-[15px] font-bold text-slate-100"><UptimeTimer uptimeSeconds={status.uptime_seconds || 0} /></p>
          <p className="mt-0.5 text-[13px] text-slate-500">live timer · d h m s</p>
        </div>
      </div>

      {message && (
        <div className="rounded-xl border p-4 text-sm"
          style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }} style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
          ✓ {message}
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-1 text-[15px] font-semibold text-white">Live Collection</h3>
          <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
            Collect real host telemetry from the live system and push it through the detection
            pipeline.
          </p>
          <div className="mt-5">
            <ActionButton busy={busy} kind="collect" onClick={() => run("collect")} variant="primary">
              Collect Live Host Data
            </ActionButton>
          </div>
        </div>

        <div className="rounded-2xl border border-violet-500/10 bg-violet-500/[0.03] p-6">
          <h3 className="mb-1 text-[15px] font-semibold text-white">Machine Learning</h3>
          <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
            Isolation Forest + supervised anomaly detection
          </p>

          <div className="mt-4 space-y-2 text-[13px]">
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="flex items-center gap-2 text-slate-400">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    trained ? (ml?.stale ? "bg-amber-400" : "bg-emerald-400") : "bg-red-400"
                  } ${trained && !ml?.stale ? "shadow-[0_0_6px_rgba(16,185,129,0.5)]" : ""}`}
                />
                {trained ? (ml?.stale ? "Stale" : "Trained") : "Not trained"}
              </span>
              <span className={`font-semibold ${trained ? (ml?.stale ? "text-amber-400" : "text-emerald-400") : "text-red-400"}`}>
                {trained ? (ml?.stale ? "retrain" : "ready") : "no"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Samples</span>
              <span className="font-mono text-slate-200">{ml?.samples ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Streams</span>
              <span className="truncate font-mono text-slate-200">
                {(ml?.streams ?? []).join(", ") || "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Supervised</span>
              <span className="font-mono text-slate-200">{ml?.supervised ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Supervised streams</span>
              <span className="truncate font-mono text-slate-200">
                {ml?.supervised_streams && Object.keys(ml.supervised_streams).length > 0
                  ? Object.entries(ml.supervised_streams)
                      .map(([stream, name]) => `${stream}: ${name}`)
                      .join(", ")
                  : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Drift</span>
              <span className={`font-semibold ${ml?.drift ? "text-amber-400" : "text-emerald-400"}`}>
                {ml?.drift ? "drifted" : "clean"}
              </span>
            </div>
            {ml?.drift_reason && (
              <p className="rounded-xl border border-amber-500/20 bg-amber-500/[0.06] px-3.5 py-2 text-[13px] text-amber-400">
                {ml.drift_reason}
              </p>
            )}
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Feature version</span>
              <span className="font-mono text-slate-200">v{ml?.feature_version ?? "—"}</span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Persisted bundle</span>
              <span className={`font-semibold ${ml?.persisted ? "text-emerald-400" : "text-slate-500"}`}>
                {ml?.persisted ? "yes" : "no"}
              </span>
            </div>
            <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <p className="text-slate-400">Anomaly thresholds (deployed score)</p>
              <div className="mt-1.5 space-y-1.5">
                {(ml?.thresholds
                  ? Object.entries(ml.thresholds).filter(([, t]) => t !== undefined)
                  : []
                ).map(([stream, threshold]) => (
                  <div key={stream} className="flex items-center gap-2">
                    <span className="w-16 font-mono text-[13px] text-slate-500">{stream}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.04]">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-violet-600 to-cyan-500"
                        style={{ width: `${Math.round(Number(threshold) * 100)}%` }}
                      />
                    </div>
                    <span className="w-12 text-right font-mono text-[13px] text-slate-300">{threshold}</span>
                  </div>
                ))}
              </div>
            </div>
            {ml?.staleness_reason && ml?.staleness_reason !== "fresh" && (
              <p className="rounded-xl border border-amber-500/20 bg-amber-500/[0.06] px-3.5 py-2 text-[13px] text-amber-400">
                {ml.staleness_reason}
              </p>
            )}
            {ml?.trained_at && (
              <p className="text-right text-[13px] text-slate-500">
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
        </div>

        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-4 text-[15px] font-semibold text-white">Current KPIs</h3>
          <div className="space-y-2">
            <KpiRow label="Security score" value={summary.security_score?.toFixed(1)} color="text-cyan-300" />
            <KpiRow label="Total events" value={summary.total_events?.toLocaleString()} color="text-slate-200" />
            <KpiRow label="Active alerts" value={summary.active_alerts} color="text-amber-300" />
            <KpiRow label="Critical threats" value={summary.critical_threats} color="text-red-300" />
            <KpiRow label="Anomalies (ML)" value={summary.anomalies_detected} color="text-violet-300" />
            <KpiRow label="Events last hour" value={summary.events_last_hour} color="text-slate-200" />
            <KpiRow label="System status" value={summary.system_status} color="text-emerald-300" />
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-emerald-500/10 bg-emerald-500/[0.03] p-6">
          <h3 className="mb-1 text-[15px] font-semibold text-white">Data Quality</h3>
          <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
            Corrupted event-log values (truncated rendering debris) are discarded before
            detection so they can never create false-positive alerts.
          </p>

          <div className="mt-4 space-y-2 text-[13px]">
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Status</span>
              <span className={`font-semibold uppercase ${
                dq?.current?.status === "critical" ? "text-red-400"
                  : dq?.current?.status === "degraded" ? "text-orange-400"
                    : dq?.current?.status === "warning" ? "text-amber-400"
                      : "text-emerald-400"
              }`}>
                {dq?.current?.status ?? "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Corruption rate (window)</span>
              <span className="font-mono text-slate-200">
                {dq?.current?.corruption_rate != null ? `${(dq.current.corruption_rate * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <span className="text-slate-400">Valid / corrupted</span>
              <span className="font-mono text-slate-200">
                {dq?.current ? `${dq.current.valid} / ${dq.current.corrupted}` : "—"}
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.04]">
              <div
                className={`h-full rounded-full ${
                  dq?.current?.status === "critical" ? "bg-gradient-to-r from-rose-500 to-rose-400"
                    : dq?.current?.status === "degraded" ? "bg-gradient-to-r from-orange-500 to-orange-400"
                      : dq?.current?.status === "warning" ? "bg-gradient-to-r from-amber-400 to-amber-300"
                        : "bg-gradient-to-r from-emerald-500 to-emerald-400"
                }`}
                style={{ width: `${Math.min(100, (dq?.current?.corruption_rate ?? 0) * 100)}%` }}
              />
            </div>
            {dq?.current?.reasons && Object.keys(dq.current.reasons).length > 0 && (
              <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
                <p className="text-slate-400">Top corruption reasons</p>
                <ul className="mt-1 space-y-0.5 text-[13px] text-slate-300">
                  {Object.entries(dq.current.reasons)
                    .slice(0, 3)
                    .map(([reason, count]) => (
                      <li key={reason} className="flex justify-between gap-2">
                        <span className="truncate">{reason}</span>
                        <span className="font-mono text-slate-500">{count}</span>
                      </li>
                    ))}
                </ul>
              </div>
            )}
            {dq?.history && dq.history.length > 0 && (
              <p className="text-right text-[13px] text-slate-500">
                {dq.history.length} snapshot{(dq.history.length === 1 ? "" : "s")} ·{" "}
                {new Date(dq.history[dq.history.length - 1].sampled_at).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </p>
            )}
          </div>

          <div className="mt-5">
            <ActionButton busy={busy} kind="dataQualityRepair" onClick={repairDataQuality} variant="secondary">
              Run Repair Sequence
            </ActionButton>
          </div>
        </div>
      </div>

      <ResultBox result={result} />
    </div>
  );
}

function TuningPanel() {
  const [fp, setFp] = useState(null);
  const [groups, setGroups] = useState(null);
  const [error, setError] = useState("");

  const refresh = async () => {
    const [a, b] = await Promise.allSettled([api.fpAnalysis(), api.alertGroups()]);
    if (a.status === "fulfilled") setFp(a.value);
    if (b.status === "fulfilled") setGroups(b.value);
    if (a.status !== "fulfilled") setError(a.reason.message);
  };
  useEffect(() => {
    refresh();
  }, []);

  const pct = (v) => `${Math.round((v || 0) * 100)}%`;
  const fpTone = (s) =>
    s >= 0.6 ? "text-red-400" : s >= 0.35 ? "text-amber-400" : "text-emerald-400";

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="rounded-2xl border border-amber-500/10 bg-amber-500/[0.03] p-6">
        <h3 className="mb-1 text-[15px] font-semibold text-white">False-Positive Analysis</h3>
        <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
          Per-rule FP candidate score from closed-without-action ratio, trigger density,
          confidence and severity. High scores = tuning candidates (roadmap P0).
        </p>
        {error && <p className="mt-2 text-[13px] text-red-400">{error}</p>}
        {!fp ? (
          <p className="mt-4 text-[13px] text-slate-500">Loading…</p>
        ) : fp.items.length === 0 ? (
          <p className="mt-4 text-[13px] text-slate-500">No alert history to analyze yet.</p>
        ) : (
          <div className="mt-4 max-h-96 space-y-2 overflow-y-auto pr-1">
            {fp.items.map((item) => (
              <div key={item.rule} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[13px] font-semibold text-slate-200">{item.rule}</span>
                  <span className={`font-mono text-[13px] font-bold ${fpTone(item.fp_candidate_score)}`}>
                    {item.fp_candidate_score.toFixed(2)}
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-2 text-[13px] text-slate-400">
                  <span>{item.total} alerts</span>
                  <span>· {item.closed} closed ({pct(item.closed / item.total)})</span>
                  <span>· {item.closed_without_action} closed w/o action</span>
                  <span>· avg triggers {item.avg_trigger_count}</span>
                  <span>· conf {item.avg_confidence}</span>
                </div>
                {item.top_evidence_tokens.length > 0 && (
                  <p className="mt-1.5 truncate font-mono text-[13px] text-slate-500">
                    {item.top_evidence_tokens.join(", ")}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-violet-500/10 bg-violet-500/[0.03] p-6">
        <h3 className="mb-1 text-[15px] font-semibold text-white">Repeated Detections</h3>
        <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
          Open alerts grouped by rule + host + user: one recurring event vs a campaign
          (roadmap P0). Groups with the same signature collapse into one entry.
        </p>
        {!groups ? (
          <p className="mt-4 text-[13px] text-slate-500">Loading…</p>
        ) : groups.items.length === 0 ? (
          <p className="mt-4 text-[13px] text-slate-500">No open alerts to group.</p>
        ) : (
          <div className="mt-4 max-h-96 space-y-2 overflow-y-auto pr-1">
            {groups.items.slice(0, 20).map((g) => (
              <div key={`${g.rule}-${g.host}-${g.user}`} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[13px] font-semibold text-slate-200">{g.rule}</span>
                  <span className="rounded-full border border-cyan-500/25 bg-cyan-500/[0.1] px-2.5 py-0.5 font-mono text-[13px] font-bold text-cyan-400 shadow-[0_0_12px_-3px_rgba(0,240,255,0.15)]">
                    ×{g.count}
                  </span>
                </div>
                <p className="mt-1 truncate text-[13px] text-slate-400">
                  host <span className="text-slate-300">{g.host || "?"}</span>
                  {g.user !== "?" && (
                    <>
                      {" "}· user <span className="text-slate-300">{g.user}</span>
                    </>
                  )}
                </p>
                <p className="mt-1 text-[13px] text-slate-500">
                  {g.trigger_count} triggers · first{" "}
                  {new Date(g.first_seen).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </p>
                {g.sample_names.length > 0 && (
                  <p className="mt-1 truncate font-mono text-[13px] text-slate-500">{g.sample_names.join(" | ")}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SuppressionPanel() {
  const [rules, setRules] = useState(null);
  const [form, setForm] = useState({ rule: "", host: "*", user: "*", reason: "", expires_hours: 168 });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = () => {
    api
      .listSuppressions()
      .then((r) => setRules(r.items))
      .catch((e) => setError(e.message));
  };
  useEffect(() => {
    refresh();
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.createSuppression({
        rule: form.rule.trim(),
        host: form.host.trim() || "*",
        user: form.user.trim() || "*",
        reason: form.reason.trim(),
        expires_hours: Number(form.expires_hours) || 168,
      });
      setMessage(`Suppression created for rule "${form.rule.trim()}".`);
      setForm({ rule: "", host: "*", user: "*", reason: "", expires_hours: 168 });
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this suppression rule? Detections will alert again.")) return;
    try {
      await api.deleteSuppression(id);
      refresh();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="rounded-2xl border border-sky-500/10 bg-sky-500/[0.03] p-6">
      <h3 className="mb-1 text-[15px] font-semibold text-white">Alert Suppression</h3>
      <p className="mt-1 text-[13px] leading-relaxed text-slate-400">
        Declare expected behaviour: while a rule matches rule/host/user, findings are
        suppressed instead of becoming alerts (roadmap P2). Default expiry: 7 days.
      </p>

      <form onSubmit={submit} className="mt-4 grid gap-2.5 sm:grid-cols-2">
        <input
          required
          placeholder="Rule id (e.g. python_execution) or *"
          value={form.rule}
          onChange={(e) => setForm({ ...form, rule: e.target.value })}
          className={inputCls}
        />
        <div className="grid grid-cols-2 gap-2.5">
          <input placeholder="Host (or *)" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} className={inputCls} />
          <input placeholder="User (or *)" value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} className={inputCls} />
        </div>
        <input placeholder="Reason" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className={`${inputCls} sm:col-span-2`} />
        <div className="sm:col-span-2 flex items-end gap-2.5">
          <input
            type="number"
            min="0"
            step="1"
            value={form.expires_hours}
            onChange={(e) => setForm({ ...form, expires_hours: e.target.value })}
            className={`${inputCls} w-28`}
            title="Expiry in hours (0 = no expiry)"
          />
          <button
            type="submit"
            disabled={busy}
            className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create Suppression"}
          </button>
        </div>
      </form>

      {message && (
        <p className="mt-3 rounded-xl border p-4 text-sm">
          ✓ {message}
        </p>
      )}
      {error && (
        <p className="mt-3 rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
          {error}
        </p>
      )}

      {rules && rules.length > 0 && (
        <div className="mt-4 max-h-64 space-y-2 overflow-y-auto pr-1">
          {rules.map((r) => (
            <div key={r.id} className="flex items-center gap-3 rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="font-mono text-[13px] font-semibold text-slate-200">
                  {r.rule} <span className="text-slate-500">· {r.host}/{r.user}</span>
                </p>
                <p className="truncate text-[13px] text-slate-500">
                  {r.reason || "no reason"} · suppressed {r.suppressed_count || 0}×
                  {r.expires_at && <> · until {new Date(r.expires_at).toLocaleDateString()}</>}
                </p>
              </div>
              <button
                type="button"
                onClick={() => remove(r.id)}
                className="rounded-lg border border-rose-500/25 bg-rose-500/[0.08] px-2.5 py-1.5 text-[13px] font-semibold text-rose-400 transition-all hover:bg-rose-500/[0.15]"
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AccountCard({ me }) {
  if (!me) return null;
  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
        <span className="h-1 w-1 rounded-full bg-cyan-400" />
        Account
      </h3>
      <dl className="space-y-3 text-[13px]">
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Username</dt>
          <dd className="font-mono font-semibold text-slate-100">{me.username}</dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Full name</dt>
          <dd className="text-slate-200">{me.full_name || "—"}</dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Role</dt>
          <dd>
            <span className={`rounded-full px-2.5 py-0.5 text-[13px] font-semibold ${me.role === "admin" ? "border border-violet-500/25 bg-violet-500/[0.1] text-violet-400" : "border border-cyan-500/25 bg-cyan-500/[0.1] text-cyan-400"}`}>
              {me.role}
            </span>
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Organization</dt>
          <dd className="text-slate-200">{me.org || "—"}</dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Created</dt>
          <dd className="text-slate-200">
            {me.created_at ? new Date(me.created_at).toLocaleDateString() : "—"}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="text-[13px] font-medium uppercase tracking-wider text-slate-500">Two-factor auth</dt>
          <dd>
            <span className={`rounded-full px-2.5 py-0.5 text-[13px] font-semibold ${me.totp_enabled ? "border border-emerald-500/25 bg-emerald-500/[0.1] text-emerald-400" : "border border-white/[0.08] bg-white/[0.03] text-slate-400"}`}>
              {me.totp_enabled ? "ON" : "OFF"}
            </span>
          </dd>
        </div>
      </dl>
    </div>
  );
}

function RenameCard({ onDone }) {
  const [form, setForm] = useState({ current_password: "", new_username: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const user = await api.renameAccount(form.current_password, form.new_username.trim());
      setMessage(`Username changed to "${user.username}".`);
      setForm({ current_password: "", new_username: "" });
      onDone(user);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <h3 className="mb-1 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
        <span className="h-1 w-1 rounded-full bg-cyan-400" />
        Rename Account
      </h3>
      <p className="mb-4 text-[13px] text-slate-500">
        Change the username you sign in with. Confirms your current password first.
      </p>
      <form onSubmit={submit} className="space-y-3">
        <input
          type="password"
          required
          autoComplete="current-password"
          placeholder="Current password"
          value={form.current_password}
          onChange={(e) => setForm({ ...form, current_password: e.target.value })}
          className={inputCls}
        />
        <input
          required
          minLength={3}
          pattern="[a-zA-Z0-9_.-]+"
          autoComplete="username"
          placeholder="New username"
          value={form.new_username}
          onChange={(e) => setForm({ ...form, new_username: e.target.value })}
          className={inputCls}
        />
        {message && (
          <p className="rounded-xl border p-4 text-sm"
          style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
            ✓ {message}
          </p>
        )}
        {error && (
          <p className="rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
        >
          {busy ? "Renaming…" : "Rename Account"}
        </button>
      </form>
    </div>
  );
}

function PasswordCard() {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");
    try {
      if (form.new_password !== form.confirm) {
        setError("New passwords do not match");
        return;
      }
      await api.changePassword(form.current_password, form.new_password);
      setMessage("Password updated.");
      setForm({ current_password: "", new_password: "", confirm: "" });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <h3 className="mb-1 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
        <span className="h-1 w-1 rounded-full bg-cyan-400" />
        Change Password
      </h3>
      <p className="mb-4 text-[13px] text-slate-500">
        Rotate your sign-in password. You will use the new one on your next login.
      </p>
      <form onSubmit={submit} className="space-y-3">
        <input
          type="password"
          required
          autoComplete="current-password"
          placeholder="Current password"
          value={form.current_password}
          onChange={(e) => setForm({ ...form, current_password: e.target.value })}
          className={inputCls}
        />
        <input
          type="password"
          required
          minLength={8}
          autoComplete="new-password"
          placeholder="New password (min 8 characters)"
          value={form.new_password}
          onChange={(e) => setForm({ ...form, new_password: e.target.value })}
          className={inputCls}
        />
        <input
          type="password"
          required
          minLength={8}
          autoComplete="new-password"
          placeholder="Confirm new password"
          value={form.confirm}
          onChange={(e) => setForm({ ...form, confirm: e.target.value })}
          className={inputCls}
        />
        {message && (
          <p className="rounded-xl border p-4 text-sm"
          style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
            ✓ {message}
          </p>
        )}
        {error && (
          <p className="rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
        >
          {busy ? "Updating…" : "Update Password"}
        </button>
      </form>
    </div>
  );
}

function MfaCard({ enabled, onChanged }) {
  const [state, setState] = useState("idle");
  const [secret, setSecret] = useState("");
  const [otpauth, setOtpauth] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const start = async () => {
    setError("");
    try {
      const res = await api.mfaSetup();
      setSecret(res.secret);
      setOtpauth(res.otpauth_url);
      setState("confirm");
    } catch (err) {
      setError(err.message);
    }
  };

  const confirm = async () => {
    setBusy(true);
    setError("");
    try {
      await api.mfaConfirm(code.trim());
      setMessage("Two-factor authentication enabled.");
      setState("idle");
      setCode("");
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    const next = window.prompt("Enter your current authenticator code to disable 2FA:");
    if (!next) return;
    setBusy(true);
    setError("");
    try {
      await api.mfaDisable(next.trim());
      setMessage("Two-factor authentication disabled.");
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (state === "confirm") {
    return (
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h3 className="mb-1 text-[15px] font-semibold text-white">Two-Factor Authentication</h3>
        <p className="mb-3 text-[13px] text-slate-500">
          Scan with your authenticator app (Google Authenticator, Authy, 1Password…)
        </p>
        {otpauth ? (
          <div className="mx-auto mb-3 flex max-w-[200px] justify-center rounded-xl bg-white p-2">
            <img
              src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauth)}`}
              alt="QR code for TOTP setup"
              className="h-full w-full"
            />
          </div>
        ) : (
          <pre className="mb-3 overflow-x-auto rounded-xl bg-white/[0.04] p-3 text-center font-mono text-[13px] text-emerald-300">
            {secret}
          </pre>
        )}
        <p className="mb-3 break-all text-[13px] text-slate-500">
          Manual entry: <span className="font-mono text-slate-300">{secret}</span>
        </p>
        <div className="flex flex-col gap-2">
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
            placeholder="6-digit verification code"
            inputMode="numeric"
            autoComplete="one-time-code"
            className={`${inputCls} text-center font-mono text-lg tracking-[0.4em]`}
          />
          <button
            type="button"
            onClick={confirm}
            disabled={code.length < 6 || busy}
            className="w-full rounded-xl border border-emerald-500/25 bg-emerald-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-emerald-400 transition-all hover:bg-emerald-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(16,185,129,0.2)] disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Activate 2FA"}
          </button>
          <button
            type="button"
            onClick={() => setState("idle")}
            className="w-full rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2 text-[13px] font-medium text-slate-400 transition-all hover:bg-white/[0.06]"
          >
            Cancel
          </button>
        </div>
        {error && (
          <p className="mt-3 rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
            {error}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <h3 className="mb-1 text-[15px] font-semibold text-white">Two-Factor Authentication</h3>
      <p className="mb-4 text-[13px] text-slate-500">
        Add a time-based one-time password (RFC 6238) as a second login factor.
      </p>
      {enabled ? (
        <div className="flex flex-col gap-2">
          <p className="rounded-xl border p-4 text-center text-sm font-semibold" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
            Two-factor authentication is ON for this account
          </p>
          <button
            type="button"
            onClick={disable}
            disabled={busy}
            className="w-full rounded-xl border border-rose-500/25 bg-rose-500/[0.08] px-4 py-2 text-[13px] font-medium text-rose-400 transition-all hover:bg-rose-500/[0.15] disabled:opacity-50"
          >
            {busy ? "Working…" : "Disable 2FA"}
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={start}
          className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]"
        >
          Set Up 2FA
        </button>
      )}
      {message && (
        <p className="mt-3 rounded-xl border p-4 text-sm">
          ✓ {message}
        </p>
      )}
      {error && (
        <p className="mt-3 rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
          {error}
        </p>
      )}
    </div>
  );
}

function PreferencesCard({ me }) {
  const [theme, setTheme] = useState(() => {
    try {
      const stored = localStorage.getItem("baraq-theme");
      if (stored === "light" || stored === "dark") return stored;
    } catch {
      /* ignore */
    }
    return typeof document !== "undefined" &&
      document.documentElement.classList.contains("light")
      ? "light"
      : "dark";
  });

  const toggleTheme = (next) => {
    setTheme(next);
    try {
      localStorage.setItem("baraq-theme", next);
    } catch {
      /* private mode etc. */
    }
    document.documentElement.classList.toggle("light", next === "light");
    window.dispatchEvent(new CustomEvent("baraq:theme-change", { detail: next }));
  };

  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <h3 className="mb-1 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
        <span className="h-1 w-1 rounded-full bg-cyan-400" />
        Preferences
      </h3>
      <p className="mb-4 text-[13px] text-slate-500">Appearance and console preferences.</p>
      <div className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.04] bg-white/[0.02] px-4 py-3.5">
        <div>
          <p className="text-[13px] font-medium text-slate-200">Theme</p>
          <p className="text-[13px] text-slate-500">{theme === "light" ? "Light" : "Dark"} appearance</p>
        </div>
        <button
          type="button"
          onClick={() => toggleTheme(theme === "light" ? "dark" : "light")}
          className="rounded-xl border border-white/[0.08] bg-white/[0.04] p-2.5 text-slate-300 transition-all hover:bg-white/[0.08]"
          aria-label="Toggle theme"
        >
          {theme === "light" ? (
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-5 w-5">
              <path fillRule="evenodd" d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69.75.75 0 01.981.98 10.503 10.503 0 01-9.694 6.46c-5.799 0-10.5-4.701-10.5-10.5 0-4.368 2.667-8.112 6.46-9.694a.75.75 0 01.818.162z" clipRule="evenodd" />
            </svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="h-5 w-5">
              <path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zm11.394-5.834a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-2.25A.75.75 0 0112 18zM7.758 17.303a.75.75 0 00-1.061-1.06l-1.591 1.59a.75.75 0 001.06 1.061l1.591-1.59zM6 12a.75.75 0 01-.75.75H3a.75.75 0 010-1.5h2.25A.75.75 0 016 12zM6.697 7.757a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 00-1.061 1.06l1.59 1.591z" />
            </svg>
          )}
        </button>
      </div>
      <p className="mt-3 text-[13px] leading-relaxed text-slate-600">
        Organization filtering (admins) is available from the sidebar. Your role and
        organization are managed by the administrator.
      </p>
    </div>
  );
}

export default function Settings({ user, onUserChange }) {
  const [me, setMe] = useState(null);
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";

  const refresh = () => {
    api.me().then((res) => setMe(res.user)).catch((err) => setError(err.message));
  };

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="space-y-8 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Settings</h1>
        <p className="mt-1 text-[13px] text-slate-400">{isAdmin ? "System operations, account, security and preferences" : "Account, security and preferences"}</p>
      </div>

      {isAdmin && (
        <div className="space-y-4">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            System Operations
          </h3>
          <SystemAdminPanel />
          <h3 className="mb-4 mt-6 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Detection Tuning
          </h3>
          <TuningPanel />
          <SuppressionPanel />
        </div>
      )}

      <div className="space-y-4">
        <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
          <span className="h-1 w-1 rounded-full bg-cyan-400" />
          Account
        </h3>
        {error && <ErrorBanner message={error} onRetry={refresh} />}
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="space-y-6">
            <AccountCard me={me} />
            <PreferencesCard me={me} />
          </div>
          <div className="space-y-6">
            <RenameCard
              onDone={(updated) => {
                setMe(updated);
                if (onUserChange) onUserChange(updated);
              }}
            />
            <PasswordCard />
            <MfaCard enabled={me?.totp_enabled ?? false} onChanged={refresh} />
          </div>
        </div>
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-[13px] font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
