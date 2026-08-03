import { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";
import { api } from "../api.js";
import { Loading, EmptyState } from "../components/Feedback.jsx";

const SCENARIO_LABELS = {
  brute_force: "Brute Force (T1110)",
  powershell: "PowerShell (T1059.001)",
  privilege_escalation: "Privilege Esc (T1068)",
  persistence: "Persistence (T1547)",
  port_scan: "Port Scan (T1046)",
  baseline: "Baseline (normal)",
};

const METRICS = [
  { key: "accuracy", label: "Accuracy", pct: true },
  { key: "precision", label: "Precision", pct: true },
  { key: "recall", label: "Recall", pct: true },
  { key: "f1_score", label: "F1-score", pct: true },
  { key: "false_positive_rate", label: "FP rate", pct: true, invert: true },
  { key: "detection_time_ms", label: "Det. time (ms)", pct: false },
];

function MetricCell({ value, invert }) {
  const v = Number(value ?? 0);
  const good = invert ? v <= 0.05 : v >= 0.9;
  return (
    <span className={`font-mono text-xs font-semibold ${good ? "text-emerald-400" : "text-amber-400"}`}>
      {invert ? `${(v * 100).toFixed(1)}%` : v >= 1.5 ? v.toFixed(0) : `${(v * 100).toFixed(1)}%`}
    </span>
  );
}

export default function Evaluation() {
  const [latest, setLatest] = useState(null);
  const [history, setHistory] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = () => {
    api
      .evaluationLatest()
      .then(setLatest)
      .catch(() => {});
    api.evaluationResults(50).then(setHistory).catch(() => {});
  };

  useEffect(() => {
    load();
  }, []);

  const run = async () => {
    setBusy(true);
    setError("");
    try {
      await api.evaluationRun();
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const runs = latest?.items ?? [];
  const overall = latest?.overall;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={run}
          disabled={busy}
          className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40"
        >
          {busy ? "Running evaluation (isolated DB)..." : "▶ Run detection evaluation"}
        </button>
        <span className="text-xs text-slate-500">
          Runs 5 attack scenarios + baseline through the full pipeline in an isolated temporary
          database — never touches production data.
        </span>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}

      {!latest && !error && <Loading label="Loading evaluation results" />}
      {latest && runs.length === 0 && <EmptyState message="No evaluation run yet — click the button above" />}

      {latest && runs.length > 0 && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
            {[
              ["Accuracy", `${(overall.accuracy * 100).toFixed(1)}%`, "text-emerald-400"],
              ["Precision", `${(overall.precision * 100).toFixed(1)}%`, "text-cyan-400"],
              ["Recall", `${(overall.recall * 100).toFixed(1)}%`, "text-sky-400"],
              ["F1-score", `${(overall.f1_score * 100).toFixed(1)}%`, "text-violet-400"],
              ["False positive rate", `${(overall.false_positive_rate * 100).toFixed(1)}%`, "text-amber-400"],
              ["Avg detection time", `${overall.detection_time_ms.toFixed(0)} ms`, "text-slate-200"],
            ].map(([label, value, color]) => (
              <div key={label} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
                <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
                <p className={`mt-1.5 text-xl font-bold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-3">Scenario</th>
                  <th className="px-4 py-3">Samples</th>
                  <th className="px-4 py-3">TP</th>
                  <th className="px-4 py-3">FP</th>
                  <th className="px-4 py-3">TN</th>
                  <th className="px-4 py-3">FN</th>
                  {METRICS.map((m) => (
                    <th key={m.key} className="px-4 py-3">{m.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 text-xs font-medium text-slate-300">
                      {SCENARIO_LABELS[r.scenario] || r.scenario}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{r.total_samples}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-emerald-400">{r.true_positives}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-red-400">{r.false_positives}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-400">{r.true_negatives}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-amber-400">{r.false_negatives}</td>
                    {METRICS.map((m) => (
                      <td key={m.key} className="px-4 py-2.5">
                        <MetricCell value={r[m.key]} invert={m.invert} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-slate-300">Per-scenario F1 & recall</h3>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={runs}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="scenario"
                    stroke="#475569"
                    fontSize={10}
                    tickFormatter={(v) => (SCENARIO_LABELS[v] || v).split(" ")[0]}
                  />
                  <YAxis domain={[0, 1]} stroke="#475569" fontSize={11} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                    labelFormatter={(v) => SCENARIO_LABELS[v] || v}
                  />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="precision" name="Precision" fill="#22d3ee" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="recall" name="Recall" fill="#a78bfa" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="f1_score" name="F1" fill="#34d399" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-slate-300">Detection time per scenario</h3>
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={runs}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="scenario"
                    stroke="#475569"
                    fontSize={10}
                    tickFormatter={(v) => (SCENARIO_LABELS[v] || v).split(" ")[0]}
                  />
                  <YAxis stroke="#475569" fontSize={11} />
                  <Tooltip
                    contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                    labelFormatter={(v) => SCENARIO_LABELS[v] || v}
                  />
                  <Bar dataKey="detection_time_ms" name="ms" fill="#fbbf24" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {history && history.items.length > 0 && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-2 text-sm font-semibold text-slate-300">Run history (last {history.items.length})</h3>
              <div className="max-h-40 space-y-1 overflow-y-auto">
                {history.items
                  .filter((r) => r.scenario === "overall")
                  .map((r) => (
                    <div key={r.id} className="flex flex-wrap gap-x-4 gap-y-1 rounded bg-slate-950/50 px-3 py-1.5 font-mono text-[11px] text-slate-500">
                      <span>{new Date(r.created_at).toLocaleString()}</span>
                      <span className="text-emerald-400">acc {(r.accuracy * 100).toFixed(1)}%</span>
                      <span className="text-cyan-400">prec {(r.precision * 100).toFixed(1)}%</span>
                      <span className="text-violet-400">rec {(r.recall * 100).toFixed(1)}%</span>
                      <span className="text-amber-400">FPR {(r.false_positive_rate * 100).toFixed(1)}%</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
