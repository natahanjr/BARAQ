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
import ChartTooltip from "../components/ChartTooltip.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

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
  const display = invert
    ? `${(v * 100).toFixed(1)}%`
    : v >= 1.5
      ? v.toFixed(0)
      : `${(v * 100).toFixed(1)}%`;
  return (
    <span className={`font-mono text-xs font-semibold ${good ? "text-emerald-400" : "text-amber-400"}`}>
      {display}
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
    <div className="space-y-6 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">
              Detection Evaluation
            </h1>
            <p className="mt-1 text-[13px] text-slate-400">
              Accuracy metrics for all detection scenarios
            </p>
          </div>
          <button
            type="button"
            onClick={run}
            disabled={busy}
            className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-6 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
          >
            {busy ? "Running evaluation..." : "Run Detection Evaluation"}
          </button>
        </div>
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <p className="text-xs leading-relaxed text-slate-400">
          Runs the 5 attack scenarios plus a normal baseline through the full detection pipeline in
          an isolated temporary database — never touches production data.
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!latest && !error && <Loading label="Loading evaluation results" />}
      {latest && runs.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] py-16 text-center">
          <span className="text-4xl">🧪</span>
          <h3 className="mt-4 text-sm font-semibold text-white">No evaluation run yet</h3>
          <p className="mt-1 text-[13px] text-slate-400">
            Click the button above to run the detection evaluation
          </p>
        </div>
      )}

      {latest && runs.length > 0 && (
        <>
          <div>
            <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
              <span className="h-1 w-1 rounded-full bg-cyan-400" />
              Overall Metrics
            </h3>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
              {[
                ["Accuracy", `${(overall.accuracy * 100).toFixed(1)}%`, "text-emerald-400"],
                ["Precision", `${(overall.precision * 100).toFixed(1)}%`, "text-cyan-400"],
                ["Recall", `${(overall.recall * 100).toFixed(1)}%`, "text-sky-400"],
                ["F1-score", `${(overall.f1_score * 100).toFixed(1)}%`, "text-violet-400"],
                [
                  "False positive rate",
                  `${(overall.false_positive_rate * 100).toFixed(1)}%`,
                  "text-amber-400",
                ],
                [
                  "Avg detection time",
                  `${overall.detection_time_ms.toFixed(0)} ms`,
                  "text-slate-200",
                ],
              ].map(([label, value, color]) => (
                <div
                  key={label}
                  className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5 text-center"
                >
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500/70">
                    {label}
                  </p>
                  <p className={`mt-2 text-2xl font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
              <span className="h-1 w-1 rounded-full bg-cyan-400" />
              Per-Scenario Results
            </h3>
            <div className="overflow-x-auto">
              <table className="data-table w-full">
                <thead>
                  <tr className="border-b border-white/[0.06] text-[10px] uppercase tracking-[0.08em] text-slate-500/70">
                    <th className="px-4 py-3 text-left">Scenario</th>
                    <th className="px-4 py-3 text-left">Samples</th>
                    <th className="px-4 py-3 text-left">TP</th>
                    <th className="px-4 py-3 text-left">FP</th>
                    <th className="px-4 py-3 text-left">TN</th>
                    <th className="px-4 py-3 text-left">FN</th>
                    {METRICS.map((m) => (
                      <th key={m.key} className="px-4 py-3 text-left">
                        {m.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r) => (
                    <tr key={r.id} className="border-b border-white/[0.04] transition-colors hover:bg-white/[0.02]">
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
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                <span className="h-1 w-1 rounded-full bg-cyan-400" />
                Per-scenario precision & recall
              </h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={runs}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                    <XAxis
                      dataKey="scenario"
                      stroke="var(--chart-grid)"
                      fontSize={10}
                      tickFormatter={(v) => (SCENARIO_LABELS[v] || v).split(" ")[0]}
                      tickLine={false}
                    />
                    <YAxis domain={[0, 1]} stroke="var(--chart-grid)" fontSize={11} tickLine={false} />
                    <Tooltip
                      content={<ChartTooltip />}
                      labelFormatter={(v) => SCENARIO_LABELS[v] || v}
                    />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    <Bar dataKey="precision" name="Precision" fill="#00f0ff" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="recall" name="Recall" fill="#7b61ff" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="f1_score" name="F1" fill="#00e676" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                <span className="h-1 w-1 rounded-full bg-cyan-400" />
                Detection time per scenario
              </h3>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={runs}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                    <XAxis
                      dataKey="scenario"
                      stroke="var(--chart-grid)"
                      fontSize={10}
                      tickFormatter={(v) => (SCENARIO_LABELS[v] || v).split(" ")[0]}
                      tickLine={false}
                    />
                    <YAxis stroke="var(--chart-grid)" fontSize={11} tickLine={false} />
                    <Tooltip content={<ChartTooltip />} labelFormatter={(v) => SCENARIO_LABELS[v] || v} />
                    <Bar dataKey="detection_time_ms" name="ms" fill="#ffb300" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {history && history.items.length > 0 && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
                <span className="h-1 w-1 rounded-full bg-cyan-400" />
                Run history (last {history.items.length})
              </h3>
              <div className="max-h-40 space-y-1 overflow-y-auto">
                {history.items
                  .filter((r) => r.scenario === "overall")
                  .map((r) => (
                    <div
                      key={r.id}
                      className="flex flex-wrap gap-x-4 gap-y-1 rounded-xl border border-white/[0.04] bg-white/[0.02] px-3 py-2 font-mono text-[11px]"
                    >
                      <span className="text-slate-400">{new Date(r.created_at).toLocaleString()}</span>
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

      <div className="flex justify-center pt-4">
        <p className="text-[11px] font-medium text-slate-500/50">
          BARAQ · Real-Time Endpoint Security Operations
        </p>
      </div>
    </div>
  );
}
