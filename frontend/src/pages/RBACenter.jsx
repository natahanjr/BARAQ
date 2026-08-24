import { useCallback, useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { api, isAdmin } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import ChartTooltip from "../components/ChartTooltip.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";

const KIND_LABELS = { user: "User", host: "Host", ip: "IP" };

const RULE_CANDIDATES = [
  "brute_force",
  "pass_the_hash",
  "lsass_dump",
  "privilege_escalation",
  "persistence",
  "lateral_movement",
  "data_staging",
  "usb_device",
  "powershell",
  "dns_exfil",
];

function formatTime(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function RBACenter() {
  const [kind, setKind] = useState("host");
  const [entities, setEntities] = useState(null);
  const [selected, setSelected] = useState(null);
  const [rules, setRules] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tuning, setTuning] = useState(null);
  const [tuningDraft, setTuningDraft] = useState(null);
  const [tuningSaved, setTuningSaved] = useState(false);

  const loadEntities = useCallback(() => {
    api
      .rbaEntities({ kind, limit: 50 })
      .then(setEntities)
      .catch((e) => setError(e.message));
  }, [kind]);

  useEffect(() => {
    loadEntities();
  }, [loadEntities]);

  useEffect(() => {
    api
      .rbaRules()
      .then(setRules)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!isAdmin()) return;
    api
      .rbaTuning()
      .then((t) => {
        setTuning(t);
        setTuningDraft(JSON.parse(JSON.stringify(t)));
      })
      .catch(() => {});
  }, []);

  const openEntity = (entity) => {
    setSelected(entity);
    api
      .rbaEntity(entity.entity_kind, entity.entity_name)
      .then((profile) => {
        setSelected((prev) =>
          prev && prev.entity_name === entity.entity_name
            ? { ...profile.entity, timeline: profile.timeline }
            : prev,
        );
      })
      .catch((e) => setError(e.message));
  };

  const runDecay = () => {
    setBusy(true);
    api
      .rbaDecay()
      .then(() => loadEntities())
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const runSync = () => {
    setBusy(true);
    api
      .rbaSync(24)
      .then(() => loadEntities())
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const saveTuning = () => {
    if (!tuningDraft) return;
    setBusy(true);
    setTuningSaved(false);
    api
      .rbaSetTuning({
        rule_risk_weights: tuningDraft.rule_risk_weights,
        risk_thresholds: tuningDraft.risk_thresholds,
        risk_decay_days: Number(tuningDraft.risk_decay_days),
        risk_notable_window_hours: Number(tuningDraft.risk_notable_window_hours),
        entity_risk_enabled: tuningDraft.entity_risk_enabled,
      })
      .then((t) => {
        setTuning(t);
        setTuningDraft(JSON.parse(JSON.stringify(t)));
        setTuningSaved(true);
        loadEntities();
        setTimeout(() => setTuningSaved(false), 2500);
      })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const timelineData =
    selected?.timeline?.map((e) => ({
      t: formatTime(e.created_at),
      score: e.score_after,
      delta: e.delta,
    })) || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Entity Risk Center"
        subtitle="Risk-Based Alerting: accumulated risk per user, host and IP with exponential decay over time."
        actions={
          <div className="flex gap-2">
            <button
              onClick={runSync}
              disabled={busy}
              className="rounded-lg border border-slate-600 px-3 py-1.5 text-sm font-medium text-slate-200 hover:border-violet-400 hover:text-violet-300 disabled:opacity-50"
            >
              Sync 24h
            </button>
            <button
              onClick={runDecay}
              disabled={busy}
              className="rounded-lg border border-slate-600 px-3 py-1.5 text-sm font-medium text-slate-200 hover:border-violet-400 hover:text-violet-300 disabled:opacity-50"
            >
              Apply Decay
            </button>
          </div>
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError("")} />}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-lg font-semibold text-white">Risk Leaderboard</h3>
            <div className="flex gap-1 rounded-lg border border-slate-700 p-0.5">
              {Object.entries(KIND_LABELS).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setKind(key)}
                  className={`rounded-md px-3 py-1 text-xs font-medium ${
                    kind === key
                      ? "bg-violet-500/20 text-violet-300"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          {entities === null ? (
            <Loading />
          ) : entities.entities.length === 0 ? (
            <EmptyState
              title="No accumulated risk"
              message="Entities gain risk as alerts fire against them. Run 'Sync 24h' to backfill from recent detections."
            />
          ) : (
            <div className="max-h-[520px] overflow-auto">
              <table className="data-table w-full">
                <thead className="sticky top-0 bg-slate-900/90 text-xs uppercase tracking-wider text-slate-400 backdrop-blur">
                  <tr>
                    <th className="px-3 py-2">Entity</th>
                    <th className="px-3 py-2">Level</th>
                    <th className="px-3 py-2 text-right">Score</th>
                    <th className="px-3 py-2 text-right">Alerts</th>
                    <th className="px-3 py-2 text-right">Last Update</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {entities.entities.map((e) => (
                    <tr
                      key={`${e.entity_kind}:${e.entity_name}`}
                      onClick={() => openEntity(e)}
                      className={`cursor-pointer hover:bg-slate-800/40 ${
                        selected?.entity_name === e.entity_name ? "bg-violet-500/10" : ""
                      }`}
                    >
                      <td className="px-3 py-2 font-mono text-xs text-slate-200">
                        {e.entity_name}
                      </td>
                      <td className="px-3 py-2">
                        <RiskBadge level={e.risk_level} score={e.score} />
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-xs text-slate-300">
                        {Number(e.score).toFixed(1)}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-xs text-slate-300">
                        {e.alerts_count}
                      </td>
                      <td className="px-3 py-2 text-right text-xs text-slate-400">
                        {formatTime(e.last_updated)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card tone="violet">
          <h3 className="mb-4 text-lg font-semibold text-white">
            {selected ? `${KIND_LABELS[selected.entity_kind]}: ${selected.entity_name}` : "Entity Timeline"}
          </h3>
          {!selected && (
            <EmptyState
              title="Select an entity"
              message="Click a row in the leaderboard to see how its risk accumulated over time."
            />
          )}
          {selected && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <RiskBadge level={selected.risk_level} score={selected.score} />
                <span className="text-xs text-slate-400">
                  {selected.alerts_count} contributing detection(s)
                </span>
              </div>
              {timelineData.length > 0 ? (
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.5} />
                          <stop offset="100%" stopColor="#00f0ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                      <XAxis dataKey="t" stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
                      <YAxis stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area
                        type="monotone"
                        dataKey="score"
                        name="Risk score"
                        stroke="#00f0ff"
                        fill="url(#riskGradient)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-sm text-slate-400">No timeline events yet.</p>
              )}
              {selected.contributions?.length > 0 && (
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-3">
                  <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Recent contributions
                  </h4>
                  <ul className="space-y-1.5">
                    {selected.contributions.slice(-8).reverse().map((c, i) => (
                      <li key={i} className="flex flex-wrap items-center gap-2 text-xs">
                        <span className="font-mono text-slate-300">{c.rule}</span>
                        <span className="font-mono text-slate-500">{c.mitre_id}</span>
                        <span className="font-mono text-violet-300">
                          +{Number(c.delta).toFixed(1)}
                        </span>
                        <span className="text-slate-500">{formatTime(c.created_at)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {isAdmin() && tuningDraft && (
        <Card tone="amber">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-lg font-semibold text-white">Risk Tuning</h3>
              <p className="text-xs text-slate-400">
                Live detection tuning - changes apply on the next accumulation, decay or escalation pass (no restart).
              </p>
            </div>
            <button
              onClick={saveTuning}
              disabled={busy}
              className="rounded-lg bg-violet-600 px-4 py-1.5 text-sm font-semibold text-white hover:bg-violet-500 disabled:opacity-50"
            >
              {tuningSaved ? "Saved" : busy ? "Saving…" : "Save Tuning"}
            </button>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            <div>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                Per-rule risk multipliers
              </h4>
              <div className="space-y-1.5">
                {Object.entries(tuningDraft.rule_risk_weights).map(([rule, weight]) => (
                  <div key={rule} className="flex items-center gap-2">
                    <span className="w-40 truncate font-mono text-xs text-slate-300">{rule}</span>
                    <input
                      type="number"
                      step="0.1"
                      min="0"
                      value={weight}
                      onChange={(e) =>
                        setTuningDraft((d) => ({
                          ...d,
                          rule_risk_weights: {
                            ...d.rule_risk_weights,
                            [rule]: Number(e.target.value),
                          },
                        }))
                      }
                      className="w-24 rounded-md border border-slate-600 bg-slate-800 px-2 py-1 text-xs text-slate-100"
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Escalation thresholds
              </h4>
              <div className="grid grid-cols-3 gap-3">
                {["medium", "high", "critical"].map((lvl) => (
                  <label key={lvl} className="block">
                    <span className="mb-1 block text-[11px] uppercase tracking-wide text-slate-400">{lvl}</span>
                    <input
                      type="number"
                      value={tuningDraft.risk_thresholds[lvl]}
                      onChange={(e) =>
                        setTuningDraft((d) => ({
                          ...d,
                          risk_thresholds: {
                            ...d.risk_thresholds,
                            [lvl]: Number(e.target.value),
                          },
                        }))
                      }
                      className="w-full rounded-md border border-slate-600 bg-slate-800 px-2 py-1 text-sm text-slate-100"
                    />
                  </label>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase tracking-wide text-slate-400">
                    Decay half-life (days)
                  </span>
                  <input
                    type="number"
                    min="0.1"
                    value={tuningDraft.risk_decay_days}
                    onChange={(e) =>
                      setTuningDraft((d) => ({ ...d, risk_decay_days: Number(e.target.value) }))
                    }
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-2 py-1 text-sm text-slate-100"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase tracking-wide text-slate-400">
                    Notable dedup (hours)
                  </span>
                  <input
                    type="number"
                    min="1"
                    value={tuningDraft.risk_notable_window_hours}
                    onChange={(e) =>
                      setTuningDraft((d) => ({ ...d, risk_notable_window_hours: Number(e.target.value) }))
                    }
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-2 py-1 text-sm text-slate-100"
                  />
                </label>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-200">
                <input
                  type="checkbox"
                  checked={tuningDraft.entity_risk_enabled}
                  onChange={(e) =>
                    setTuningDraft((d) => ({ ...d, entity_risk_enabled: e.target.checked }))
                  }
                  className="h-4 w-4 accent-violet-500"
                />
                Entity risk accumulation enabled
              </label>
            </div>
          </div>
        </Card>
      )}

      <Card>
        <h3 className="mb-3 text-lg font-semibold text-white">Declarative Correlation Rules</h3>
        {rules === null ? (
          <Loading />
        ) : rules.rules.length === 0 ? (
          <EmptyState
            title="No correlation rules"
            message="Add YAML files to backend/detection/correlation_rules/ to enable multi-stage correlation."
          />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {rules.rules.map((r) => (
              <div
                key={r.name}
                className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-4"
              >
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-semibold text-slate-100">
                    {r.name}
                  </span>
                  <RiskBadge level={r.severity.toUpperCase()} />
                </div>
                <p className="mb-3 text-xs text-slate-400">{r.description}</p>
                <div className="flex flex-wrap gap-1.5">
                  {r.stages.map((s) => (
                    <span
                      key={s.label}
                      className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-300"
                    >
                      {s.label}
                    </span>
                  ))}
                </div>
                <div className="mt-3 flex items-center gap-3 text-[11px] text-slate-500">
                  <span className="font-mono">{r.mitre_id}</span>
                  <span>group_by: {r.group_by}</span>
                  <span>match: {r.match}</span>
                  <span>{r.window_minutes} min</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}