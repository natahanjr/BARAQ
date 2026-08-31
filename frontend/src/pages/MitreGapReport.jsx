import { memo, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge } from "../components/ui/index.js";

function ProgressBar({ value, color = "var(--accent-cyan)" }) {
  return (
    <div className="h-2.5 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: color }}
      />
    </div>
  );
}

function MitreGapReport() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [tacticFilter, setTacticFilter] = useState("");

  const load = () => {
    setError("");
    api
      .get("/api/mitre/gap-report")
      .then(setData)
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const stats = useMemo(() => {
    if (!data) return null;
    const total = data.total_techniques || 0;
    const covered = data.covered || 0;
    const uncovered = data.uncovered || 0;
    const pct = total > 0 ? ((covered / total) * 100).toFixed(1) : 0;
    return { total, covered, uncovered, pct };
  }, [data]);

  const tactics = useMemo(() => {
    if (!data?.uncovered_techniques) return [];
    const set = new Set(data.uncovered_techniques.map((t) => t.tactic));
    return [...set];
  }, [data]);

  const filteredUncovered = useMemo(() => {
    if (!data?.uncovered_techniques) return [];
    return tacticFilter
      ? data.uncovered_techniques.filter((t) => t.tactic === tacticFilter)
      : data.uncovered_techniques;
  }, [data, tacticFilter]);

  const filteredCovered = useMemo(() => {
    if (!data?.covered_techniques) return [];
    return tacticFilter
      ? data.covered_techniques.filter((t) => t.tactic === tacticFilter)
      : data.covered_techniques;
  }, [data, tacticFilter]);

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="MITRE ATT&CK Gap Report"
        subtitle="Detection coverage analysis across ATT&CK techniques"
        label="Detection"
      />

      {error && <ErrorBanner message={error} onRetry={load} />}
      {!data && !error && <Loading label="Loading gap report" />}

      {data && stats && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {[
              ["Total Techniques", stats.total, "var(--fg-primary)"],
              ["Covered", stats.covered, "var(--status-healthy)"],
              ["Uncovered", stats.uncovered, "var(--severity-critical)"],
              ["Coverage", `${stats.pct}%`, "var(--accent-cyan)"],
            ].map(([label, value, color]) => (
              <Card key={label} className="p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{label}</p>
                <p className="mt-1 text-[22px] font-bold tabular-nums" style={{ color, fontFeatureSettings: '"tnum"' }}>
                  {value}
                </p>
              </Card>
            ))}
          </div>

          <Card>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[13px] font-semibold text-[var(--fg-primary)]">Coverage Bar</span>
              <span className="text-[14px] font-bold text-[var(--accent-cyan)]">{stats.pct}%</span>
            </div>
            <ProgressBar value={stats.pct} />
          </Card>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={() => setTacticFilter("")}
              className={`rounded-lg px-3 py-1.5 text-[11px] font-medium transition-all ${
                !tacticFilter
                  ? "bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30"
                  : "bg-[var(--bg-inset)] text-[var(--fg-muted)] border border-[var(--border-default)] hover:text-[var(--fg-secondary)]"
              }`}
            >
              All Tactics
            </button>
            {tactics.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTacticFilter(tacticFilter === t ? "" : t)}
                className={`rounded-lg px-3 py-1.5 text-[11px] font-medium transition-all ${
                  tacticFilter === t
                    ? "bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30"
                    : "bg-[var(--bg-inset)] text-[var(--fg-muted)] border border-[var(--border-default)] hover:text-[var(--fg-secondary)]"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {filteredUncovered.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Uncovered Techniques ({filteredUncovered.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead>
                      <tr className="border-b border-[var(--border-subtle)]">
                        <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">ID</th>
                        <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Name</th>
                        <th className="pb-2 font-semibold text-[var(--fg-muted)]">Tactic</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)]">
                      {filteredUncovered.map((t) => (
                        <tr key={t.id || t.technique_id}>
                          <td className="py-3 pr-4 font-mono text-[11px] font-medium text-[var(--accent-cyan)]">{t.id || t.technique_id}</td>
                          <td className="py-3 pr-4 text-[12px] text-[var(--fg-primary)]">{t.name || t.technique_name}</td>
                          <td className="py-3"><Badge severity="info" size="sm">{t.tactic}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}

          {filteredCovered.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Covered Techniques ({filteredCovered.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead>
                      <tr className="border-b border-[var(--border-subtle)]">
                        <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">ID</th>
                        <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Name</th>
                        <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Tactic</th>
                        <th className="pb-2 font-semibold text-[var(--fg-muted)]">Detection Rules</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)]">
                      {filteredCovered.map((t) => (
                        <tr key={t.id || t.technique_id}>
                          <td className="py-3 pr-4 font-mono text-[11px] font-medium text-[var(--fg-muted)]">{t.id || t.technique_id}</td>
                          <td className="py-3 pr-4 text-[12px] text-[var(--fg-primary)]">{t.name || t.technique_name}</td>
                          <td className="py-3 pr-4"><Badge severity="low" size="sm">{t.tactic}</Badge></td>
                          <td className="py-3">
                            <div className="flex flex-wrap gap-1">
                              {(t.detection_rules || t.rules || []).slice(0, 3).map((r, i) => (
                                <span key={i} className="rounded bg-[var(--status-healthy)]/10 px-1.5 py-0.5 text-[10px] font-medium text-[var(--status-healthy)]">
                                  {typeof r === "string" ? r : r.name || r.id}
                                </span>
                              ))}
                              {(t.detection_rules || t.rules || []).length > 3 && (
                                <span className="text-[10px] text-[var(--fg-muted)]">
                                  +{(t.detection_rules || t.rules || []).length - 3} more
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

export default memo(MitreGapReport);
