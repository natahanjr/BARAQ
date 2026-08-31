import { memo, useEffect, useState } from "react";
import { api } from "../api.js";
import { ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge } from "../components/ui/index.js";

function BaselineDetail({ user }) {
  const b = user.baseline || {};
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {[
        ["Login Hours", b.login_hours?.join(", ") || "\u2014"],
        ["Typical Hosts", b.typical_hosts?.join(", ") || "\u2014"],
        ["Processes", b.typical_processes?.join(", ") || "\u2014"],
        ["IPs", b.known_ips?.join(", ") || "\u2014"],
      ].map(([label, value]) => (
        <div key={label} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">{label}</p>
          <p className="mt-1 text-[11px] text-[var(--fg-secondary)] truncate" title={value}>{value}</p>
        </div>
      ))}
    </div>
  );
}

function UEBA() {
  const [baselines, setBaselines] = useState(null);
  const [anomalies, setAnomalies] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);

  const load = () => {
    setError("");
    Promise.allSettled([
      api.get("/api/ueba/baselines"),
      api.get("/api/ueba/anomalies"),
    ]).then(([b, a]) => {
      if (b.status === "fulfilled") setBaselines(b.value.items || b.value);
      else setError(b.reason.message);
      if (a.status === "fulfilled") setAnomalies(a.value.items || a.value);
    });
  };

  useEffect(() => { load(); }, []);

  const riskColor = (score) => {
    if (score > 0.7) return "var(--severity-critical)";
    if (score > 0.4) return "var(--severity-high)";
    if (score > 0.2) return "var(--severity-medium)";
    return "var(--status-healthy)";
  };

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="User Entity Behavior Analytics"
        subtitle="Behavioral baselines and anomaly detection"
        label="Analytics"
      />

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="grid gap-5 lg:grid-cols-2">
        <div>
          <h2 className="mb-3 text-[14px] font-semibold text-[var(--fg-primary)]">User Baselines</h2>
          {!baselines && !error && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-14 animate-pulse rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)]" />
              ))}
            </div>
          )}
          {baselines && baselines.length === 0 && (
            <Card className="py-10 text-center">
              <p className="text-[13px] text-[var(--fg-muted)]">No baselines established yet</p>
            </Card>
          )}
          {baselines && (
            <div className="space-y-2">
              {baselines.map((u) => (
                <div key={u.user || u.id} className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all hover:border-[var(--border-strong)]">
                  <button
                    type="button"
                    onClick={() => setExpanded(expanded === u.user ? null : u.user)}
                    className="w-full px-4 py-3 text-left"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{u.user || u.username}</span>
                        {u.risk_score != null && (
                          <span className="text-[11px] font-bold tabular-nums" style={{ color: riskColor(u.risk_score), fontFeatureSettings: '"tnum"' }}>
                            {(u.risk_score * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"
                        className={`text-[var(--fg-muted)] transition-transform duration-200 ${expanded === u.user ? "rotate-180" : ""}`}>
                        <path d="M4 6l4 4 4-4" />
                      </svg>
                    </div>
                  </button>
                  {expanded === u.user && (
                    <div className="border-t border-[var(--border-subtle)] px-4 pb-4 pt-3 space-y-3">
                      <BaselineDetail user={u} />
                      {u.volume_spikes > 0 && (
                        <Badge severity="medium" size="sm">{u.volume_spikes} volume spike{u.volume_spikes !== 1 ? "s" : ""}</Badge>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <h2 className="mb-3 text-[14px] font-semibold text-[var(--fg-primary)]">Anomaly Detection</h2>
          {!anomalies && !error && (
            <div className="space-y-2">
              {[1, 2].map((i) => (
                <div key={i} className="h-20 animate-pulse rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)]" />
              ))}
            </div>
          )}
          {anomalies && anomalies.length === 0 && (
            <Card className="py-10 text-center">
              <p className="text-[13px] text-[var(--fg-muted)]">No anomalies detected</p>
            </Card>
          )}
          {anomalies && (
            <div className="space-y-2">
              {anomalies.map((a, i) => (
                <Card key={a.id || i} hover>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{a.user || a.username}</span>
                        <Badge severity={a.severity || "medium"} size="sm">{a.type || "anomaly"}</Badge>
                      </div>
                      <p className="mt-1.5 text-[12px] text-[var(--fg-secondary)]">{a.description || a.detail}</p>
                      {a.timestamp && (
                        <p className="mt-1 text-[11px] text-[var(--fg-muted)]">{new Date(a.timestamp).toLocaleString()}</p>
                      )}
                    </div>
                    {a.risk_score != null && (
                      <div className="shrink-0 text-right">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Risk</p>
                        <p className="text-[14px] font-bold tabular-nums" style={{ color: riskColor(a.risk_score), fontFeatureSettings: '"tnum"' }}>
                          {(a.risk_score * 100).toFixed(0)}
                        </p>
                      </div>
                    )}
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(UEBA);
