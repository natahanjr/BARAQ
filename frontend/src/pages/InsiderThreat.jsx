import { memo, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge } from "../components/ui/index.js";

const THREAT_LEVELS = {
  none: { severity: "info", label: "None" },
  low: { severity: "low", label: "Low" },
  medium: { severity: "medium", label: "Medium" },
  high: { severity: "high", label: "High" },
  critical: { severity: "critical", label: "Critical" },
};

function ThreatScoreCard({ user, expanded, onToggle }) {
  const level = THREAT_LEVELS[user.threat_level] || THREAT_LEVELS.none;

  return (
    <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all hover:border-[var(--border-strong)]">
      <button type="button" onClick={onToggle} className="w-full px-5 py-4 text-left">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-mono text-[13px] font-semibold text-[var(--fg-primary)]">{user.user || user.username}</span>
            <Badge severity={level.severity} size="sm" dot>{level.label}</Badge>
          </div>
          <div className="flex items-center gap-3">
            {user.score != null && (
              <span className="text-[16px] font-bold tabular-nums" style={{ color: user.score > 0.7 ? "var(--severity-critical)" : user.score > 0.4 ? "var(--severity-high)" : "var(--fg-primary)", fontFeatureSettings: '"tnum"' }}>
                {(user.score * 100).toFixed(0)}
              </span>
            )}
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"
              className={`text-[var(--fg-muted)] transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}>
              <path d="M4 6l4 4 4-4" />
            </svg>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border-subtle)] px-5 pb-5 pt-4 space-y-4">
          {user.indicators?.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Indicators</p>
              <div className="space-y-1.5">
                {user.indicators.map((ind, i) => (
                  <div key={i} className="flex items-start gap-2 rounded-lg bg-[var(--bg-inset)] px-3 py-2">
                    <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--severity-high)]" />
                    <span className="text-[12px] text-[var(--fg-secondary)]">{typeof ind === "string" ? ind : ind.description || JSON.stringify(ind)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {user.recommended_actions?.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Recommended Actions</p>
              <div className="flex flex-wrap gap-1.5">
                {user.recommended_actions.map((action, i) => (
                  <span key={i} className="rounded-md border border-[var(--accent-cyan)]/25 bg-[var(--accent-cyan)]/[0.08] px-2.5 py-1 text-[11px] font-medium text-[var(--accent-cyan)]">
                    {action}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function InsiderThreat() {
  const [users, setUsers] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);
  const [highRiskOnly, setHighRiskOnly] = useState(false);

  const load = () => {
    setError("");
    api
      .request("/api/insider-threat/scores")
      .then((data) => setUsers(data.items || data))
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const filtered = users
    ? highRiskOnly
      ? users.filter((u) => u.threat_level === "high" || u.threat_level === "critical")
      : users
    : [];

  const stats = users
    ? {
        total: users.length,
        high: users.filter((u) => u.threat_level === "high" || u.threat_level === "critical").length,
      }
    : null;

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Insider Threat Scoring"
        subtitle="User risk scoring and threat indicator analysis"
        label="Insider Threat"
      />

      {error && <ErrorBanner message={error} onRetry={load} />}

      {stats && (
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Users</p>
            <p className="mt-1 text-[24px] font-bold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>
              {stats.total}
            </p>
          </Card>
          <Card className="p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">High Risk</p>
            <p className="mt-1 text-[24px] font-bold tabular-nums text-[var(--severity-critical)]" style={{ fontFeatureSettings: '"tnum"' }}>
              {stats.high}
            </p>
          </Card>
        </div>
      )}

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setHighRiskOnly(!highRiskOnly)}
          className={`rounded-lg px-3 py-1.5 text-[12px] font-medium transition-all ${
            highRiskOnly
              ? "bg-[var(--severity-critical)]/10 text-[var(--severity-critical)] border border-[var(--severity-critical)]/30"
              : "bg-[var(--bg-inset)] text-[var(--fg-muted)] border border-[var(--border-default)] hover:text-[var(--fg-secondary)]"
          }`}
        >
          High Risk Only
        </button>
        <span className="text-[11px] text-[var(--fg-muted)]">
          {filtered.length} user{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {!users && !error && <Loading label="Loading threat scores" />}

      {users && filtered.length === 0 && (
        <Card className="flex flex-col items-center justify-center py-16 text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-[var(--radius-2xl)] bg-[var(--bg-surface-active)]">
            <span className="text-2xl">&#128274;</span>
          </div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">
            {highRiskOnly ? "No high-risk users" : "No users scored yet"}
          </h3>
          <p className="mt-1.5 max-w-sm text-sm text-[var(--fg-muted)] leading-relaxed">
            {highRiskOnly ? "All users are within normal risk parameters." : "User behavior baselines are being established."}
          </p>
        </Card>
      )}

      {users && (
        <div className="space-y-2">
          {filtered.map((u) => (
            <ThreatScoreCard
              key={u.user || u.username || u.id}
              user={u}
              expanded={expanded === (u.user || u.username)}
              onToggle={() => setExpanded(expanded === (u.user || u.username) ? null : (u.user || u.username))}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default memo(InsiderThreat);
