import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { EmptyState, ErrorBanner, Loading } from "../components/Feedback.jsx";
import { AssistantIcon, RefreshIcon, ShieldIcon } from "../components/icons.jsx";

const KIND_COLORS = {
  user: "#38bdf8",
  device: "#818cf8",
  process: "#f472b6",
  ip: "#fb923c",
  domain: "#34d399",
  file: "#e879f9",
  technique: "#a3e635",
  threat_actor: "#f87171",
};

const RISK_COLORS = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-amber-400",
  LOW: "text-emerald-400",
};

const TILE_ACCENT = {
  cyan: "border-cyan-500/25 from-cyan-500/15 text-cyan-300",
  red: "border-red-500/25 from-red-500/15 text-red-300",
  amber: "border-amber-500/25 from-amber-500/15 text-amber-300",
  violet: "border-violet-500/25 from-violet-500/15 text-violet-300",
  emerald: "border-emerald-500/25 from-emerald-500/15 text-emerald-300",
  orange: "border-orange-500/25 from-orange-500/15 text-orange-300",
};

function StatTile({ label, value, sub, accent = "cyan" }) {
  const a = TILE_ACCENT[accent] || TILE_ACCENT.cyan;
  return (
    <div
      className={`relative overflow-hidden rounded-xl border bg-gradient-to-br to-slate-900/60 p-4 backdrop-blur-sm ${a}`}
    >
      <p className="text-[10px] font-medium uppercase tracking-[0.08em] text-slate-500">
        {label}
      </p>
      <p className="mt-1.5 text-2xl font-semibold tracking-tight">{value}</p>
      {sub && <p className="mt-0.5 truncate text-[11px] text-slate-500">{sub}</p>}
    </div>
  );
}

function WatchlistRow({ entity, analyzing, onClick }) {
  const color = KIND_COLORS[entity.kind] || "#64748b";
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex w-full items-center justify-between gap-3 rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2 text-left transition-colors hover:border-cyan-500/40 hover:bg-slate-800/50"
    >
      <span className="flex min-w-0 items-center gap-2.5">
        <span
          className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-[10px] font-bold text-slate-950"
          style={{ backgroundColor: color }}
        >
          {(entity.kind || "?").slice(0, 1).toUpperCase()}
        </span>
        <span className="min-w-0">
          <span className="block truncate font-mono text-xs text-slate-200">{entity.name}</span>
          <span className="block text-[10px] text-slate-500">
            {entity.kind} · {entity.events_count} events · {entity.alerts_count} alerts
          </span>
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        <RiskBadge level={entity.risk_level} score={entity.risk_score} />
        {analyzing === true && <span className="animate-pulse text-[10px] text-cyan-400">AI…</span>}
      </span>
    </button>
  );
}

export default function CommandCenter() {
  const [summary, setSummary] = useState(null);
  const [entityStatus, setEntityStatus] = useState(null);
  const [entities, setEntities] = useState([]);
  const [actors, setActors] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const [aiKind, setAiKind] = useState("ip");
  const [aiName, setAiName] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const [aiOutput, setAiOutput] = useState("");
  const [aiError, setAiError] = useState("");

  const load = useCallback(() => {
    setError("");
    Promise.all([
      api.summary(),
      api.entityStatus(),
      api.entities({ min_risk: 50, limit: 5 }),
      api.entities({ kind: "threat_actor", limit: 4 }),
      api.incidents({}),
      api.alerts({ page_size: 6 }),
    ])
      .then(([s, es, en, at, inc, al]) => {
        setSummary(s);
        setEntityStatus(es);
        setEntities(en.items || []);
        setActors(at.items || []);
        setIncidents(inc.items || []);
        setAlerts(al.items || []);
        setLastUpdated(new Date());
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 20000);
    return () => clearInterval(timer);
  }, [load]);

  const runAi = useCallback(
    (kind, name) => {
      const k = kind ?? aiKind;
      const n = (name ?? aiName).trim();
      if (!n || aiBusy) return;
      setAiBusy(true);
      setAiError("");
      setAiOutput("");
      api
        .assistantEntityExplain(k, n)
        .then((r) => setAiOutput(r.reply))
        .catch((e) => setAiError(e.message))
        .finally(() => setAiBusy(false));
    },
    [aiKind, aiName, aiBusy],
  );

  const briefing = () => {
    setAiBusy(true);
    setAiError("");
    setAiOutput("");
    api
      .assistantSummarize()
      .then((r) => setAiOutput(r.reply))
      .catch((e) => setAiError(e.message))
      .finally(() => setAiBusy(false));
  };

  const analyzeEntity = (ent) => {
    setAiKind(ent.kind);
    setAiName(ent.name);
    runAi(ent.kind, ent.name);
  };

  const activeIncidents = (incidents || []).filter(
    (i) => !["closed", "resolved"].includes(String(i.status || "").toLowerCase()),
  );

  if (error && !summary && !entityStatus)
    return <ErrorBanner message={error} onRetry={load} />;
  if (loading) return <Loading label="Loading command center" />;

  const score = summary?.security_score ?? 0;

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Command Center"
        subtitle="Live watch over entities, open cases and analyst intelligence"
        actions={
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-[11px] ${
                score >= 70
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : score >= 40
                    ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                    : "border-red-500/30 bg-red-500/10 text-red-300"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  score >= 70 ? "bg-emerald-400" : score >= 40 ? "bg-amber-400" : "bg-red-400"
                }`}
              />
              {summary?.system_status ?? "UNKNOWN"}
            </span>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/[0.08]"
            >
              <RefreshIcon className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile
          label="Security Score"
          value={`${Math.round(score)}/100`}
          sub={`${summary?.system_status || "—"} posture`}
          accent={score >= 70 ? "emerald" : score >= 40 ? "amber" : "red"}
        />
        <StatTile
          label="Open Alerts"
          value={summary?.active_alerts ?? 0}
          sub={`${summary?.critical_threats ?? 0} critical / high`}
          accent={(summary?.active_alerts ?? 0) > 0 ? "orange" : "cyan"}
        />
        <StatTile
          label="Active Cases"
          value={activeIncidents.length}
          sub={`of ${(incidents || []).length} total incidents`}
          accent={activeIncidents.length > 0 ? "violet" : "cyan"}
        />
        <StatTile
          label="Entities Tracked"
          value={(entityStatus?.total_entities ?? 0).toLocaleString()}
          sub={`${(entityStatus?.total_edges ?? 0).toLocaleString()} relationships`}
          accent="cyan"
        />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Entity watchlist */}
        <Card className="lg:col-span-1">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">Entity Watchlist</h3>
              <p className="mt-0.5 text-sm text-slate-400">
                Highest-risk entities in the graph
              </p>
            </div>
            <Link
              to="/entities"
              className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
            >
              Open graph →
            </Link>
          </div>
          <div className="space-y-2">
            {entities.length > 0 ? (
              entities.map((e) => (
                <WatchlistRow key={`${e.kind}:${e.name}`} entity={e} onClick={() => analyzeEntity(e)} />
              ))
            ) : (
              <EmptyState title="No risky entities" subtitle="Everything is within normal baseline" />
            )}
          </div>
          <div className="mt-4 flex items-center gap-2 border-t border-slate-800/50 pt-3 text-[10px] text-slate-500">
            <ShieldIcon className="h-3.5 w-3.5" />
            Click an entity to run instant AI analysis
          </div>
        </Card>

        {/* Active cases */}
        <Card className="lg:col-span-1">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">Active Cases</h3>
              <p className="mt-0.5 text-sm text-slate-400">
                Incidents needing attention
              </p>
            </div>
            <Link
              to="/incidents"
              className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
            >
              All incidents →
            </Link>
          </div>
          <div className="space-y-2">
            {activeIncidents.length > 0 ? (
              activeIncidents.slice(0, 6).map((inc) => (
                <Link
                  key={inc.id}
                  to={`/incidents`}
                  className="block rounded-xl border border-slate-800/60 bg-slate-900/40 p-3 transition-colors hover:border-slate-600"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-slate-100">{inc.title}</p>
                      <p className="mt-0.5 font-mono text-[10px] text-slate-500">
                        {inc.ref || `INC-${inc.id}`}
                      </p>
                    </div>
                    <span className="flex shrink-0 flex-col items-end gap-1">
                      <SeverityBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                    </span>
                  </div>
                  {inc.alert_count > 0 && (
                    <p className="mt-2 text-[10px] text-slate-500">
                      {inc.alert_count} linked alert{inc.alert_count === 1 ? "" : "s"}
                      {inc.mitre_id ? ` · ${inc.mitre_id}` : ""}
                    </p>
                  )}
                </Link>
              ))
            ) : (
              <EmptyState title="No active cases" subtitle="The queue is clear" icon="🛡" />
            )}
          </div>
        </Card>

        {/* AI analyst panel */}
        <Card className="lg:col-span-1">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">AI Analyst</h3>
              <p className="mt-0.5 text-sm text-slate-400">
                Briefing and on-demand entity analysis
              </p>
            </div>
            <AssistantIcon className="h-6 w-6 text-violet-400" />
          </div>

          <div className="flex items-center gap-2">
            <select
              value={aiKind}
              onChange={(e) => setAiKind(e.target.value)}
              className="rounded-lg border border-slate-700/60 bg-slate-900/70 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500/50"
            >
              {["ip", "user", "device", "domain", "file", "process"].map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <input
              value={aiName}
              onChange={(e) => setAiName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runAi()}
              placeholder="IP, host, hash…"
              className="min-w-0 flex-1 rounded-lg border border-slate-700/60 bg-slate-900/70 px-2.5 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
            />
            <button
              type="button"
              onClick={() => runAi()}
              disabled={aiBusy || !aiName.trim()}
              className="shrink-0 rounded-lg bg-violet-500/15 px-3 py-1.5 text-xs font-semibold text-violet-300 ring-1 ring-violet-500/40 transition-colors hover:bg-violet-500/25 disabled:opacity-50"
            >
              Analyze
            </button>
          </div>

          <button
            type="button"
            onClick={briefing}
            disabled={aiBusy}
            className="mt-2 w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/[0.08] disabled:opacity-50"
          >
            {aiBusy ? "Working…" : "Generate incident briefing"}
          </button>

          {aiError && (
            <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
              {aiError}
            </div>
          )}

          {aiBusy && <Loading label="Analysing" />}

          {aiOutput && (
            <div className="mt-3 max-h-72 overflow-y-auto rounded-xl border border-slate-700/50 bg-slate-950/50 p-3">
              <p className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-slate-300">
                {aiOutput}
              </p>
            </div>
          )}
        </Card>
      </div>

      {/* Threat actor view */}
      <Card>
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-white">Threat Actor View</h3>
            <p className="mt-0.5 text-sm text-slate-400">
              Hostile clusters attributed from verified IOC verdicts
            </p>
          </div>
          <Link
            to="/entities?kind=threat_actor"
            className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
          >
            Open intelligence graph →
          </Link>
        </div>
        {actors.length > 0 ? (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {actors.map((a) => (
              <button
                key={a.name}
                type="button"
                onClick={() => analyzeEntity(a)}
                className="group rounded-xl border border-slate-800/60 bg-slate-900/40 p-3 text-left transition-colors hover:border-rose-500/40"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded bg-black/30 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-rose-300">
                    <span className="h-1 w-1 rounded-full bg-rose-400" />
                    {a.kind === "threat_actor" ? "threat_actor" : a.kind}
                  </span>
                  <RiskBadge level={a.risk_level} score={a.risk_score} />
                </div>
                <p className="mt-2 truncate text-xs font-semibold text-slate-100" title={a.name}>
                  {a.name}
                </p>
                <p className="mt-1 text-[10px] text-slate-500">
                  {a.events_count} linked indicators · {a.properties?.category || "—"}
                </p>
              </button>
            ))}
          </div>
        ) : (
          <EmptyState
            title="No attributed actors"
            subtitle="Clusters appear once alerts produce verified, high-confidence IOCs"
            icon="🎭"
          />
        )}
        <div className="mt-4 flex items-center gap-2 border-t border-slate-800/50 pt-3 text-[10px] text-slate-500">
          <ShieldIcon className="h-3.5 w-3.5" />
          Actors derive from analyst overrides & embedded IOC signatures — never fabricated group names.
          Click an actor to run AI analysis.
        </div>
      </Card>

      {/* Open alerts strip */}
      <Card>
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-white">Open Alerts</h3>
            <p className="mt-0.5 text-sm text-slate-400">Most recent detections</p>
          </div>
          <Link
            to="/alerts"
            className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
          >
            View all →
          </Link>
        </div>
        {alerts.length > 0 ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {alerts.map((a) => (
              <Link
                key={a.id}
                to={`/alerts/${a.id}`}
                className="block rounded-xl border border-slate-800/60 bg-slate-900/40 p-3.5 transition-colors hover:border-slate-600"
              >
                <div className="flex items-start justify-between gap-2">
                  <h4 className="min-w-0 truncate text-sm font-medium text-slate-100">{a.name}</h4>
                  <span className="shrink-0 rounded border border-white/5 bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-slate-400">
                    {a.mitre_id}
                  </span>
                </div>
                <p className="mt-1.5 line-clamp-2 text-xs text-slate-400">{a.evidence}</p>
                <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500">
                  <span
                    className={`font-mono font-semibold ${RISK_COLORS[a.risk_level] || "text-slate-400"}`}
                  >
                    {a.risk_score?.toFixed ? a.risk_score.toFixed(0) : a.risk_score ?? "—"}
                  </span>
                  <span>
                    {a.created_at
                      ? new Date(a.created_at).toLocaleString([], {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })
                      : "—"}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState title="No open alerts" subtitle="System is operating normally" icon="🛡" />
        )}
      </Card>

      {lastUpdated && (
        <p className="text-right text-[11px] text-slate-600">
          Last updated {lastUpdated.toLocaleTimeString()} · {summary?.total_events?.toLocaleString()} total events ·{" "}
          {entityStatus?.provider ?? "postgres"} graph provider
        </p>
      )}
    </div>
  );
}