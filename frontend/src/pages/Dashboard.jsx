import { useEffect, useState } from "react";
import { Link } from "react-router";
import {
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import ChartTooltip from "../components/ChartTooltip.jsx";
import HeartbeatChart from "../components/HeartbeatChart.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import {
  BoltIcon,
  AlertsIcon,
  BoxesIcon,
  AlertIcon,
  RefreshIcon,
} from "../components/icons.jsx";

const RISK_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#3b82f6",
};

const SEVERITY_BAR = {
  critical: "#ef4444",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#94a3b8",
};

const KPI_ACCENT = {
  cyan: {
    bar: "#22d3ee",
    text: "text-cyan-300",
    glow: "shadow-[0_8px_32px_-10px_rgba(34,211,238,0.3)]",
    grad: "from-cyan-500/15 via-slate-900/50 to-slate-900/60 border-cyan-500/25",
  },
  green: {
    bar: "#34d399",
    text: "text-emerald-300",
    glow: "shadow-[0_8px_32px_-10px_rgba(52,211,153,0.25)]",
    grad: "from-emerald-500/15 via-slate-900/50 to-slate-900/60 border-emerald-500/25",
  },
  orange: {
    bar: "#fb923c",
    text: "text-orange-300",
    glow: "shadow-[0_8px_32px_-10px_rgba(251,146,60,0.25)]",
    grad: "from-orange-500/15 via-slate-900/50 to-slate-900/60 border-orange-500/25",
  },
  red: {
    bar: "#f87171",
    text: "text-red-300",
    glow: "shadow-[0_8px_32px_-10px_rgba(248,113,113,0.25)]",
    grad: "from-red-500/15 via-slate-900/50 to-slate-900/60 border-red-500/25",
  },
};

function MetricBox({ label, value, icon: Icon, trend, color = "cyan", sub }) {
  const accent = KPI_ACCENT[color] || KPI_ACCENT.cyan;
  return (
    <div
      className={`relative overflow-hidden rounded-xl border bg-gradient-to-br backdrop-blur-sm ${accent.grad} ${accent.glow}`}
    >
      <span
        className="absolute inset-x-0 top-0 h-[2px]"
        style={{
          background: `linear-gradient(90deg, transparent, ${accent.bar}, transparent)`,
        }}
      />
      <div className="absolute -right-8 -top-8 h-28 w-28 rounded-full opacity-25 blur-2xl"
        style={{ backgroundColor: accent.bar }}
      />
      <div className="flex items-start justify-between gap-2 p-5">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-slate-500">
            {label}
          </p>
          <p className={`mt-2 text-3xl font-semibold tracking-tight ${accent.text}`}>{value}</p>
          {sub && <p className="mt-0.5 text-xs text-slate-500">{sub}</p>}
          {trend && (
            <p className="mt-2.5 inline-flex truncate rounded-md bg-black/20 px-2 py-0.5 text-[11px] text-slate-300">
              {trend}
            </p>
          )}
        </div>
        <Icon className="h-6 w-6 shrink-0 opacity-60" />
      </div>
    </div>
  );
}

function ChartCard({ title, subtitle, children, action }) {
  return (
    <Card>
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-white">{title}</h3>
          {subtitle && <p className="mt-0.5 text-sm text-slate-400">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </Card>
  );
}

function AlertCard({ alert }) {
  const severity = (alert.severity || "info").toLowerCase();
  const bar = SEVERITY_BAR[severity] || SEVERITY_BAR.info;

  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-800/60 bg-slate-900/50 p-4 transition-colors hover:border-slate-700/70">
      <span className="absolute inset-y-0 left-0 w-[3px]" style={{ backgroundColor: bar }} />
      <div className="min-w-0 flex-1 pl-3">
        <div className="flex items-start justify-between gap-3">
          <h4 className="truncate text-sm font-medium text-slate-100">{alert.name}</h4>
          <span className="shrink-0 rounded border border-white/5 bg-black/30 px-2 py-0.5 font-mono text-[10px] text-slate-400">
            {alert.mitre_id}
          </span>
        </div>
        <p className="mt-1 line-clamp-2 text-xs text-slate-400">{alert.evidence}</p>
        <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500">
          <span>
            Risk:{" "}
            <strong className="font-mono text-slate-300">
              {alert.risk_score?.toFixed(0) ?? "—"}
            </strong>
          </span>
          <span>
            {alert.created_at
              ? new Date(alert.created_at).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "—"}
          </span>
        </div>
      </div>
    </div>
  );
}

function UserBehaviorRow({ user }) {
  const total = (user.successes || 0) + (user.failures || 0);
  const failPct = total > 0 ? Math.round(((user.failures || 0) / total) * 100) : 0;

  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-900/50 p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-slate-100">{user.user || "Unknown"}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            <span className="text-emerald-400">{user.successes ?? 0}</span> successful ·{" "}
            <span className="text-red-400">{user.failures ?? 0}</span> failed
          </p>
        </div>
        <div className="shrink-0 text-right">
          <p className="font-mono text-sm font-semibold text-cyan-400">
            {user.avg_risk?.toFixed(0) ?? "—"}
          </p>
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Avg risk</p>
        </div>
      </div>
      <div className="mt-2.5 flex h-1 overflow-hidden rounded-full bg-slate-800/70">
        <div
          className="h-full bg-emerald-500/80"
          style={{ width: `${100 - failPct}%` }}
          title="Successful logons"
        />
        <div
          className="h-full bg-red-500/80"
          style={{ width: `${failPct}%` }}
          title="Failed logons"
        />
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [categories, setCategories] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [topAttackers, setTopAttackers] = useState([]);
  const [userBehavior, setUserBehavior] = useState([]);
  const [detectionMethods, setDetectionMethods] = useState([]);
  const [riskDistribution, setRiskDistribution] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = () => {
    setError("");
    Promise.all([
      api.summary(),
      api.timeline(24),
      api.threatCategories(),
      api.attackStats(),
      api.topAttackers(5),
      api.userBehavior(8),
      api.detectionMethods(),
      api.riskDistribution(),
      api.alerts({ page_size: 8 }),
    ])
      .then(([s, t, c, att, ta, ub, dm, rd, al]) => {
        setSummary(s);
        setTimeline(t);
        setCategories(c);
        setAttacks(att);
        setTopAttackers(ta);
        setUserBehavior(ub);
        setDetectionMethods(dm);
        setRiskDistribution(rd);
        setAlerts(al.items || []);
        setLastUpdated(new Date());
      })
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  if (error && !summary)
    return <ErrorBanner message={error} onRetry={load} />;
  if (!summary) return <Loading label="Loading dashboard" />;

  const timelineData = (timeline?.events || []).map((e) => ({
    ...e,
    label: (e.bucket || "").slice(11, 16),
    alerts: (timeline.alerts || []).find((a) => a.bucket === e.bucket)?.count || 0,
  }));

  const riskData = (riskDistribution || [])
    .filter((r) => r.count > 0)
    .map((r) => ({
      name: r.risk_level,
      value: r.count,
      color: RISK_COLORS[r.risk_level] || "#64748b",
    }));

  const detectionData = (detectionMethods || [])
    .filter((d) => d.count > 0)
    .map((d) => ({
      name: String(d.method || "rule").toUpperCase(),
      value: d.count,
    }));

  const showPieLabel = ({ percent, name }) =>
    percent > 0.06 ? `${name} ${(percent * 100).toFixed(0)}%` : "";

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Security Overview"
        subtitle="Real-time threat detection and analysis"
        actions={
          <button
            type="button"
            onClick={load}
            className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/[0.08]"
          >
            <RefreshIcon className="h-4 w-4" />
            Refresh
          </button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricBox
          label="Security Score"
          value={Math.round(summary?.security_score ?? 0)}
          icon={BoltIcon}
          sub="/ 100"
          trend={`Risk level: ${summary?.risk_level ?? summary?.system_status ?? "UNKNOWN"}`}
          color={
            summary?.risk_level === "CRITICAL" || summary?.system_status === "CRITICAL"
              ? "red"
              : summary?.risk_level === "HIGH" || summary?.system_status === "ATTENTION"
                ? "orange"
                : "green"
          }
        />
        <MetricBox
          label="Active Alerts"
          value={summary?.active_alerts ?? 0}
          icon={AlertsIcon}
          trend="Open threats requiring attention"
          color={(summary?.active_alerts ?? 0) > 5 ? "red" : "orange"}
        />
        <MetricBox
          label="Total Events"
          value={(summary?.total_events ?? 0).toLocaleString()}
          icon={BoxesIcon}
          sub="Normalized telemetry"
          trend={`${summary?.events_last_hour ?? 0} in the last hour`}
          color="cyan"
        />
        <MetricBox
          label="Critical Threats"
          value={summary?.critical_threats ?? 0}
          icon={AlertIcon}
          sub="Open critical / high alerts"
          trend={summary?.anomalies_detected ? `${summary.anomalies_detected} ML anomalies` : "No ML anomalies"}
          color={(summary?.critical_threats ?? 0) > 0 ? "red" : "green"}
        />
      </div>

      {/* Primary charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ChartCard
            title="Event Timeline"
            subtitle="Heartbeat monitor — event volume and alerts over the last 24 hours"
          >
            <div className="h-80">
              <HeartbeatChart data={timelineData} />
            </div>
          </ChartCard>
        </div>

        <ChartCard title="Risk Distribution" subtitle="Open alerts by hybrid risk level">
          <div className="h-80">
            {riskData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    cx="50%"
                    cy="45%"
                    labelLine={false}
                    label={showPieLabel}
                    outerRadius={85}
                    innerRadius={45}
                    dataKey="value"
                    nameKey="name"
                  >
                    {riskData.map((entry, index) => (
                      <Cell key={`risk-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                  <Legend
                    verticalAlign="bottom"
                    wrapperStyle={{ fontSize: 12 }}
                    formatter={(value) => (
                      <span className="text-slate-300">{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No alerts" subtitle="No open alerts to classify" />
            )}
          </div>
        </ChartCard>
      </div>

      {/* Secondary charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ChartCard title="MITRE ATT&CK Tactics" subtitle="Detected attack techniques">
          <div className="h-72">
            {categories.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categories.slice(0, 8)} margin={{ left: -12 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                  <XAxis
                    dataKey="tactic"
                    stroke="#64748b"
                    fontSize={11}
                    angle={-30}
                    textAnchor="end"
                    interval={0}
                    tickLine={false}
                  />
                  <YAxis stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(148,163,184,0.06)" }} />
                  <Bar dataKey="count" name="Alerts" fill="#06b6d4" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No tactics mapped" subtitle="No open alerts to analyze" />
            )}
          </div>
        </ChartCard>

        <ChartCard
          title="Detection Method Breakdown"
          subtitle="Rule-based vs hybrid ML detection"
        >
          <div className="h-72">
            {detectionData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={detectionData}
                    cx="50%"
                    cy="45%"
                    labelLine={false}
                    label={showPieLabel}
                    outerRadius={85}
                    innerRadius={45}
                    dataKey="value"
                    nameKey="name"
                  >
                    {detectionData.map((entry, index) => (
                      <Cell
                        key={`det-${index}`}
                        fill={entry.name === "RULE" ? "#06b6d4" : "#8b5cf6"}
                        stroke="#0f172a"
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                  <Legend
                    verticalAlign="bottom"
                    wrapperStyle={{ fontSize: 12 }}
                    formatter={(value) => <span className="text-slate-300">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No detections" subtitle="No open alerts to classify" />
            )}
          </div>
        </ChartCard>
      </div>

      {/* Attack stats and user behavior */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ChartCard title="Top Attack Types" subtitle="Most frequently detected threats">
          <div className="h-72">
            {attacks.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attacks.slice(0, 6)} layout="vertical" margin={{ left: 12 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                  <XAxis type="number" stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                  <YAxis
                    dataKey="attack"
                    type="category"
                    width={140}
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                  />
                  <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(148,163,184,0.06)" }} />
                  <Bar dataKey="count" name="Alerts" fill="#10b981" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No attack data" subtitle="No open alerts to summarize" />
            )}
          </div>
        </ChartCard>

        <ChartCard title="User Account Activity" subtitle="Login success and failure patterns">
          <div className="space-y-3">
            {userBehavior.length > 0 ? (
              userBehavior.slice(0, 6).map((user, idx) => (
                <UserBehaviorRow key={idx} user={user} />
              ))
            ) : (
              <EmptyState title="No login activity" subtitle="No authentication events recorded" />
            )}
          </div>
        </ChartCard>
      </div>

      {/* Recent alerts */}
      <Card>
        <div className="mb-5 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-white">Recent Alerts</h3>
            <p className="mt-0.5 text-sm text-slate-400">
              Latest security events and detections
            </p>
          </div>
          <Link
            to="/alerts"
            className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
          >
            View all →
          </Link>
        </div>

        {alerts.length > 0 ? (
          <div className="grid grid-cols-1 gap-3">
            {alerts.slice(0, 6).map((alert) => (
              <Link
                key={alert.id}
                to={`/alerts/${alert.id}`}
                className="block rounded-xl transition-transform hover:scale-[1.005]"
              >
                <AlertCard alert={alert} />
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState
            title="No alerts"
            subtitle="System is operating normally"
            icon="🛡"
          />
        )}
      </Card>

      {/* Top attackers */}
      {topAttackers.length > 0 && (
        <Card>
          <div className="mb-5">
            <h3 className="text-base font-semibold text-white">Top Attack Sources</h3>
            <p className="mt-0.5 text-sm text-slate-400">
              Accounts most frequently targeted by brute-force attempts (T1110)
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {topAttackers.map((attacker, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-100">
                      {attacker.user || "Unknown"}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Targeted{" "}
                      <strong className="font-mono text-slate-300">{attacker.count}</strong>{" "}
                      times
                    </p>
                  </div>
                  <span className="rounded border border-white/5 bg-red-500/10 px-2 py-1 font-mono text-[10px] font-medium text-red-400">
                    T1110
                  </span>
                </div>
                <div className="mt-3 h-1 overflow-hidden rounded-full bg-slate-800/70">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-red-500/70 to-orange-400/70"
                    style={{ width: `${Math.min(100, attacker.count * 10)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {lastUpdated && (
        <p className="text-right text-[11px] text-slate-600">
          Last updated {lastUpdated.toLocaleTimeString()}
        </p>
      )}
    </div>
  );
}
