import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  AreaChart,
  Area,
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
import StatCard from "../components/StatCard.jsx";
import ScoreRing from "../components/ScoreRing.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { Loading, EmptyState } from "../components/Feedback.jsx";

const PIE_COLORS = ["#f87171", "#fb923c", "#fbbf24", "#38bdf8", "#64748b"];
const BAR_COLORS = ["#22d3ee", "#f87171", "#fbbf24", "#a78bfa", "#34d399", "#f472b6"];

function PageCard({ title, right, children }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">{title}</h2>
        {right}
      </div>
      {children}
    </div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [categories, setCategories] = useState([]);
  const [severity, setSeverity] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [topAttackers, setTopAttackers] = useState([]);
  const [userBehavior, setUserBehavior] = useState([]);
  const [detectionMethods, setDetectionMethods] = useState([]);
  const [riskDistribution, setRiskDistribution] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    Promise.all([
      api.summary(),
      api.timeline(24),
      api.threatCategories(),
      api.severityDistribution(),
      api.attackStats(),
      api.topAttackers(5),
      api.userBehavior(8),
      api.detectionMethods(),
      api.riskDistribution(),
      api.alerts({ page_size: 8 }),
    ])
      .then(([s, t, c, sev, att, ta, ub, dm, rd, al]) => {
        setSummary(s);
        setTimeline(t);
        setCategories(c);
        setSeverity(sev);
        setAttacks(att);
        setTopAttackers(ta);
        setUserBehavior(ub);
        setDetectionMethods(dm);
        setRiskDistribution(rd);
        setAlerts(al.items || []);
      })
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  if (error && !summary) return <div className="text-sm text-red-400">{error}</div>;
  if (!summary) return <Loading label="Loading dashboard" />;

  const timelineData = (timeline?.events || []).map((e) => ({
    ...e,
    label: (e.bucket || "").slice(11, 16),
    alerts: (timeline.alerts || []).find((a) => a.bucket === e.bucket)?.count || 0,
  }));
  const severityData = (severity || []).filter((s) => s.count > 0);

  const currentRisk = (riskDistribution || []).find((r) => r.count > 0)?.risk_level || "LOW";
  const riskColor =
    currentRisk === "CRITICAL" ? "text-red-400" : currentRisk === "HIGH" ? "text-orange-400"
    : currentRisk === "MEDIUM" ? "text-amber-400" : "text-emerald-400";
  const methodData = (detectionMethods || []).map((m) => ({
    ...m,
    label: m.method === "hybrid" ? "Hybrid (rule+ML)" : m.method === "ml" ? "ML-only" : "Rule-based",
  }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <div className="flex items-center gap-4 rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <ScoreRing score={summary.security_score} />
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-500">System status</p>
            <p
              className={`mt-1 text-lg font-bold ${
                summary.system_status === "HEALTHY"
                  ? "text-emerald-400"
                  : summary.system_status === "ATTENTION"
                  ? "text-amber-400"
                  : "text-red-400"
              }`}
            >
              {summary.system_status}
            </p>
          </div>
        </div>
        <StatCard label="Total events" value={summary.total_events.toLocaleString()} sub={`${summary.events_last_hour} in last hour`} accent="text-slate-100" icon="≡" />
        <StatCard label="Active alerts" value={summary.active_alerts} accent="text-amber-400" icon="⚠" />
        <StatCard label="Critical threats" value={summary.critical_threats} accent="text-red-400" icon="‼" />
        <StatCard label="Anomalies (ML)" value={summary.anomalies_detected} accent="text-violet-400" icon="◈" />
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">Current risk level</p>
          <p className={`mt-2 text-2xl font-bold ${riskColor}`}>{currentRisk}</p>
          <p className="mt-1 text-xs text-slate-500">
            {(riskDistribution || []).filter((r) => r.count > 0).length} level(s) on open alerts
          </p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <PageCard title="Event & alert timeline (24h)">
          {timelineData.length === 0 ? (
            <EmptyState message="No events collected yet" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={timelineData}>
                <defs>
                  <linearGradient id="evt" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="alt" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f87171" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#f87171" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#475569" fontSize={11} />
                <YAxis stroke="#475569" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Area type="monotone" dataKey="count" name="Events" stroke="#22d3ee" fill="url(#evt)" strokeWidth={2} />
                <Area type="monotone" dataKey="alerts" name="Alerts" stroke="#f87171" fill="url(#alt)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </PageCard>

        <PageCard title="Threat categories (MITRE tactics)">
          {categories.length === 0 ? (
            <EmptyState message="No open alerts" />
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={categories}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="tactic" stroke="#475569" fontSize={11} />
                <YAxis stroke="#475569" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                  {categories.map((_, i) => (
                    <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </PageCard>

        <PageCard title="Severity distribution">
          {severityData.length === 0 ? (
            <EmptyState message="No open alerts" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityData} dataKey="count" nameKey="severity" innerRadius={45} outerRadius={80} paddingAngle={2}>
                  {severityData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                />
                <Legend wrapperStyle={{ fontSize: 12, color: "#94a3b8" }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </PageCard>

        <PageCard title="Attack statistics">
          {attacks.length === 0 ? (
            <EmptyState message="No open alerts" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={attacks} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#475569" fontSize={11} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="attack"
                  stroke="#475569"
                  fontSize={10}
                  width={180}
                  tickFormatter={(v) => (v.length > 26 ? `${v.slice(0, 26)}…` : v)}
                />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Bar dataKey="count" name="Alerts" fill="#22d3ee" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </PageCard>

        <PageCard title="User behavior (logins)">
          {userBehavior.length === 0 ? (
            <EmptyState message="No login events yet" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={userBehavior}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="user" stroke="#475569" fontSize={10} />
                <YAxis stroke="#475569" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="successes" name="Success" stackId="a" fill="#34d399" radius={[2, 2, 0, 0]} />
                <Bar dataKey="failures" name="Failures" stackId="a" fill="#f87171" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </PageCard>

        <PageCard title="Detection method breakdown">
          {methodData.length === 0 ? (
            <EmptyState message="No open alerts" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={methodData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="label" stroke="#475569" fontSize={10} />
                <YAxis stroke="#475569" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                />
                <Bar dataKey="count" name="Alerts" fill="#a78bfa" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </PageCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Latest alerts</h2>
          {alerts.length === 0 ? (
            <EmptyState message="No alerts yet" />
          ) : (
            <div className="space-y-2">
              {alerts.map((a) => (
                <Link
                  key={a.id}
                  to={`/alerts/${a.id}`}
                  className="flex items-center justify-between gap-4 rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2.5 transition-colors hover:border-slate-700"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <SeverityBadge severity={a.severity} />
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-slate-200">{a.name}</p>
                      <p className="truncate font-mono text-[11px] text-slate-500">
                        {a.mitre_id} · {a.mitre_tactic}
                      </p>
                    </div>
                  </div>
                  <div className="shrink-0 text-right text-[11px] text-slate-500">
                    <p>{a.created_at ? new Date(a.created_at).toLocaleString() : "—"}</p>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Top targets</h2>
          {topAttackers.length === 0 ? (
            <EmptyState message="No credential attacks" />
          ) : (
            <div className="space-y-2">
              {topAttackers.map((t) => (
                <div key={t.user} className="flex items-center justify-between rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2 text-sm">
                  <span className="truncate font-mono text-slate-300">{t.user}</span>
                  <span className="text-xs text-slate-500">{t.count} hit(s)</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
