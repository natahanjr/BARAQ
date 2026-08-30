import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api.js";
import { ErrorBanner } from "../Feedback.jsx";
import { Badge, MetricCard, RiskGauge, Card, CardHeader, CardTitle, CardContent } from "../ui/index.js";

const REFRESH_MS = 30000;

const timeAgo = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const greeting = () => {
  const h = new Date().getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 17) return "Good afternoon";
  return "Good evening";
};

const reducedMotion = () =>
  window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

const SEV_COLOR = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
  info: "var(--fg-muted)",
};

const SEV_DOT = {
  critical: "bg-[var(--severity-critical)]",
  high: "bg-[var(--severity-high)]",
  medium: "bg-[var(--severity-medium)]",
  low: "bg-[var(--severity-low)]",
  info: "bg-[var(--fg-muted)]",
};

/* ── Score Ring ─────────────────────────────────────────────────────── */

function ScoreRing({ value }) {
  const R = 56, C = 2 * Math.PI * R;
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (reducedMotion()) { setShown(value); return; }
    const t = setTimeout(() => setShown(value), 150);
    return () => clearTimeout(t);
  }, [value]);

  const color = value >= 80 ? "var(--status-healthy)"
    : value >= 60 ? "var(--severity-medium)"
    : value >= 40 ? "var(--severity-high)"
    : "var(--severity-critical)";

  const label = value >= 80 ? "HEALTHY"
    : value >= 60 ? "FAIR"
    : value >= 40 ? "ATTENTION"
    : "CRITICAL";

  const glowColor = value >= 80 ? "rgba(34,197,94,0.15)"
    : value >= 60 ? "rgba(234,179,8,0.15)"
    : value >= 40 ? "rgba(249,115,22,0.15)"
    : "rgba(239,68,68,0.15)";

  return (
    <div className="relative flex items-center justify-center" style={{ width: 160, height: 160 }}>
      {/* Outer glow */}
      <div
        className="absolute inset-0 rounded-full blur-xl transition-all duration-1000"
        style={{ background: glowColor, opacity: shown > 0 ? 0.6 : 0 }}
      />
      <svg width="160" height="160" viewBox="0 0 160 160">
        {/* Track */}
        <circle cx="80" cy="80" r={R} fill="none" stroke="var(--border-subtle)" strokeWidth="8" />
        {/* Ticks */}
        {[...Array(24)].map((_, i) => {
          const angle = (i / 24) * 360 - 90;
          const rad = (angle * Math.PI) / 180;
          const x1 = 80 + (R + 8) * Math.cos(rad);
          const y1 = 80 + (R + 8) * Math.sin(rad);
          const x2 = 80 + (R + 12) * Math.cos(rad);
          const y2 = 80 + (R + 12) * Math.sin(rad);
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--border-subtle)" strokeWidth="1" />;
        })}
        {/* Progress arc */}
        <circle
          cx="80" cy="80" r={R} fill="none" strokeWidth="8" strokeLinecap="round"
          stroke={color}
          strokeDasharray={C} strokeDashoffset={C - (C * shown) / 100}
          transform="rotate(-90 80 80)"
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.32,0.72,0,1)", filter: `drop-shadow(0 0 6px ${glowColor})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="text-[42px] font-bold tracking-tight text-[var(--fg-primary)] leading-none"
          style={{ fontFeatureSettings: '"tnum"' }}
        >
          {value}
        </span>
        <span
          className="mt-1.5 text-[10px] font-bold uppercase tracking-[var(--tracking-widest)]"
          style={{ color }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}

/* ── Severity Bar ─────────────────────────────────────────────────────── */

function SeverityBar({ counts }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((n, k) => n + (counts?.[k] || 0), 0);
  if (!total) return null;
  return (
    <div className="mt-4">
      <div className="flex overflow-hidden rounded-full" style={{ height: 4, background: "var(--border-subtle)", gap: 2 }}>
        {order.map((k) => {
          const n = counts[k] || 0;
          if (!n) return null;
          return <div key={k} style={{ width: `${(n / total) * 100}%`, background: SEV_COLOR[k], borderRadius: 999, transition: "width 0.8s ease" }} />;
        })}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {order.filter((k) => (counts?.[k] || 0) > 0).map((k) => (
          <span key={k} className="flex items-center gap-1.5 text-[10px] text-[var(--fg-muted)]">
            <span className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[k]}`} />
            {k} · {counts[k]}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ── Alert Row ────────────────────────────────────────────────────────── */

function AlertRow({ alert }) {
  return (
    <Link
      to={`/alerts/${alert.id}`}
      className="flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-[var(--bg-surface-hover)]"
    >
      <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_DOT[alert.severity] || SEV_DOT.info}`} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-[13px] font-medium text-[var(--fg-primary)]">{alert.name}</p>
        <p className="truncate text-[11px] text-[var(--fg-muted)]">
          {alert.host || "unknown"} · {alert.category || alert.rule || "detection"}
        </p>
      </div>
      <span className="text-[11px] text-[var(--fg-muted)]">{timeAgo(alert.created_at)}</span>
      <span className="text-[var(--fg-faint)]">›</span>
    </Link>
  );
}

/* ── Status Row ───────────────────────────────────────────────────────── */

function collectorHealthOk(collectors) {
  if (!collectors || !collectors.channels) return true;
  const channels = collectors.channels;
  if (!Array.isArray(channels) || channels.length === 0) return true;
  const healthy = channels.filter((ch) => ch.ok).length;
  return healthy > 0;
}

function collectorHealthNote(collectors) {
  if (!collectors || !collectors.channels) return "initializing";
  const channels = collectors.channels;
  if (!Array.isArray(channels) || channels.length === 0) return "no channels";
  const healthy = channels.filter((ch) => ch.ok).length;
  const total = channels.length;
  if (healthy === total) return `${total} channels active`;
  return `${healthy}/${total} channels`;
}

function StatusRow({ label, ok, note }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-[var(--border-subtle)] last:border-0">
      <span className="text-[13px] text-[var(--fg-secondary)]">{label}</span>
      <span className="flex items-center gap-2.5">
        <span className="text-[11px] text-[var(--fg-muted)]">{note}</span>
        <span className="relative flex h-2 w-2">
          {ok && <span className="pulse-dot absolute inline-flex h-full w-full rounded-full bg-[var(--status-healthy)] opacity-40" />}
          <span className={`relative inline-flex h-2 w-2 rounded-full ${ok ? "bg-[var(--status-healthy)]" : "bg-[var(--severity-critical)]"}`} />
        </span>
      </span>
    </div>
  );
}

/* ── Skeleton ─────────────────────────────────────────────────────────── */

function Skeleton() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="skeleton h-[240px] rounded-[var(--radius-2xl)]" />
        <div className="grid grid-cols-2 gap-4 lg:col-span-2">
          {[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-[120px] rounded-[var(--radius-2xl)]" />)}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="skeleton h-[200px] rounded-[var(--radius-2xl)] lg:col-span-2" />
        <div className="skeleton h-[200px] rounded-[var(--radius-2xl)]" />
      </div>
    </div>
  );
}

/* ── SVG Icons (stable refs) ──────────────────────────────────────────── */

const EventsSvg = memo(() => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <path d="M2 13L6 9L10 11L16 5" stroke="var(--accent-cyan)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M12 5H16V9" stroke="var(--accent-cyan)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
));
const AlertsSvg = memo(() => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <path d="M9 2L16 14H2L9 2Z" stroke="var(--severity-high)" strokeWidth="1.5" strokeLinejoin="round" />
    <path d="M9 7V10" stroke="var(--severity-high)" strokeWidth="1.5" strokeLinecap="round" />
    <circle cx="9" cy="12.5" r="0.75" fill="var(--severity-high)" />
  </svg>
));
const CriticalSvg = memo(() => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <circle cx="9" cy="9" r="7" stroke="var(--severity-critical)" strokeWidth="1.5" />
    <path d="M9 5V10" stroke="var(--severity-critical)" strokeWidth="1.5" strokeLinecap="round" />
    <circle cx="9" cy="12.5" r="0.75" fill="var(--severity-critical)" />
  </svg>
));
const AnomaliesSvg = memo(() => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <path d="M2 14L5 8L8 11L11 4L16 14" stroke="var(--accent-violet)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
));

/* ═══════════════════════════════════════════════════════════════════════ PAGE */

export default function AppleDashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    try {
      const [summary, alerts, mlStatus, systemHealth, collectorHealth] = await Promise.all([
        api.summary(),
        api.alerts({ page_size: 5 }),
        api.get("/api/system/ml/status").catch(() => ({})),
        api.get("/api/health").catch(() => ({})),
        api.get("/api/system/collectors/health").catch(() => ({})),
      ]);
      if (!alive.current) return;
      setData({
        summary,
        alerts: alerts.items || [],
        totalAlerts: alerts.total ?? (alerts.items || []).length,
        ml: mlStatus || {},
        health: systemHealth || {},
        collectors: collectorHealth || {},
      });
      setUpdated(new Date());
      setError("");
    } catch (err) {
      if (alive.current) setError(err.message);
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    load();
    const timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    return () => { alive.current = false; clearInterval(timer); };
  }, [load]);

  if (error && !data) return <ErrorBanner message={error} onRetry={load} />;
  if (!data) {
    return (
      <div className="pb-10 pt-1">
        <p className="console-label mb-4">COMMAND CENTER</p>
        <Skeleton />
      </div>
    );
  }

  const { summary, alerts, ml, health, collectors } = data;
  const score = summary?.security_score ?? 0;

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* ── Header ────────────────────────────────────────────── */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">
            {greeting()}
          </p>
          <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">
            Command Center
          </h1>
        </div>
        <div className="flex items-center gap-3">
          {updated && (
            <span className="text-[11px] text-[var(--fg-muted)]">
              Last evaluated {timeAgo(updated.toISOString())}
            </span>
          )}
          <span className="inline-flex items-center gap-2 rounded-full border border-[var(--status-healthy-muted)] bg-[var(--status-healthy-muted)] px-3 py-1">
            <span className="relative flex h-1.5 w-1.5">
              <span className="pulse-dot absolute inline-flex h-full w-full rounded-full bg-[var(--status-healthy)] opacity-40" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-[var(--status-healthy)]" />
            </span>
            <span className="text-[11px] font-semibold text-[var(--status-healthy)]">Live</span>
          </span>
        </div>
      </header>

      {/* ── Hero: Security Posture ───────────────────────────── */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Score Ring */}
        <Card className="flex flex-col items-center justify-center gap-3 p-7">
          <ScoreRing value={score} />
          <p className="text-[13px] text-[var(--fg-muted)]">{summary?.system_status || "Analyzing..."}</p>
        </Card>

        {/* KPI Cards */}
        <div className="grid grid-cols-2 gap-4 lg:col-span-2">
          <Link to="/telemetry">
            <MetricCard label="Events" value={summary?.total_events ?? 0} icon={EventsSvg} accent="cyan" trendLabel="Total events processed" />
          </Link>
          <Link to="/alerts?status=open">
            <MetricCard label="Active Alerts" value={summary?.active_alerts ?? 0} icon={AlertsSvg} accent={(summary?.active_alerts ?? 0) > 0 ? "orange" : "green"} trendLabel="Requiring attention" />
          </Link>
          <Link to="/alerts?severity=critical,high">
            <MetricCard label="Critical" value={summary?.critical_threats ?? 0} icon={CriticalSvg} accent={(summary?.critical_threats ?? 0) > 0 ? "red" : "green"} trendLabel="Immediate response needed" />
          </Link>
          <Link to="/telemetry?anomaly=true">
            <MetricCard label="Anomalies" value={summary?.anomalies_detected ?? 0} icon={AnomaliesSvg} accent={(summary?.anomalies_detected ?? 0) > 0 ? "violet" : "green"} trendLabel="ML-detected anomalies" />
          </Link>
        </div>
      </section>

      {/* ── Risk Overview ─────────────────────────────────────── */}
      <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: "Critical", value: summary?.severity_counts?.critical || 0, severity: "critical", icon: "\u26A0" },
          { label: "High", value: summary?.severity_counts?.high || 0, severity: "high", icon: "\u25B2" },
          { label: "Medium", value: summary?.severity_counts?.medium || 0, severity: "medium", icon: "\u25CF" },
          { label: "Low", value: summary?.severity_counts?.low || 0, severity: "low", icon: "\u25CB" },
        ].map((item) => {
          const sevColor = SEV_COLOR[item.severity];
          return (
            <Card key={item.label} hover className="group relative overflow-hidden p-5">
              <div
                className="absolute -right-4 -top-4 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-300 group-hover:opacity-60"
                style={{ background: sevColor }}
              />
              <div className="relative">
                <div className="flex items-center justify-between">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">
                    {item.label}
                  </p>
                  <span className="text-[14px] opacity-40" style={{ color: sevColor }}>{item.icon}</span>
                </div>
                <p
                  className="mt-2 text-[28px] font-bold tabular-nums leading-none text-[var(--fg-primary)]"
                  style={{ fontFeatureSettings: '"tnum"' }}
                >
                  {item.value}
                </p>
                {/* Mini bar */}
                <div className="mt-3 h-1 overflow-hidden rounded-full" style={{ background: "var(--border-subtle)" }}>
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: item.value > 0 ? `${Math.min(100, item.value * 10)}%` : "0%",
                      background: sevColor,
                    }}
                  />
                </div>
              </div>
            </Card>
          );
        })}
      </section>

      {/* ── ML + System Health ────────────────────────────────── */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Link to="/ml-detection" className="lg:col-span-2">
          <Card className="h-full cursor-pointer transition-all duration-200 hover:border-[var(--accent-cyan)]/20 hover:shadow-[0_0_30px_-8px_var(--accent-cyan)]">
            <CardHeader>
              <CardTitle>Detection Engine</CardTitle>
              <div className="flex items-center gap-2">
                {ml.model_state && (
                  <Badge severity={ml.model_state === "HEALTHY" ? "info" : ml.model_state === "WARNING" ? "medium" : "critical"} size="sm">
                    {ml.model_state}
                  </Badge>
                )}
                <span className="text-[12px] font-semibold text-[var(--accent-cyan)]">View ML →</span>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4 mt-2">
                {[
                  ["Engine", ml.supervised?.split("+")[0] || "anomaly"],
                  ["Scored", Number(ml.scored_events ?? 0).toLocaleString()],
                  ["Samples", Number(ml.samples ?? 0).toLocaleString()],
                ].map(([k, v]) => (
                  <div key={k}>
                    <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{k}</p>
                    <p className="mt-1 text-[14px] font-semibold text-[var(--fg-primary)]">{v}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </Link>

        <Card>
          <CardHeader>
            <CardTitle>System Health</CardTitle>
          </CardHeader>
          <CardContent>
            <StatusRow
              label="Telemetry"
              ok={collectorHealthOk(collectors)}
              note={collectorHealthNote(collectors)}
            />
            <StatusRow
              label="Detection engine"
              ok={health.checks?.database?.status === "ok"}
              note={health.checks?.database?.status === "ok" ? "online" : health.checks?.database?.message || "offline"}
            />
            <StatusRow
              label="ML model"
              ok={ml.model_state && ml.model_state !== "CRITICAL" && ml.model_state !== "UNTRAINED"}
              note={ml.model_state === "HEALTHY" ? `v${ml.version} healthy` : ml.model_state?.toLowerCase() || "untrained"}
            />
            <StatusRow
              label="Threat intel"
              ok={!ml.drift && ml.ready}
              note={ml.drift ? "drift detected" : ml.ready ? "nominal" : "not ready"}
            />
          </CardContent>
        </Card>
      </section>

      {/* ── Recent Alerts ─────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Alerts</CardTitle>
          <Link to="/alerts" className="text-[12px] font-semibold text-[var(--accent-cyan)] transition-colors hover:opacity-80">
            View all{data.totalAlerts ? ` (${data.totalAlerts})` : ""} →
          </Link>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 py-12">
              <div className="flex h-12 w-12 items-center justify-center rounded-[var(--radius-xl)] bg-[var(--status-healthy-muted)]">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                  <path d="M12 3L21 9V15C21 20.5 17 25 12 27C7 25 3 20.5 3 15V9L12 3Z" stroke="var(--status-healthy)" strokeWidth="2" strokeLinejoin="round" />
                  <path d="M9 13L11 15L15 10" stroke="var(--status-healthy)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <h4 className="text-[15px] font-semibold text-[var(--fg-primary)]">All Clear</h4>
              <p className="text-center text-[13px] text-[var(--fg-muted)]">No active threats. Your system is secure.</p>
            </div>
          ) : (
            <>
              <div className="divide-y divide-[var(--border-subtle)]">
                {alerts.slice(0, 5).map((a) => <AlertRow key={a.id} alert={a} />)}
              </div>
              <SeverityBar counts={summary?.severity_counts} />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
