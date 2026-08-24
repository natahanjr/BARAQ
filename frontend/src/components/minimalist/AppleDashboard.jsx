import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api.js";
import { ErrorBanner } from "../Feedback.jsx";
import "./AppleDashboard.css";

/* ------------------------------------------------------------------ utils */

const timeAgo = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

const SEV_COLOR = {
  critical: "var(--bq-red)",
  high: "var(--bq-orange)",
  medium: "var(--bq-blue)",
  low: "var(--bq-text-3)",
  info: "var(--bq-text-3)",
};

const greeting = () => {
  const h = new Date().getHours();
  if (h < 5) return "Working late";
  if (h < 12) return "Good morning";
  if (h < 17) return "Good afternoon";
  return "Good evening";
};

const prefersReducedMotion = () =>
  window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

/** Animate a number from `from` to `to` with Apple's ease-out feel. */
function useCountUp(to, duration = 950) {
  const [v, setV] = useState(() => to);
  useEffect(() => {
    if (prefersReducedMotion()) {
      setV(to);
      return;
    }
    let raf;
    const t0 = performance.now();
    const from = 0;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / duration);
      const eased = 1 - Math.pow(2, -10 * p); // expo out
      setV(from + (to - from) * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [to, duration]);
  return v;
}

function CountUp({ value, format }) {
  const v = useCountUp(Number(value) || 0);
  return <>{format ? format(v) : Math.round(v).toLocaleString()}</>;
}

/* ------------------------------------------------------------- sub-views */

function ScoreRing({ value, delay = 0 }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (prefersReducedMotion()) {
      setShown(value);
      return;
    }
    const t = setTimeout(() => setShown(value), 120 + delay * 1000);
    return () => clearTimeout(t);
  }, [value, delay]);
  const R = 66;
  const C = 2 * Math.PI * R;
  const tone =
    value >= 70 ? "var(--bq-green)" : value >= 40 ? "var(--bq-orange)" : "var(--bq-red)";
  const label = value >= 70 ? "Secure" : value >= 40 ? "Attention" : "At risk";
  return (
    <div className="relative flex items-center justify-center" style={{ width: 176, height: 176 }}>
      <svg width="176" height="176" viewBox="0 0 176 176" aria-hidden>
        <circle className="bq-ring-track" cx="88" cy="88" r={R} fill="none" strokeWidth="10" />
        <circle
          className="bq-ring-fg"
          cx="88"
          cy="88"
          r={R}
          fill="none"
          stroke={tone}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={C - (C * shown) / 100}
          transform="rotate(-90 88 88)"
          style={{ color: tone }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="bq-ring-num" style={{ color: tone }}>
          <CountUp value={value} />
        </span>
        <span className="bq-caption">{label}</span>
      </div>
    </div>
  );
}

function Stat({ label, value, tone, delay, to, note }) {
  const body = (
    <>
      <span className="flex w-full items-center justify-between">
        <span className="bq-caption">{label}</span>
        <span aria-hidden className="stat-chevron text-[15px] leading-none"
              style={{ color: "var(--bq-text-3)" }}>›</span>
      </span>
      <span className="flex w-full items-baseline justify-between gap-2">
        <span className="bq-metric" style={tone ? { color: tone } : undefined}>
          <CountUp value={value} />
        </span>
        {note ? (
          <span className="text-[11px]" style={{ color: "var(--bq-text-3)" }}>{note}</span>
        ) : null}
      </span>
    </>
  );
  const cls =
    "bq-card bq-card--hover bq-in flex flex-col justify-between gap-6 p-5 group stat-tap";
  if (to) {
    return (
      <Link to={to} className={cls} style={{ animationDelay: `${delay}s` }}
            aria-label={`${label} — view details`}>
        {body}
      </Link>
    );
  }
  return <div className={cls} style={{ animationDelay: `${delay}s` }}>{body}</div>;
}

function StateRow({ label, ok, note, pulse = false, warn = false }) {
  const cls = !ok ? "bq-dot--crit" : warn ? "bq-dot--warn" : "bq-dot--ok";
  return (
    <div className="flex items-center justify-between py-[11px]">
      <span className="text-[13px]">{label}</span>
      <span className="flex items-center gap-2.5">
        <span className="text-[13px]" style={{ color: "var(--bq-text-2)" }}>{note}</span>
        <span className={`bq-dot ${cls} ${ok && pulse ? "bq-dot--pulse" : ""}`} />
      </span>
    </div>
  );
}

function MlCard({ ml, delay }) {
  if (!ml || Object.keys(ml).length === 0) return null;
  const state = ml.model_state || "UNKNOWN";
  const stateTone =
    state === "HEALTHY" ? "var(--bq-green)" :
    state === "WARNING" ? "var(--bq-orange)" : "var(--bq-red)";
  const source =
    ml.model_source === "bootstrap"
      ? "Built-in seed model — armed on day one"
      : ml.model_source === "user"
        ? `Trained on this host · v${ml.version}`
        : "Awaiting first training cycle";
  const streams = Array.isArray(ml.streams) ? ml.streams : [];
  return (
    <section className="bq-card bq-in p-7" aria-label="ML detection engine"
             style={{ animationDelay: `${delay}s`, height: "100%" }}>
      <header className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-[17px] font-semibold tracking-[-0.01em]">Detection Intelligence</h2>
          <p className="bq-subtitle mt-0.5">{source}</p>
        </div>
        <span className="flex items-center gap-2 rounded-full px-3 py-1.5"
              style={{ background: "var(--bq-surface-strong)", border: "1px solid var(--bq-hairline)" }}>
          <span
            className={`bq-dot ${state === "HEALTHY" ? "bq-dot--ok bq-dot--pulse" : state === "WARNING" ? "bq-dot--warn" : "bq-dot--crit"}`}
            style={{ background: stateTone }}
          />
          <span className="text-[12px] font-medium" style={{ color: stateTone }}>{state}</span>
        </span>
      </header>

      <div className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
        {[
          ["Engine", ml.supervised && ml.supervised !== "none" ? ml.supervised.split("+")[0] : "anomaly only", "/evaluation"],
          ["Scored events", Number(ml.scored_events ?? 0).toLocaleString(), "/evaluation"],
          ["Samples", Number(ml.samples ?? 0).toLocaleString(), "/evaluation"],
          ["Drift", ml.drift ? "detected" : "none", ml.drift ? "/evaluation" : null],
        ].map(([k, v, href]) => (
          <div key={k}>
            <div className="bq-caption mb-1">{k}</div>
            {href ? (
              <Link to={href} className="text-[15px] font-medium tracking-[-0.01em] transition-colors hover:underline"
                    style={k === "Drift" && ml.drift ? { color: "var(--bq-orange)" } : { color: "var(--bq-text-1)" }}>
                {v}
              </Link>
            ) : (
              <div className="text-[15px] font-medium tracking-[-0.01em]"
                   style={k === "Drift" ? { color: "var(--bq-text-3)" } : undefined}>
                {v}
              </div>
            )}
          </div>
        ))}
      </div>

      {streams.length > 0 && (
        <div className="mt-5 flex flex-wrap gap-2">
          {streams.map((s) => {
            const t = ml.thresholds?.[s];
            return (
              <Link
                key={s}
                to={`/telemetry?stream=${s}`}
                className="bq-chip transition-all hover:scale-[1.03] hover:shadow-[0_0_12px_-4px_rgba(56,189,248,0.3)]"
              >
                <span className="bq-dot bq-dot--ok" style={{ opacity: 0.9 }} />
                {s}{t !== undefined ? ` · τ ${Number(t).toFixed(2)}` : ""}
              </Link>
            );
          })}
        </div>
      )}

      <footer className="mt-5 border-t pt-4" style={{ borderColor: "var(--bq-hairline)" }}>
        <Link to="/evaluation" className="bq-link text-[13px] font-medium" style={{ color: "var(--bq-blue)" }}>
          Open evaluation →
        </Link>
      </footer>
    </section>
  );
}

function SeverityBar({ counts }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((n, k) => n + (counts?.[k] || 0), 0);
  if (!total) return null;
  return (
    <div className="mt-4">
      <div className="bq-segbar" role="img" aria-label="Alert severity distribution">
        {order.map((k, i) => {
          const n = counts[k] || 0;
          if (!n) return null;
          return (
            <span key={k}
                  title={`${k}: ${n}`}
                  style={{
                    width: `${(n / total) * 100}%`,
                    background: SEV_COLOR[k],
                    animationDelay: `${0.55 + i * 0.08}s`,
                  }} />
          );
        })}
      </div>
      <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
        {order.filter((k) => (counts?.[k] || 0) > 0).map((k) => (
          <span key={k} className="flex items-center gap-1.5 text-[11px]"
                style={{ color: "var(--bq-text-3)" }}>
            <span className="bq-sev" style={{ background: SEV_COLOR[k], width: 6, height: 6 }} />
            {k} · {counts[k]}
          </span>
        ))}
      </div>
    </div>
  );
}

function Skeleton() {
  return (
    <div aria-label="Loading dashboard" className="grid grid-cols-1 gap-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="bq-skel h-[248px]" />
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:col-span-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="bq-skel h-[116px]" />
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="bq-skel h-[220px] lg:col-span-2" />
        <div className="bq-skel h-[220px]" />
      </div>
      <div className="bq-skel h-[280px]" />
    </div>
  );
}

/* ------------------------------------------------------------------- page */

const REFRESH_MS = 30000;

export default function AppleDashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(null);
  const [tick, setTick] = useState(0); // re-render for timeAgo freshness
  const alive = useRef(true);

  const load = useCallback(async () => {
    try {
      const [summary, alerts, mlStatus] = await Promise.all([
        api.summary(),
        api.alerts({ page_size: 6 }),
        api.get("/api/system/ml/status").catch(() => ({})),
      ]);
      if (!alive.current) return;
      setData({
        summary,
        alerts: alerts.items || [],
        totalAlerts: alerts.total ?? (alerts.items || []).length,
        ml: mlStatus || {},
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
    const timer = setInterval(() => {
      if (!document.hidden) load();
    }, REFRESH_MS);
    const clock = setInterval(() => setTick((t) => t + 1), 60000);
    return () => {
      alive.current = false;
      clearInterval(timer);
      clearInterval(clock);
    };
  }, [load]);

  if (error && !data) return <ErrorBanner message={error} onRetry={load} />;
  if (!data) {
    return (
      <div className="bq pb-10 pt-1">
        <p className="bq-caption mb-4">Security Operations</p>
        <Skeleton />
      </div>
    );
  }

  const { summary, alerts, ml } = data;
  void tick; // refresh time-ago labels
  const score = summary?.security_score ?? 0;

  return (
    <div className="bq pb-10 pt-1">
      <div className="bq-ambient" aria-hidden />

      <div className="relative" style={{ zIndex: 1 }}>
        {/* ------------------------------------------------ header */}
        <header className="bq-in mb-7 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="bq-caption mb-1.5">{greeting()} · Security Operations</p>
            <h1 className="bq-title">Overview</h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[12px]" style={{ color: "var(--bq-text-3)" }}>
              {updated
                ? `Updated ${updated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
                : ""}
            </span>
            <span className="flex items-center gap-2 rounded-full px-3 py-1.5"
                  style={{ background: "var(--bq-surface)", border: "1px solid var(--bq-hairline)" }}>
              <span className="bq-dot bq-dot--ok bq-dot--pulse" />
              <span className="text-[12px] font-medium">Live</span>
            </span>
          </div>
        </header>

        {/* ---------------------------------------------- hero row */}
        <section className="grid grid-cols-1 gap-4 lg:grid-cols-3" aria-label="Posture">
          <div className="bq-card bq-in flex flex-col items-center justify-center gap-3 p-7 lg:col-span-1"
               style={{ animationDelay: "0.05s" }}>
            <ScoreRing value={score} delay={0.05} />
            <p className="bq-subtitle">{summary?.system_status ?? ""}</p>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:col-span-2">
            <Stat label="Events ingested" value={summary?.total_events ?? 0}
                  to="/telemetry" note="browse" delay={0.12} />
            <Stat label="Active alerts" value={summary?.active_alerts ?? 0}
                  tone={(summary?.active_alerts ?? 0) > 0 ? "var(--bq-blue)" : undefined}
                  to="/alerts?status=open" note="triage" delay={0.18} />
            <Stat label="Critical + high" value={summary?.critical_threats ?? 0}
                  tone={(summary?.critical_threats ?? 0) > 0 ? "var(--bq-red)" : undefined}
                  to="/alerts?status=open&severity=critical,high" note="urgent" delay={0.24} />
            <Stat label="Anomalies flagged" value={summary?.anomalies_detected ?? 0}
                  tone={(summary?.anomalies_detected ?? 0) > 0 ? "var(--bq-purple)" : undefined}
                  to="/telemetry?anomaly=true" note="ML flagged" delay={0.30} />
          </div>
        </section>

        {/* ------------------------------------------- ML + status */}
        <section className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <MlCard ml={ml} delay={0.38} />
          </div>
          <section className="bq-card bq-in p-7" aria-label="System health"
                   style={{ animationDelay: "0.44s" }}>
            <h2 className="mb-2 text-[17px] font-semibold tracking-[-0.01em]">System</h2>
            <div>
              <StateRow label="Telemetry collection" ok note="streaming" pulse />
              <StateRow label="Detection engine" ok note="online" />
              <StateRow
                label="ML model"
                ok={ml.model_state !== "CRITICAL"}
                warn={ml.model_state === "WARNING"}
                note={(ml.model_source === "bootstrap" ? "seed model" : ml.model_state?.toLowerCase()) || "—"}
              />
              <StateRow label="Threat intel" ok={!ml.drift} warn={!!ml.drift}
                        note={ml.drift ? "review drift" : "nominal"} />
            </div>
          </section>
        </section>

        {/* ------------------------------------------ recent alerts */}
        <section className="bq-card bq-in mt-4 p-7" aria-label="Recent alerts"
                 style={{ animationDelay: "0.50s" }}>
          <header className="mb-3 flex items-baseline justify-between">
            <h2 className="text-[17px] font-semibold tracking-[-0.01em]">Recent Alerts</h2>
            <Link to="/alerts" className="bq-link text-[13px] font-medium"
                  style={{ color: "var(--bq-blue)" }}>
              View all{data.totalAlerts ? ` (${data.totalAlerts})` : ""} →
            </Link>
          </header>

          {alerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-14">
              <svg width="44" height="52" viewBox="0 0 44 52" fill="none" aria-hidden>
                <path d="M22 2 40 9v13c0 12.5-7.6 21.9-18 28C11.6 43.9 4 34.5 4 22V9L22 2Z"
                      stroke="var(--bq-green)" strokeWidth="2.5" strokeLinejoin="round" />
                <path d="M15 25l5 5 9-10" stroke="var(--bq-green)" strokeWidth="2.5"
                      strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <h3 className="text-[17px] font-semibold tracking-[-0.01em]">All Clear</h3>
              <p className="bq-subtitle">No alerts right now — we're still watching everything.</p>
            </div>
          ) : (
            <>
              <div>
                {alerts.map((a, i) => (
                  <Link key={a.id} to={`/alerts/${a.id}`} className="bq-row bq-in"
                        style={{ animationDelay: `${0.56 + i * 0.06}s` }}>
                    <span className={`bq-sev ${a.severity === "critical" ? "bq-sev--critical" : ""}`}
                          style={{ background: SEV_COLOR[a.severity] || "var(--bq-text-3)" }} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[14px] font-medium tracking-[-0.01em]">
                        {a.name}
                      </span>
                      <span className="bq-subtitle block truncate">
                        {a.host || "unknown host"} · {a.category || a.rule || "detection"}
                      </span>
                    </span>
                    <span className="text-[13px]" style={{ color: "var(--bq-text-3)" }}>
                      {timeAgo(a.created_at)}
                    </span>
                    <span aria-hidden style={{ color: "var(--bq-text-3)" }}>›</span>
                  </Link>
                ))}
              </div>
              <SeverityBar counts={summary?.severity_counts} />
            </>
          )}
        </section>
      </div>
    </div>
  );
}
