import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { api, authStore } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import HeartbeatChart from "../components/HeartbeatChart.jsx";
import Strike from "../components/Strike.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import {
  BoltIcon,
  AlertsIcon,
  BoxesIcon,
  AlertIcon,
  RefreshIcon,
  IncidentsIcon,
  IntelIcon,
  RiskShieldIcon,
} from "../components/icons.jsx";

const RISK_COLORS = {
  CRITICAL: "#ff3d71",
  HIGH: "#f97316",
  MEDIUM: "#ffb300",
  LOW: "#00f0ff",
};

// Color-independent severity markers (plan: never rely on color alone).
const SEVERITY_MARK = {
  critical: { shape: "●", cls: "text-red-400" },
  high: { shape: "▲", cls: "text-orange-400" },
  medium: { shape: "◆", cls: "text-amber-400" },
  low: { shape: "○", cls: "text-sky-400" },
  info: { shape: "○", cls: "text-slate-400" },
};

const SEVERITY_CHIP = {
  critical: { chip: "border-red-500/40 bg-red-500/15 text-red-400", dot: "bg-red-500" },
  high: { chip: "border-orange-500/40 bg-orange-500/15 text-orange-400", dot: "bg-orange-400" },
  medium: { chip: "border-amber-500/40 bg-amber-500/15 text-amber-400", dot: "bg-amber-400" },
  low: { chip: "border-sky-500/40 bg-sky-500/15 text-sky-400", dot: "bg-sky-400" },
  info: { chip: "border-slate-500/40 bg-slate-500/15 text-slate-400", dot: "bg-slate-400" },
};

const STATUS_CHIP = {
  open: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  investigating: "border-violet-500/40 bg-violet-500/10 text-violet-300",
  contained: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  resolved: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  closed: "border-slate-500/40 bg-slate-500/10 text-slate-400",
};

// All 14 ATT&CK tactics — gaps are tactics with no detection in the window.
const MITRE_TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
  "Reconnaissance",
  "Resource Development",
];

const RANGE_OPTIONS = ["30m", "1h", "6h", "24h"];
const TREND_OPTIONS = ["1h", "6h", "24h", "7d", "30d"];

const KPI_ACCENT = {
  cyan: {
    text: "text-cyan-300",
    bubble: "from-cyan-500/25 to-blue-600/25 border-cyan-400/40 text-cyan-300",
    bar: "from-cyan-400 to-violet-500",
    glow: "bg-cyan-500",
    grad: "from-cyan-500/12 via-slate-900/60 to-slate-900/80 border-cyan-400/20",
  },
  green: {
    text: "text-emerald-300",
    bubble: "from-emerald-500/25 to-teal-600/25 border-emerald-400/40 text-emerald-300",
    bar: "from-emerald-400 to-teal-500",
    glow: "bg-emerald-500",
    grad: "from-emerald-500/12 via-slate-900/60 to-slate-900/80 border-emerald-400/20",
  },
  violet: {
    text: "text-violet-300",
    bubble: "from-violet-500/25 to-fuchsia-600/25 border-violet-400/40 text-violet-300",
    bar: "from-violet-400 to-fuchsia-500",
    glow: "bg-violet-500",
    grad: "from-violet-500/12 via-slate-900/60 to-slate-900/80 border-violet-400/20",
  },
  orange: {
    text: "text-orange-300",
    bubble: "from-orange-500/25 to-amber-600/25 border-orange-400/40 text-orange-300",
    bar: "from-orange-400 to-amber-500",
    glow: "bg-orange-500",
    grad: "from-orange-500/12 via-slate-900/60 to-slate-900/80 border-orange-400/20",
  },
  red: {
    text: "text-red-300",
    bubble: "from-red-500/25 to-rose-600/25 border-red-400/40 text-red-300",
    bar: "from-red-400 to-rose-500",
    glow: "bg-red-500",
    grad: "from-red-500/12 via-slate-900/60 to-slate-900/80 border-red-400/20",
  },
};

function MetricBox({ label, value, icon: Icon, color = "cyan", sub, gauge }) {
  const accent = KPI_ACCENT[color] || KPI_ACCENT.cyan;
  return (
    <div
      className={`card-surface group relative overflow-hidden rounded-2xl border bg-gradient-to-br p-4 ${accent.grad}`}
    >
      <span
        className="absolute -right-10 -top-10 h-28 w-28 rounded-full opacity-15 blur-2xl transition-opacity group-hover:opacity-30"
        style={{ backgroundColor: accent.glow }}
      />
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            {label}
          </p>
          <p className={`mt-1.5 text-3xl font-bold tracking-tight ${accent.text}`}>{value}</p>
          {sub && <p className="mt-0.5 truncate text-xs text-slate-500">{sub}</p>}
          {gauge !== undefined && (
            <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-white/5">
              <div
                className={`h-full rounded-full bg-gradient-to-r ${accent.bar}`}
                style={{ width: `${Math.min(100, Math.max(0, gauge))}%` }}
              />
            </div>
          )}
        </div>
        <span
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border bg-gradient-to-br ${accent.bubble}`}
        >
          <Icon className="h-5 w-5" />
        </span>
      </div>
    </div>
  );
}

function Panel({ title, subtitle, action, children, className = "" }) {
  return (
    <Card className={className}>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
          {subtitle && <p className="mt-0.5 truncate text-xs text-slate-500">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </Card>
  );
}

function RangePills({ options, value, onChange }) {
  return (
    <div className="flex shrink-0 items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] p-0.5">
      {options.map((opt) => (
        <button
          key={opt}
          type="button"
          onClick={() => onChange(opt)}
          className={`rounded-md px-2 py-1 font-mono text-[10px] font-semibold transition-colors ${
            value === opt
              ? "bg-cyan-500/20 text-cyan-300"
              : "text-slate-500 hover:text-slate-300"
          }`}
        >
          {opt}
        </button>
      ))}
    </div>
  );
}

function StrikeButton({ alert, onStrike }) {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onStrike(alert);
      }}
      title={`⚡ STRIKE — one-click containment of alert #${alert.id}`}
      className="inline-flex items-center gap-1 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-cyan-300 transition-all hover:border-cyan-400/70 hover:bg-cyan-500/20"
    >
      ⚡ Strike
    </button>
  );
}

function SevBadge({ severity }) {
  const sev = (severity || "info").toLowerCase();
  const style = SEVERITY_CHIP[sev] || SEVERITY_CHIP.info;
  const mark = SEVERITY_MARK[sev] || SEVERITY_MARK.info;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${style.chip}`}
      title={`${sev.toUpperCase()} (${mark.shape})`}
    >
      <span className={`${mark.cls} text-[9px] leading-none`}>{mark.shape}</span>
      {sev}
    </span>
  );
}

function StatusBadge({ status }) {
  const s = (status || "open").toLowerCase();
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium capitalize ${STATUS_CHIP[s] || STATUS_CHIP.open}`}
    >
      {s}
    </span>
  );
}

function ageMinutes(iso) {
  if (!iso) return null;
  const age = (Date.now() - new Date(iso).getTime()) / 60000;
  return Math.max(0, Math.round(age));
}

function fmtAge(min) {
  if (min === null || min === undefined) return "—";
  if (min < 60) return `${min}m`;
  if (min < 1440) return `${Math.floor(min / 60)}h ${min % 60}m`;
  return `${Math.floor(min / 1440)}d`;
}

/* ------------------------------------------------------------------ */
/* Incident queue — the analyst's triage table (P0 per the plan)       */
/* ------------------------------------------------------------------ */
function IncidentQueue({ incidents, onReload, showToast }) {
  const navigate = useNavigate();
  const [selected, setSelected] = useState(new Set());
  const [sevFilter, setSevFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [q, setQ] = useState("");
  const isAdmin = authStore.user?.role === "admin";
  const currentUser = authStore.user?.username || "";

  const owners = useMemo(() => {
    const set = new Set();
    incidents.forEach((i) => i.owner && set.add(i.owner));
    if (currentUser) set.add(currentUser);
    return [...set].sort();
  }, [incidents, currentUser]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return incidents.filter((i) => {
      if (sevFilter && i.severity !== sevFilter) return false;
      if (statusFilter && i.status !== statusFilter) return false;
      if (needle) {
        const hay = `${i.ref} ${i.title} ${i.host || ""} ${i.owner || ""} ${i.mitre_id || ""}`.toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    });
  }, [incidents, sevFilter, statusFilter, q]);

  const toggle = (id) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };
  const toggleAll = () => {
    if (selected.size === filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map((i) => i.id)));
  };

  const bulk = (patch) => {
    const ids = [...selected];
    if (!ids.length) return;
    Promise.all(ids.map((id) => api.updateIncident(id, patch)))
      .then(() => {
        showToast({ kind: "success", text: `${ids.length} incident${ids.length > 1 ? "s" : ""} updated` });
        setSelected(new Set());
        onReload();
      })
      .catch((e) => showToast({ kind: "error", text: `Bulk action failed: ${e.message}` }));
  };

  const selectCls =
    "rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1.5 text-[11px] font-medium text-slate-300 outline-none transition-colors hover:border-cyan-400/30 focus:border-cyan-400/50";

  return (
    <Panel
      title="Incident Queue"
      subtitle="Open cases — triage, assign, escalate or close without leaving the command center"
      action={
        <Link
          to="/incidents"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Incident Center →
        </Link>
      }
    >
      {/* Filters */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by ref, title, host, analyst, MITRE…"
          className={`${selectCls} w-56`}
        />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} className={selectCls}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={selectCls}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="resolved">Resolved</option>
        </select>
        <span className="ml-auto font-mono text-[10px] text-slate-500">
          {filtered.length} shown · {incidents.length} open
        </span>
      </div>

      {/* Bulk triage bar */}
      {isAdmin && selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-cyan-400/25 bg-cyan-500/[0.07] px-3 py-2">
          <span className="font-mono text-[11px] font-semibold text-cyan-300">
            {selected.size} selected
          </span>
          <select
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                bulk({ status: e.target.value });
                e.target.value = "";
              }
            }}
            className={selectCls}
          >
            <option value="" disabled>
              Set status…
            </option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
          <select
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                bulk({ severity: e.target.value });
                e.target.value = "";
              }
            }}
            className={selectCls}
          >
            <option value="" disabled>
              Change severity…
            </option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            defaultValue=""
            onChange={(e) => {
              if (e.target.value !== undefined) {
                bulk({ owner: e.target.value });
                e.target.value = "";
              }
            }}
            className={selectCls}
          >
            <option value="" disabled>
              Assign analyst…
            </option>
            <option value="">Unassign</option>
            {owners.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => bulk({ status: "closed" })}
            className="rounded-lg border border-red-400/30 bg-red-500/10 px-3 py-1.5 text-[11px] font-semibold text-red-300 transition-colors hover:bg-red-500/20"
          >
            Close selected
          </button>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="data-table w-full">
          <thead>
            <tr>
              <th className="w-8">
                <input
                  type="checkbox"
                  checked={filtered.length > 0 && selected.size === filtered.length}
                  onChange={toggleAll}
                  className="h-3.5 w-3.5 accent-cyan-400"
                  aria-label="Select all incidents"
                />
              </th>
              <th className="w-16">ID</th>
              <th className="w-24">Severity</th>
              <th className="w-14 text-right">Risk</th>
              <th>Incident</th>
              <th className="w-28">Entity</th>
              <th className="w-20">MITRE</th>
              <th className="w-28">Status</th>
              <th className="w-24">Assigned</th>
              <th className="w-16 text-right">Age</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 12).map((inc) => {
              const age = ageMinutes(inc.created_at);
              const overdue =
                (inc.severity === "critical" && age >= 15) || age >= 60;
              return (
                <tr
                  key={inc.id}
                  onClick={() => navigate("/incidents")}
                  className="group cursor-pointer transition-colors hover:bg-white/[0.03]"
                >
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selected.has(inc.id)}
                      onChange={() => toggle(inc.id)}
                      className="h-3.5 w-3.5 accent-cyan-400"
                      aria-label={`Select ${inc.ref}`}
                    />
                  </td>
                  <td className="whitespace-nowrap font-mono text-[11px] text-slate-400">
                    {inc.ref}
                  </td>
                  <td>
                    <SevBadge severity={inc.severity} />
                  </td>
                  <td
                    className={`text-right font-mono text-[11px] ${
                      (inc.risk_score ?? 0) >= 80
                        ? "text-red-400"
                        : (inc.risk_score ?? 0) >= 50
                          ? "text-orange-300"
                          : "text-slate-300"
                    }`}
                  >
                    {inc.risk_score ? Math.round(inc.risk_score) : "—"}
                  </td>
                  <td className="max-w-[260px] truncate text-slate-200">{inc.title}</td>
                  <td className="max-w-[120px] truncate font-mono text-[11px] text-slate-400">
                    {inc.host || "—"}
                  </td>
                  <td className="whitespace-nowrap font-mono text-[10px] text-slate-500">
                    {inc.mitre_id === "T0000" ? "—" : inc.mitre_id}
                  </td>
                  <td>
                    <StatusBadge status={inc.status} />
                  </td>
                  <td className="max-w-[100px] truncate text-[11px] text-slate-400">
                    {inc.owner || <span className="text-slate-600">Unassigned</span>}
                  </td>
                  <td
                    className={`text-right font-mono text-[11px] ${overdue ? "text-red-400" : "text-slate-400"}`}
                    title={overdue ? "SLA attention needed" : ""}
                  >
                    {fmtAge(age)}
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={10} className="py-8 text-center text-xs text-slate-500">
                  No incidents match the current filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Active threats — what needs attention RIGHT NOW                     */
/* ------------------------------------------------------------------ */
function ActiveThreats({ alerts, riskDistribution, onStrike }) {
  const navigate = useNavigate();
  const critical = alerts.filter((a) => (a.severity || "").toLowerCase() === "critical");
  const high = alerts.filter((a) => (a.severity || "").toLowerCase() === "high");
  const threats = [...critical, ...high, ...alerts.filter((a) => a.severity !== "critical" && a.severity !== "high")].slice(0, 8);

  const riskMix = (riskDistribution || []).filter((r) => r.count > 0);

  return (
    <Panel
      title="Active Threats"
      subtitle="Critical and high detections requiring attention now"
      action={
        <Link
          to="/alerts"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          All alerts →
        </Link>
      }
    >
      {threats.length > 0 ? (
        <ul className="space-y-2">
          {threats.map((alert) => {
            const sev = (alert.severity || "info").toLowerCase();
            const isCritical = sev === "critical";
            return (
              <li
                key={alert.id}
                onClick={() => navigate(`/alerts/${alert.id}`)}
                className={`group cursor-pointer rounded-xl border p-3 transition-colors hover:bg-white/[0.03] ${
                  isCritical ? "border-red-500/30 bg-red-500/[0.06]" : "border-orange-500/25 bg-orange-500/[0.04]"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {isCritical ? (
                        <span className="relative flex h-2 w-2 shrink-0">
                          <span className="pulse-dot absolute inline-flex h-full w-full rounded-full bg-red-500" />
                          <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
                        </span>
                      ) : (
                        <span className="h-2 w-2 shrink-0 rounded-full bg-orange-400" />
                      )}
                      <p className="truncate text-xs font-medium text-slate-100">{alert.name}</p>
                    </div>
                    <p className="mt-1 truncate font-mono text-[10px] text-slate-500">
                      {alert.host || "—"} · {alert.mitre_id === "T0000" ? "unmapped" : alert.mitre_id}{" "}
                      · {new Date(alert.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      className={`font-mono text-[11px] font-semibold ${isCritical ? "text-red-400" : "text-orange-300"}`}
                    >
                      {alert.risk_score ? Math.round(alert.risk_score) : "—"}
                    </span>
                    <span className="opacity-0 transition-opacity group-hover:opacity-100">
                      <StrikeButton alert={alert} onStrike={onStrike} />
                    </span>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <EmptyState title="No active threats" subtitle="System is operating normally" icon="🛡" />
      )}

      {riskMix.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2 border-t border-white/5 pt-3">
          {riskMix.map((r) => (
            <span
              key={r.risk_level}
              className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-[10px] font-medium text-slate-400"
            >
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: RISK_COLORS[r.risk_level] || "#64748b" }}
              />
              {r.risk_level} · {r.count}
            </span>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Threat timeline — atomic event feed (expandable)                    */
/* ------------------------------------------------------------------ */
function ThreatTimeline({ events }) {
  const [range, setRange] = useState("1h");
  const [expanded, setExpanded] = useState(null);

  const cutoff = Date.now() - { "30m": 30, "1h": 60, "6h": 360, "24h": 1440 }[range] * 60000;
  const rows = (events || []).filter((e) => new Date(e.timestamp).getTime() >= cutoff);
  const anomalies = rows.filter((e) => e.is_anomaly).length;

  return (
    <Panel
      title="Threat Timeline"
      subtitle={`Live telemetry feed — ${rows.length} events in range, ${anomalies} ML anomalies`}
      action={<RangePills options={RANGE_OPTIONS} value={range} onChange={setRange} />}
    >
      {rows.length > 0 ? (
        <ul className="space-y-1.5">
          {rows.map((ev) => {
            const open = expanded === ev.id;
            const time = new Date(ev.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
            return (
              <li
                key={ev.id}
                className={`rounded-xl border transition-colors ${
                  ev.is_anomaly
                    ? "border-violet-500/30 bg-violet-500/[0.06]"
                    : "border-white/5 bg-white/[0.02] hover:bg-white/[0.04]"
                }`}
              >
                <button
                  type="button"
                  onClick={() => setExpanded(open ? null : ev.id)}
                  className="flex w-full items-center gap-3 px-3 py-2 text-left"
                >
                  <span className="w-16 shrink-0 font-mono text-[11px] text-slate-400">{time}</span>
                  <span className="w-16 shrink-0 truncate font-mono text-[10px] text-slate-500">
                    {ev.category}
                  </span>
                  <span className="hidden w-14 shrink-0 font-mono text-[10px] text-slate-600 sm:inline">
                    E{ev.event_id}
                  </span>
                  <span className="hidden min-w-0 shrink-0 max-w-[150px] truncate font-mono text-[11px] text-slate-400 md:inline">
                    {ev.user !== "-" ? ev.user : ""}@{ev.host !== "-" ? ev.host : ""}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-xs text-slate-300">{ev.message}</span>
                  {ev.is_anomaly && (
                    <span className="shrink-0 rounded border border-violet-400/40 bg-violet-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-violet-300">
                      ML {ev.ml_score ? ev.ml_score.toFixed(2) : ""}
                    </span>
                  )}
                  <span className={`shrink-0 text-[10px] text-slate-600 transition-transform ${open ? "rotate-90" : ""}`}>
                    ›
                  </span>
                </button>
                {open && (
                  <div className="border-t border-white/5 px-3 py-2.5">
                    <p className="text-xs leading-relaxed text-slate-300">{ev.message}</p>
                    {ev.raw && (
                      <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-white/5 bg-black/30 p-2.5 font-mono text-[10px] leading-relaxed text-slate-500">
                        {typeof ev.raw === "string" ? ev.raw : JSON.stringify(ev.raw, null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <EmptyState title="No events in range" subtitle="Widen the time range or collect new telemetry" />
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Attack trends + detection performance                               */
/* ------------------------------------------------------------------ */
function AttackTrends({ timeline, attacks, userBehavior }) {
  const [range, setRange] = useState("24h");
  const [data, setData] = useState(timeline);
  const hours = { "1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720 }[range];

  useEffect(() => {
    setData(timeline);
  }, [timeline]);

  useEffect(() => {
    let alive = true;
    api
      .timeline(hours)
      .then((t) => {
        if (alive) setData(t);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [hours]);

  const chartData = (data?.events || []).map((e) => ({
    ...e,
    label: (e.bucket || "").slice(11, 16),
    alerts: (data?.alerts || []).find((a) => a.bucket === e.bucket)?.count || 0,
  }));
  const maxAttacks = Math.max(1, ...(attacks || []).slice(0, 4).map((a) => a.count));

  return (
    <Panel
      title="Attack Trends"
      subtitle="Event and alert volume over the selected window"
      action={<RangePills options={TREND_OPTIONS} value={range} onChange={setRange} />}
    >
      <div className="h-56">
        <HeartbeatChart data={chartData} />
      </div>
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Top attack types
          </p>
          {(attacks || []).slice(0, 4).map((a, idx) => (
            <div key={idx} className="mb-1.5 flex items-center gap-2">
              <span className="w-36 truncate font-mono text-[11px] text-slate-300">{a.attack}</span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-500"
                  style={{ width: `${Math.max(3, (a.count / maxAttacks) * 100)}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-[10px] text-slate-400">{a.count}</span>
            </div>
          ))}
        </div>
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Targeted accounts
          </p>
          {(userBehavior || []).slice(0, 4).map((u, idx) => {
            const total = (u.successes || 0) + (u.failures || 0);
            const failPct = total > 0 ? Math.round(((u.failures || 0) / total) * 100) : 0;
            return (
              <div key={idx} className="mb-1.5 flex items-center gap-2">
                <span className="w-36 truncate font-mono text-[11px] text-slate-300">
                  {u.user || "Unknown"}
                </span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                  <div
                    className={`h-full rounded-full bg-gradient-to-r ${failPct > 30 ? "from-red-500 to-rose-500" : "from-emerald-400 to-teal-500"}`}
                    style={{ width: `${failPct}%` }}
                  />
                </div>
                <span className="w-8 text-right font-mono text-[10px] text-slate-400">{failPct}%</span>
              </div>
            );
          })}
        </div>
      </div>
    </Panel>
  );
}

function DetectionPerformance({ evalData, detectionMethods }) {
  const overall = evalData?.overall;
  const items = (evalData?.items || []).slice(0, 6);
  const methods = (detectionMethods || []).filter((d) => d.count > 0);
  const maxMethod = Math.max(1, ...methods.map((m) => m.count));

  return (
    <Panel
      title="Detection Performance"
      subtitle="Latest evaluation suite — how well the engine actually detects"
      action={
        <Link
          to="/evaluation"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Evaluation →
        </Link>
      }
    >
      {overall ? (
        <>
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Precision", value: overall.precision, color: "text-cyan-300" },
              { label: "Recall", value: overall.recall, color: "text-violet-300" },
              { label: "F1", value: overall.f1_score, color: "text-emerald-300" },
            ].map((m) => (
              <div key={m.label} className="rounded-xl border border-white/5 bg-white/[0.03] p-3 text-center">
                <p className={`text-xl font-bold ${m.color}`}>{(m.value * 100).toFixed(1)}%</p>
                <p className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-500">{m.label}</p>
              </div>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-slate-500">
            <span>
              FPR <strong className="font-mono text-slate-300">{(overall.false_positive_rate * 100).toFixed(1)}%</strong>
            </span>
            <span>
              Accuracy{" "}
              <strong className="font-mono text-slate-300">{(overall.accuracy * 100).toFixed(1)}%</strong>
            </span>
            <span>
              Avg detection{" "}
              <strong className="font-mono text-slate-300">
                {overall.detection_time_ms ? `${(overall.detection_time_ms / 1000).toFixed(1)}s` : "—"}
              </strong>
            </span>
          </div>
          {items.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                By scenario
              </p>
              <ul className="space-y-1.5">
                {items.map((s) => (
                  <li key={s.scenario} className="flex items-center gap-2">
                    <span className="w-28 truncate text-[11px] text-slate-300">{s.scenario}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-violet-500"
                        style={{ width: `${Math.max(2, (s.f1_score ?? 0) * 100)}%` }}
                      />
                    </div>
                    <span className="w-10 text-right font-mono text-[10px] text-slate-400">
                      {((s.f1_score ?? 0) * 100).toFixed(0)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : (
        <EmptyState title="No evaluation run yet" subtitle="Run the suite from the Evaluation page" />
      )}

      {methods.length > 0 && (
        <div className="mt-4 border-t border-white/5 pt-3">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Detection mix
          </p>
          <div className="flex flex-wrap gap-2">
            {methods.map((m) => (
              <span
                key={m.method}
                className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1 text-[10px] text-slate-400"
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${m.method === "rule" ? "bg-cyan-400" : "bg-violet-400"}`}
                />
                {String(m.method || "rule").toUpperCase()} · {m.count}
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* MITRE coverage — what we see AND what we miss                       */
/* ------------------------------------------------------------------ */
function MitreCoverage({ categories }) {
  const counts = useMemo(() => {
    const map = {};
    (categories || []).forEach((c) => {
      const key = String(c.tactic || "").toLowerCase();
      map[key] = (map[key] || 0) + c.count;
    });
    return MITRE_TACTICS.map((tactic) => ({
      tactic,
      count: map[tactic.toLowerCase()] || 0,
    }));
  }, [categories]);

  const observed = counts.filter((c) => c.count > 0);
  const gaps = counts.filter((c) => c.count === 0);
  const pct = counts.length ? Math.round((observed.length / counts.length) * 100) : 0;

  return (
    <Panel
      title="MITRE ATT&CK Coverage"
      subtitle={`Tactics with active detections: ${observed.length}/${counts.length} (${pct}%) in the last 24h`}
      action={
        <Link
          to="/automation"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Detection rules →
        </Link>
      }
    >
      <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        {observed.map((c) => (
          <div key={c.tactic} className="flex items-center gap-2 py-0.5">
            <span className="w-32 truncate text-[11px] text-slate-300">{c.tactic}</span>
            <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-violet-500"
                style={{ width: `${Math.min(100, 20 + c.count * 6)}%` }}
              />
            </div>
            <span className="w-8 text-right font-mono text-[10px] text-slate-400">{c.count}</span>
          </div>
        ))}
      </div>

      {gaps.length > 0 && (
        <div className="mt-4 border-t border-white/5 pt-3">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-400/90">
            Coverage gaps — no detections in range
          </p>
          <div className="flex flex-wrap gap-2">
            {gaps.map((g) => (
              <span
                key={g.tactic}
                className="inline-flex items-center gap-2 rounded-lg border border-amber-400/20 bg-amber-500/[0.06] px-2.5 py-1 text-[10px] text-amber-300/90"
              >
                {g.tactic}
                <Link to="/automation" className="text-[9px] font-semibold text-cyan-400 hover:underline">
                  Create detection
                </Link>
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* SOAR response status                                                */
/* ------------------------------------------------------------------ */
function SoarStatus({ runs }) {
  const today = useMemo(() => {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    return (runs || []).filter((r) => new Date(r.created_at).getTime() >= start.getTime());
  }, [runs]);

  const done = today.filter((r) => r.status === "completed").length;
  const partial = today.filter((r) => r.status === "partial").length;
  const failed = today.filter((r) => r.status === "failed").length;
  const total = today.length;
  const successRate = total ? Math.round((done / total) * 100) : 0;

  return (
    <Panel
      title="SOAR · Automated Response"
      subtitle="Playbook executions today"
      action={
        <Link
          to="/automation"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Automation →
        </Link>
      }
    >
      {total > 0 ? (
        <>
          <div className="flex items-end justify-between">
            <div>
              <p className="text-3xl font-bold text-slate-100">{total}</p>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">actions today</p>
            </div>
            <div className="text-right">
              <p className="font-mono text-xl font-bold text-emerald-300">{successRate}%</p>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">success rate</p>
            </div>
          </div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/5">
            <div
              className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-teal-500"
              style={{ width: `${successRate}%` }}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <span className="rounded-full border border-emerald-400/25 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-300">
              ✓ {done} completed
            </span>
            {partial > 0 && (
              <span className="rounded-full border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">
                ⚠ {partial} partial
              </span>
            )}
            {failed > 0 && (
              <span className="rounded-full border border-red-400/30 bg-red-500/10 px-2 py-0.5 text-[10px] text-red-300">
                ✕ {failed} failed
              </span>
            )}
          </div>
          {failed > 0 && (
            <div className="mt-3 rounded-xl border border-red-400/20 bg-red-500/[0.05] p-2.5">
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-red-300/90">
                Failed actions — review
              </p>
              {today
                .filter((r) => r.status === "failed")
                .slice(0, 3)
                .map((r) => (
                  <p key={r.id} className="truncate font-mono text-[10px] text-slate-400">
                    {r.playbook_name} → alert #{r.alert_id}
                  </p>
                ))}
            </div>
          )}
        </>
      ) : (
        <EmptyState title="No runs today" subtitle="Playbooks will appear here as they execute" />
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Risk intelligence + SOC workload (analysts / SLA aging)             */
/* ------------------------------------------------------------------ */
function RiskIntelligence({ entities }) {
  const navigate = useNavigate();
  return (
    <Panel
      title="Risk Intelligence"
      subtitle="Highest accumulated entity risk — why each entity is dangerous"
      action={
        <Link
          to="/rba"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Risk Center →
        </Link>
      }
    >
      {entities.length > 0 ? (
        <ul className="space-y-2.5">
          {entities.slice(0, 5).map((ent) => {
            const level = ent.risk_level || "LOW";
            const color = RISK_COLORS[level] || "#64748b";
            const factors = (ent.contributions || []).slice(0, 3);
            return (
              <li
                key={`${ent.entity_kind}:${ent.entity_name}`}
                onClick={() => navigate(`/rba?kind=${ent.entity_kind}&name=${encodeURIComponent(ent.entity_name)}`)}
                className="cursor-pointer rounded-xl border border-white/5 bg-white/[0.03] p-3 transition-colors hover:bg-white/[0.05]"
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="rounded-lg border border-white/10 bg-white/[0.05] px-1.5 py-0.5 font-mono text-[9px] uppercase text-slate-400">
                      {ent.entity_kind}
                    </span>
                    <p className="truncate font-mono text-xs font-medium text-slate-100">
                      {ent.entity_name}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      className="rounded-full border px-2 py-0.5 text-[9px] font-bold"
                      style={{ borderColor: `${color}55`, color, backgroundColor: `${color}14` }}
                    >
                      {level}
                    </span>
                    <span className="w-8 text-right font-mono text-xs font-bold" style={{ color }}>
                      {Math.round(ent.score)}
                    </span>
                  </div>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.min(100, ent.score)}%`,
                      background: `linear-gradient(90deg, ${color}66, ${color})`,
                    }}
                  />
                </div>
                {factors.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {factors.map((f, idx) => (
                      <span
                        key={idx}
                        className="rounded border border-white/10 bg-black/20 px-1.5 py-0.5 font-mono text-[9px] text-slate-400"
                        title={`${f.rule || f.mitre_id || "contribution"}`}
                      >
                        {f.mitre_id || f.rule || "finding"} +{Number(f.delta || 0).toFixed(0)}
                      </span>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <EmptyState title="No elevated entities" subtitle="Entity risk is accumulating normally" />
      )}
    </Panel>
  );
}

function SocWorkload({ incidents }) {
  const buckets = useMemo(() => {
    const b = [
      { label: "0–15m", min: 0, max: 15, count: 0, color: "from-emerald-400 to-teal-500" },
      { label: "15–60m", min: 15, max: 60, count: 0, color: "from-cyan-400 to-violet-500" },
      { label: "1–4h", min: 60, max: 240, count: 0, color: "from-amber-400 to-orange-500" },
      { label: "4h+", min: 240, max: Infinity, count: 0, color: "from-red-500 to-rose-500" },
    ];
    incidents.forEach((i) => {
      const age = ageMinutes(i.created_at);
      if (age === null) return;
      const bucket = b.find((x) => age >= x.min && age < x.max);
      if (bucket) bucket.count += 1;
    });
    return b;
  }, [incidents]);

  const byOwner = useMemo(() => {
    const map = {};
    incidents.forEach((i) => {
      const key = i.owner || "Unassigned";
      map[key] = (map[key] || 0) + 1;
    });
    return Object.entries(map)
      .map(([owner, count]) => ({ owner, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [incidents]);

  const maxOwner = Math.max(1, ...byOwner.map((o) => o.count));
  const maxBucket = Math.max(1, ...buckets.map((b) => b.count));
  const overdueCritical = incidents.filter((i) => i.severity === "critical" && (ageMinutes(i.created_at) ?? 0) >= 15).length;
  const aging = incidents.filter((i) => (ageMinutes(i.created_at) ?? 0) >= 60).length;

  return (
    <Panel
      title="SOC Workload"
      subtitle="Analyst load and incident aging against SLA"
      action={
        <span className="flex shrink-0 gap-2">
          {overdueCritical > 0 && (
            <span className="rounded-full border border-red-400/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold text-red-300">
              {overdueCritical} critical overdue
            </span>
          )}
          <span className="rounded-full border border-amber-400/25 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">
            {aging} aging
          </span>
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Analyst workload
          </p>
          <ul className="space-y-1.5">
            {byOwner.map((o) => (
              <li key={o.owner} className="flex items-center gap-2">
                <span
                  className={`w-24 truncate text-[11px] ${o.owner === "Unassigned" ? "text-amber-300/90" : "text-slate-300"}`}
                >
                  {o.owner}
                </span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-violet-500 to-cyan-400"
                    style={{ width: `${Math.max(4, (o.count / maxOwner) * 100)}%` }}
                  />
                </div>
                <span className="w-6 text-right font-mono text-[10px] text-slate-400">{o.count}</span>
              </li>
            ))}
            {byOwner.length === 0 && <li className="text-[11px] text-slate-600">No open incidents</li>}
          </ul>
        </div>
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
            Incident age
          </p>
          <ul className="space-y-1.5">
            {buckets.map((b) => (
              <li key={b.label} className="flex items-center gap-2">
                <span className="w-12 shrink-0 font-mono text-[10px] text-slate-500">{b.label}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                  <div
                    className={`h-full rounded-full bg-gradient-to-r ${b.color}`}
                    style={{ width: `${Math.max(3, (b.count / maxBucket) * 100)}%` }}
                  />
                </div>
                <span className="w-6 text-right font-mono text-[10px] text-slate-400">{b.count}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* ML intelligence + platform health                                   */
/* ------------------------------------------------------------------ */
function MlIntelligence({ mlStatus, drift, anomalies }) {
  const streams = drift?.streams || {};
  const streamList = Object.entries(streams);
  const state = mlStatus?.model_state || (mlStatus ? (mlStatus.stale || !mlStatus.ready ? "WARNING" : "HEALTHY") : "—");
  const stateTone =
    state === "HEALTHY"
      ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-300"
      : state === "WARNING"
        ? "border-amber-400/40 bg-amber-500/10 text-amber-300"
        : "border-red-400/40 bg-red-500/10 text-red-300";

  return (
    <Panel
      title="ML · AI Intelligence"
      subtitle="Model state, live scoring and drift — one unambiguous health view"
      action={
        <Link
          to="/evaluation"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          ML detail →
        </Link>
      }
    >
      <div className="flex flex-wrap items-center gap-3">
        <span
          className={`rounded border px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider ${stateTone}`}
        >
          {state === "HEALTHY" ? "●" : state === "WARNING" ? "▲" : "✕"} MODEL STATE · {state}
        </span>
        <span className="text-[10px] text-slate-500">
          {mlStatus?.trained_at ? `last training ${new Date(mlStatus.trained_at).toLocaleString()}` : "never trained"}
        </span>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          { label: "Live scoring", value: (mlStatus?.scored_events ?? mlStatus?.samples ?? "—").toLocaleString?.() ?? "—", color: "text-cyan-300" },
          { label: "Anomalies", value: anomalies ?? 0, color: "text-violet-300" },
          { label: "Model version", value: mlStatus?.model_version != null ? `v${mlStatus.model_version}` : "—", color: "text-slate-200" },
          { label: "Drift", value: mlStatus?.drift ? "DRIFTED" : mlStatus?.stale ? "STALE" : "CLEAN", color: mlStatus?.drift ? "text-red-300" : mlStatus?.stale ? "text-amber-300" : "text-emerald-300" },
        ].map((m) => (
          <div key={m.label} className="rounded-xl border border-white/5 bg-white/[0.03] p-3">
            <p className={`truncate text-lg font-bold ${m.color}`}>{String(m.value).toUpperCase()}</p>
            <p className="mt-0.5 text-[9px] uppercase tracking-wider text-slate-500">{m.label}</p>
          </div>
        ))}
      </div>

      <div className="mt-4">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
          Drift monitor · 24h window
        </p>
        {streamList.length > 0 ? (
          <ul className="space-y-1.5">
            {streamList.map(([name, s]) => {
              const v = s.verdict || "ok";
              const cls =
                v === "drift"
                  ? "border-red-400/30 bg-red-500/10 text-red-300"
                  : v === "watch"
                    ? "border-amber-400/25 bg-amber-500/10 text-amber-300"
                    : "border-emerald-400/20 bg-emerald-500/10 text-emerald-300";
              return (
                <li key={name} className="flex items-center gap-2">
                  <span className="w-20 capitalize text-[11px] text-slate-300">{name}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                    <div
                      className={`h-full rounded-full bg-gradient-to-r ${v === "drift" ? "from-red-500 to-rose-500" : v === "watch" ? "from-amber-400 to-orange-500" : "from-emerald-400 to-teal-500"}`}
                      style={{ width: `${Math.min(100, s.psi * 250)}%` }}
                    />
                  </div>
                  <span className={`w-16 text-right rounded-full border px-2 py-0.5 text-center text-[9px] font-bold uppercase ${cls}`}>
                    {v} · {s.psi.toFixed(2)}
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="text-[11px] text-slate-600">
            {drift?.status === "not-trained"
              ? "Detector not trained yet — train the model in the Evaluation center"
              : "Insufficient recent samples — scoring continues; drift verdict pending"}
          </p>
        )}
      </div>
    </Panel>
  );
}

function SystemHealth({ health, feeds }) {
  const rows = [
    { label: "Collectors", ok: true, detail: "ingest active" },
    { label: "Event pipeline", ok: true, detail: "normalizing" },
    { label: "Database", ok: true, detail: "connected" },
    {
      label: "Data quality",
      ok: (health?.data_quality?.status || "ok") !== "degraded",
      detail: health?.data_quality?.status || "ok",
    },
    {
      label: "Single instance",
      ok: !!health?.single_instance,
      detail: health?.single_instance ? "lock held" : "standby",
    },
  ];
  const feedsHealthy = (feeds || []).filter((f) => f.state && !f.state.last_error).length;
  const feedsTotal = (feeds || []).length;

  return (
    <Panel
      title="Platform Health"
      subtitle="BARAQ service state — a self-hosted SOC must know its own health"
      action={
        <Link
          to="/settings"
          className="shrink-0 text-xs font-semibold text-cyan-400 transition-colors hover:text-cyan-300"
        >
          Settings →
        </Link>
      }
    >
      <ul className="space-y-1.5">
        {rows.map((r) => (
          <li key={r.label} className="flex items-center gap-2">
            <span
              className={`h-1.5 w-1.5 shrink-0 rounded-full ${r.ok ? "bg-emerald-400" : "bg-red-400"}`}
            />
            <span className="w-32 text-[11px] text-slate-300">{r.label}</span>
            <span className={`text-[10px] uppercase tracking-wide ${r.ok ? "text-emerald-300/90" : "text-red-300"}`}>
              {r.ok ? "healthy" : "attention"}
            </span>
            <span className="ml-auto truncate font-mono text-[10px] text-slate-600">{r.detail}</span>
          </li>
        ))}
        <li className="flex items-center gap-2">
          <span
            className={`h-1.5 w-1.5 shrink-0 rounded-full ${
              feedsTotal === 0
                ? "bg-slate-500"
                : feedsHealthy === feedsTotal
                  ? "bg-emerald-400"
                  : "bg-orange-400"
            }`}
          />
          <span className="w-32 text-[11px] text-slate-300">Threat intel</span>
          <span
            className={`text-[10px] uppercase tracking-wide ${
              feedsTotal === 0
                ? "text-slate-400"
                : feedsHealthy === feedsTotal
                  ? "text-emerald-300/90"
                  : "text-amber-300"
            }`}
          >
            {feedsTotal === 0 ? "not configured" : feedsHealthy === feedsTotal ? "healthy" : "degraded"}
          </span>
          <span className="ml-auto font-mono text-[10px] text-slate-600">
            {feedsTotal === 0 ? "no providers — 0/0" : `${feedsHealthy}/${feedsTotal} providers`}
          </span>
        </li>
      </ul>

      {feedsTotal > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5 border-t border-white/5 pt-3">
          {feeds.slice(0, 6).map((f) => (
            <span
              key={f.name || f.id}
              title={f.state?.last_error || f.name}
              className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[9px] ${
                f.state && !f.state.last_error
                  ? "border-white/10 bg-white/[0.03] text-slate-400"
                  : "border-red-400/25 bg-red-500/[0.06] text-red-300"
              }`}
            >
              <span
                className={`h-1 w-1 rounded-full ${f.state && !f.state.last_error ? "bg-emerald-400" : "bg-red-400"}`}
              />
              {f.name || f.id}
            </span>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                               */
/* ------------------------------------------------------------------ */
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
  const [incidents, setIncidents] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [entities, setEntities] = useState([]);
  const [runs, setRuns] = useState([]);
  const [evalData, setEvalData] = useState(null);
  const [mlStatus, setMlStatus] = useState(null);
  const [drift, setDrift] = useState(null);
  const [health, setHealth] = useState(null);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [strikeAlert, setStrikeAlert] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = (t) => {
    setToast(t);
    setTimeout(() => setToast(null), 3200);
  };

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
      api.alerts({ page_size: 10 }),
      api.incidents({ limit: 100 }),
      api.get("/api/intel/feeds").catch(() => ({ feeds: [] })),
      api.events({ page_size: 40 }).catch(() => ({ items: [] })),
    ])
      .then(([s, t, c, att, ta, ub, dm, rd, al, inc, fd, evs]) => {
        setSummary(s);
        setTimeline(t);
        setCategories(c);
        setAttacks(att);
        setTopAttackers(ta);
        setUserBehavior(ub);
        setDetectionMethods(dm);
        setRiskDistribution(rd);
        setAlerts(al.items || []);
        setIncidents(inc.items || []);
        setFeeds(fd?.feeds || []);
        setEvents(evs?.items || []);
        setLastUpdated(new Date());
      })
      .catch((e) => setError(e.message));

    // Secondary panels load independently so a slow endpoint can never
    // block the command center itself.
    api
      .rbaEntities({ min_level: "HIGH", limit: 5 })
      .then((r) => setEntities(r?.entities || []))
      .catch(() => {});
    api
      .automationRuns(50)
      .then((r) => setRuns(r?.runs || []))
      .catch(() => {});
    api.evaluationLatest().then(setEvalData).catch(() => {});
    api.get("/api/system/ml/status").then(setMlStatus).catch(() => {});
    api.get("/api/health").then(setHealth).catch(() => {});
    api
      .get("/api/system/ml/drift?hours=24")
      .then(setDrift)
      .catch(() => {});
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  if (error && !summary) return <ErrorBanner message={error} onRetry={load} />;
  if (!summary) return <Loading label="Loading war room" />;

  const eps = ((summary.events_last_hour ?? 0) / 3600).toFixed(1);
  const feedsHealthy = feeds.filter((f) => f.state && !f.state.last_error).length;
  const openCritical = incidents.filter((i) => i.severity === "critical").length;
  const score = summary.security_score ?? 0;
  const scoreColor =
    summary.risk_level === "CRITICAL" || summary.system_status === "CRITICAL"
      ? "red"
      : summary.risk_level === "HIGH" || summary.system_status === "ATTENTION"
        ? "orange"
        : "green";
  const activeAlerts = summary.active_alerts ?? 0;
  const criticalAlerts = summary.critical_threats ?? 0;
  const highRiskEntities = entities.length;

  return (
    <div className="space-y-5 pb-12">
      <PageHeader
        label="War Room · Live"
        title="Security Operations Center"
        subtitle="Detect · Triage · Investigate · Respond — one command center"
        actions={
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1.5 rounded-full border border-emerald-400/25 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-emerald-300 sm:inline-flex">
              <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-emerald-400" />
              Live
            </span>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2 text-xs font-medium text-slate-300 transition-all hover:border-cyan-400/30 hover:bg-white/[0.08] hover:text-cyan-200"
            >
              <RefreshIcon className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      {/* KPI row — how healthy is the SOC right now */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricBox
          label="Security Score"
          value={Math.round(score)}
          icon={BoltIcon}
          sub={`Status: ${summary?.system_status ?? "UNKNOWN"}`}
          gauge={score}
          color={scoreColor}
        />
        <MetricBox
          label="Open Incidents"
          value={incidents.length}
          icon={IncidentsIcon}
          sub={openCritical > 0 ? `${openCritical} critical — engage now` : "No critical cases open"}
          color={openCritical > 0 ? "red" : "violet"}
        />
        <MetricBox
          label="Active Alerts"
          value={activeAlerts}
          icon={AlertsIcon}
          sub={criticalAlerts > 0 ? `${criticalAlerts} critical` : "No critical alerts"}
          color={criticalAlerts > 0 ? "red" : "cyan"}
        />
        <MetricBox
          label="High Risk Entities"
          value={highRiskEntities}
          icon={RiskShieldIcon}
          sub="Score ≥ HIGH in risk center"
          color={highRiskEntities > 0 ? "orange" : "green"}
        />
        <MetricBox
          label="Events / 24h"
          value={(summary?.total_events ?? 0).toLocaleString()}
          icon={BoxesIcon}
          sub={`${eps} events/s last hour`}
          color="cyan"
        />
        <MetricBox
          label="Threat Intel Feeds"
          value={`${feedsHealthy}/${feeds.length}`}
          icon={IntelIcon}
          sub={feedsHealthy === feeds.length ? "All providers healthy" : "Provider degraded"}
          color={feedsHealthy === feeds.length ? "green" : "orange"}
        />
      </div>

      {/* Incident queue + active threats */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <IncidentQueue incidents={incidents} onReload={load} showToast={showToast} />
        </div>
        <ActiveThreats alerts={alerts} riskDistribution={riskDistribution} onStrike={setStrikeAlert} />
      </div>

      {/* Threat timeline — full width */}
      <ThreatTimeline events={events} />

      {/* Attack trends + detection performance */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <AttackTrends timeline={timeline} attacks={attacks} userBehavior={userBehavior} />
        </div>
        <DetectionPerformance evalData={evalData} detectionMethods={detectionMethods} />
      </div>

      {/* MITRE coverage + SOAR */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <MitreCoverage categories={categories} />
        </div>
        <SoarStatus runs={runs} />
      </div>

      {/* Risk intelligence + SOC workload */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <RiskIntelligence entities={entities} />
        </div>
        <SocWorkload incidents={incidents} />
      </div>

      {/* ML intelligence + platform health */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <MlIntelligence
            mlStatus={mlStatus}
            drift={drift}
            anomalies={summary?.anomalies_detected ?? 0}
          />
        </div>
        <SystemHealth health={health} feeds={feeds} />
      </div>

      {lastUpdated && (
        <p className="text-right font-mono text-[10px] text-slate-600">
          LAST UPDATED {lastUpdated.toLocaleTimeString()}
        </p>
      )}

      {strikeAlert && (
        <Strike alert={strikeAlert} onClose={() => setStrikeAlert(null)} onToast={showToast} />
      )}

      {toast && (
        <div className="toast-in fixed right-4 top-4 z-[80] flex items-center gap-2.5 rounded-xl border px-4 py-3 shadow-2xl backdrop-blur-xl sm:right-6 sm:top-6">
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              toast.kind === "success"
                ? "bg-emerald-400 shadow-[0_0_8px_rgba(0,230,118,0.9)]"
                : "bg-amber-400 shadow-[0_0_8px_rgba(255,179,0,0.9)]"
            }`}
          />
          <p className="text-xs font-medium text-slate-200">{toast.text}</p>
        </div>
      )}
    </div>
  );
}