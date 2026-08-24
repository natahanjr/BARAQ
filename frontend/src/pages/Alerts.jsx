import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, isAdmin } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import Pagination from "../components/Pagination.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { AlertsIcon } from "../components/icons.jsx";

const PAGE_SIZE = 25;

const STATUSES = ["open", "in_progress", "contained", "closed"];

function OrgChip({ org }) {
  if (!org) return null;
  return (
    <span
      className="max-w-[120px] truncate rounded-md bg-violet-500/8 px-2.5 py-1 font-mono text-[10px] font-semibold tracking-wide text-violet-300 ring-1 ring-violet-500/15"
      title={`Organization: ${org}`}
    >
      {org}
    </span>
  );
}

function AlertRow({ alert, selected, onToggle, onFix, onQuickStatus }) {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className={`group relative flex items-start gap-4 rounded-2xl border p-5 transition-all duration-300 ${
        selected
          ? "border-cyan-400/40 bg-gradient-to-br from-cyan-500/[0.08] via-transparent to-violet-500/[0.04] shadow-[0_0_30px_-8px_rgba(0,240,255,0.15)]"
          : "border-white/[0.06] bg-white/[0.025] hover:border-white/[0.12] hover:bg-white/[0.04] hover:shadow-[0_8px_32px_-8px_rgba(0,0,0,0.4)]"
      }`}
    >
      {/* Subtle left accent line */}
      <div
        className={`absolute left-0 top-4 bottom-4 w-[2px] rounded-full transition-all duration-300 ${
          alert.severity === "critical"
            ? "bg-gradient-to-b from-red-400 via-red-500 to-transparent"
            : alert.severity === "high"
            ? "bg-gradient-to-b from-orange-400 via-orange-500/60 to-transparent"
            : alert.severity === "medium"
            ? "bg-gradient-to-b from-blue-400 via-blue-500/60 to-transparent"
            : "bg-gradient-to-b from-slate-400/40 via-slate-500/20 to-transparent"
        }`}
      />

      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(alert.id)}
        title="Select for bulk triage"
        aria-label={`Select alert ${alert.id}`}
        className="mt-1.5 h-[15px] w-[15px] shrink-0 cursor-pointer rounded-[4px] border-[1.5px] border-white/20 bg-transparent accent-cyan-500 transition-all checked:border-cyan-500 checked:bg-cyan-500"
      />

      <Link to={`/alerts/${alert.id}`} className="block min-w-0 flex-1">
        <div className="flex items-start justify-between gap-5">
          <div className="min-w-0 flex-1">
            {/* Header row */}
            <div className="flex items-center gap-3">
              <span className="font-mono text-[11px] font-medium text-slate-500/70">
                #{alert.id}
              </span>
              <h3 className="truncate text-[14px] font-semibold leading-snug tracking-[-0.01em] text-white/90 transition-colors group-hover:text-cyan-200">
                {alert.name}
              </h3>
            </div>

            {/* Evidence */}
            <p className="mt-2 line-clamp-2 text-[13px] leading-relaxed text-slate-400/90">
              {alert.evidence}
            </p>

            {/* Badges row */}
            <div className="mt-3.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <RiskBadge level={alert.risk_level} score={alert.risk_score} />
              {isAdmin() && <OrgChip org={alert.org} />}
              {alert.mitre_id && (
                <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] font-medium text-slate-400 ring-1 ring-white/[0.06]">
                  {alert.mitre_id}
                </span>
              )}
              {(alert.intel_hits || 0) > 0 && (
                <span
                  title="Known-bad indicator(s) flagged at detection time"
                  className="inline-flex items-center gap-1 rounded-md border border-rose-500/25 bg-rose-500/[0.08] px-2.5 py-1 text-[10px] font-semibold text-rose-300"
                >
                  <span className="text-[11px]">&#9889;</span>
                  {alert.intel_hits} intel hit{alert.intel_hits > 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>

          {/* Right side: method + time */}
          <div className="shrink-0 text-right">
            <span className="inline-block rounded-md bg-white/[0.04] px-2.5 py-1 text-[11px] font-medium text-slate-400 ring-1 ring-white/[0.06]">
              {alert.detection_method || "rule"}
            </span>
            <p className="mt-2.5 text-[11px] font-medium text-slate-500/70">
              {alert.created_at
                ? new Date(alert.created_at).toLocaleString([], {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })
                : "\u2014"}
            </p>
          </div>
        </div>
      </Link>

      {/* Right actions */}
      <div className="flex shrink-0 flex-col items-end gap-2.5">
        <select
          value={alert.status}
          onChange={(e) => onQuickStatus(alert.id, e.target.value)}
          title="Quick triage status"
          aria-label={`Quick status for alert ${alert.id}`}
          className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-[11px] font-medium text-slate-300 transition-all focus:border-cyan-500/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/15"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s === "in_progress" ? "investigating" : s}
            </option>
          ))}
        </select>
        {isAdmin() && alert.status !== "closed" && (
          <button
            type="button"
            title="Fix alert and restore security score"
            onClick={() => onFix(alert.id)}
            className="rounded-lg border border-emerald-500/25 bg-emerald-500/[0.08] px-3.5 py-2 text-[11px] font-semibold text-emerald-400 transition-all hover:border-emerald-500/40 hover:bg-emerald-500/15 hover:shadow-[0_0_16px_-4px_rgba(0,230,118,0.3)]"
          >
            Fix
          </button>
        )}
      </div>
    </div>
  );
}

export default function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState(() => {
    const v = searchParams.get("status") || "";
    return ["open", "in_progress", "contained", "closed"].includes(v) ? v : "";
  });
  const [severity, setSeverity] = useState(() => searchParams.get("severity") || "");
  const [error, setError] = useState("");
  const [clearing, setClearing] = useState(false);
  const [clearResult, setClearResult] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [clusters, setClusters] = useState(null);
  const [activeCluster, setActiveCluster] = useState(null);

  useEffect(() => {
    api.clusters().then(setClusters).catch(() => setClusters(null));
  }, [data]);

  const selectCluster = (cluster) => {
    if (activeCluster && activeCluster.rule === cluster.rule
        && activeCluster.subject === cluster.subject) {
      setActiveCluster(null);
      return;
    }
    setActiveCluster(cluster);
    const ids = new Set(cluster.alert_ids || []);
    setSelected((prev) => {
      const next = new Set(prev);
      ids.forEach((id) => next.add(id));
      return next;
    });
  };

  useEffect(() => {
    const next = new URLSearchParams();
    if (status) next.set("status", status);
    if (severity) next.set("severity", severity);
    setSearchParams(next, { replace: true });
  }, [status, severity]);

  const load = () => {
    setError("");
    api
      .alerts({ page, page_size: PAGE_SIZE, status, severity })
      .then(setData)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
  }, [page, status, severity]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const hasFilters = status !== "" || severity !== "";

  const reset = () => {
    setStatus("");
    setSeverity("");
    setPage(1);
  };

  const fixAlert = async (id) => {
    setError("");
    try {
      await api.fixAlert(id);
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectVisible = (checked) => {
    setSelected((prev) => {
      const next = new Set(prev);
      const ids = data ? data.items.map((a) => a.id) : [];
      ids.forEach((id) => (checked ? next.add(id) : next.delete(id)));
      return next;
    });
  };

  const quickStatus = async (id, status) => {
    setError("");
    try {
      await api.setAlertStatus(id, status);
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const bulkStatus = async (status) => {
    if (selected.size === 0) return;
    const label = status === "in_progress" ? "investigating" : status;
    if (status === "closed" && !window.confirm(`Close ${selected.size} selected alert(s)?`)) return;
    setBulkBusy(true);
    setError("");
    try {
      const results = await Promise.allSettled(
        [...selected].map((id) => api.setAlertStatus(id, status))
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} alert(s) failed to update`);
      setSelected(new Set());
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const bulkFix = async () => {
    if (selected.size === 0) return;
    if (!window.confirm(`Fix ${selected.size} selected alert(s)?`)) return;
    setBulkBusy(true);
    setError("");
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.fixAlert(id)));
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} alert(s) failed to fix`);
      setSelected(new Set());
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBulkBusy(false);
    }
  };

  const clearAll = async () => {
    if (!data || data.total === 0) return;
    if (!window.confirm("Clear all open alerts? A forced security report will be generated first.")) return;
    setClearing(true);
    setError("");
    setClearResult(null);
    try {
      const result = await api.clearAlerts();
      setClearResult(result);
      setStatus("");
      setSeverity("");
      setPage(1);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Page header */}
      <div className="flex flex-wrap items-end justify-between gap-5">
        <div className="min-w-0">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            Security Operations
          </p>
          <h1 className="text-[32px] font-bold leading-tight tracking-[-0.035em] text-white">
            Alerts
          </h1>
          <p className="mt-1.5 text-[13px] font-normal text-slate-400/80">
            All detected threats and security events
          </p>
        </div>

        <div className="flex items-center gap-3">
          {data && (
            <div className="flex items-center gap-2.5 rounded-xl border border-white/[0.06] bg-white/[0.025] px-4 py-2.5">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/10">
                <AlertsIcon className="h-3.5 w-3.5 text-cyan-400" />
              </span>
              <div>
                <p className="text-[18px] font-bold tabular-nums tracking-tight text-white">
                  {data.total.toLocaleString()}
                </p>
                <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                  alerts
                </p>
              </div>
            </div>
          )}
          {isAdmin() && (
            <button
              type="button"
              onClick={clearAll}
              disabled={clearing || !data || data.total === 0}
              title="Close all open alerts and force-generate an incident report"
              className="rounded-xl border border-rose-500/25 bg-rose-500/[0.06] px-4 py-2.5 text-[13px] font-semibold text-rose-400 transition-all hover:border-rose-500/40 hover:bg-rose-500/12 hover:shadow-[0_0_20px_-4px_rgba(255,61,113,0.2)] disabled:opacity-40"
            >
              {clearing ? (
                <span className="flex items-center gap-2">
                  <span className="h-3 w-3 animate-spin rounded-full border-2 border-rose-400 border-t-transparent" />
                  Clearing...
                </span>
              ) : (
                "Clear Alerts"
              )}
            </button>
          )}
        </div>
      </div>

      {/* Clear result */}
      {clearResult && (
        <div className="rounded-2xl border p-5" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)" }}>
          <div className="flex items-start gap-3">
            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs" style={{ background: "rgba(16,185,129,0.15)", color: "var(--success-text, #065f46)" }}>
              &#10003;
            </span>
            <div>
              <p className="text-sm font-semibold" style={{ color: "var(--success-text, #065f46)" }}>{clearResult.message}</p>
              {clearResult.report && (
                <a
                  href={`/reports/${clearResult.report.file_path.split(/[\\/]/).pop()}`}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1.5 inline-flex items-center gap-1 text-[13px] font-medium text-cyan-400 transition-colors hover:text-cyan-300"
                >
                  View incident report ({clearResult.report.title}, {clearResult.report.format})
                  <span className="text-[11px]">&rarr;</span>
                </a>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Bulk triage bar */}
      {selected.size > 0 && (
        <div className="animate-in slide-in-from-top-2 rounded-2xl border border-cyan-400/25 bg-gradient-to-r from-cyan-500/[0.08] via-cyan-500/[0.04] to-transparent p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-500/15 text-[11px] font-bold text-cyan-300">
                {selected.size}
              </span>
              <span className="text-[13px] font-semibold text-cyan-200">selected</span>
            </div>
            <div className="h-4 w-px bg-white/10" />
            <button
              type="button"
              onClick={() => bulkStatus("in_progress")}
              disabled={bulkBusy}
              className="rounded-lg border border-amber-500/25 bg-amber-500/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-amber-300 transition-all hover:bg-amber-500/12 disabled:opacity-40"
            >
              Investigating
            </button>
            <button
              type="button"
              onClick={() => bulkStatus("contained")}
              disabled={bulkBusy}
              className="rounded-lg border border-violet-500/25 bg-violet-500/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-violet-300 transition-all hover:bg-violet-500/12 disabled:opacity-40"
            >
              Contained
            </button>
            <button
              type="button"
              onClick={() => bulkStatus("closed")}
              disabled={bulkBusy}
              className="rounded-lg border border-white/[0.1] bg-white/[0.03] px-3.5 py-1.5 text-[11px] font-semibold text-slate-200 transition-all hover:bg-white/[0.06] disabled:opacity-40"
            >
              Close
            </button>
            {isAdmin() && (
              <button
                type="button"
                onClick={bulkFix}
                disabled={bulkBusy}
                className="rounded-lg border border-emerald-500/25 bg-emerald-500/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-emerald-400 transition-all hover:bg-emerald-500/12 disabled:opacity-40"
              >
                Fix all
              </button>
            )}
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              disabled={bulkBusy}
              className="ml-auto rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 py-1.5 text-[11px] font-medium text-slate-400 transition-all hover:bg-white/[0.06] disabled:opacity-40"
            >
              Clear selection
            </button>
          </div>
        </div>
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-white/[0.06] bg-white/[0.025] p-4">
        <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-500">
          Filter
        </span>
        <div className="h-4 w-px bg-white/[0.06]" />
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 py-2 text-[12px] font-medium text-slate-300 transition-all focus:border-cyan-500/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/15"
          aria-label="Filter by status"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">Investigating</option>
          <option value="contained">Contained</option>
          <option value="closed">Closed</option>
        </select>

        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 py-2 text-[12px] font-medium text-slate-300 transition-all focus:border-cyan-500/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/15"
          aria-label="Filter by severity"
        >
          <option value="">All Severities</option>
          <option value="critical,high">Critical + High</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        {hasFilters && (
          <button
            type="button"
            onClick={reset}
            className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 py-2 text-[12px] font-medium text-slate-400 transition-all hover:bg-white/[0.06] hover:text-slate-200"
          >
            Reset
          </button>
        )}

        {hasFilters && (
          <span className="ml-auto text-[11px] text-slate-500">
            Filtering active
          </span>
        )}
      </div>

      {clusters && clusters.cluster_count > 1 && (
        <div className="mb-4 rounded-2xl border border-white/[0.06] bg-white/[0.025] p-4">
          <div className="mb-2.5 flex items-baseline justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-500">
              Behaviour clusters — {clusters.cluster_count} patterns covering{" "}
              {clusters.alerts_covered} open alerts
            </span>
            {activeCluster && (
              <button
                type="button"
                onClick={() => setActiveCluster(null)}
                className="text-[11px] font-medium text-cyan-400 hover:text-cyan-300"
              >
                Show all
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {clusters.clusters.slice(0, 8).map((c) => {
              const isActive =
                activeCluster && activeCluster.rule === c.rule
                && activeCluster.subject === c.subject
                && activeCluster.parent === c.parent;
              return (
                <button
                  key={`${c.rule}|${c.subject}|${c.parent}`}
                  type="button"
                  onClick={() => selectCluster(c)}
                  title={`Select ${c.count} alert(s) for bulk triage`}
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-medium transition-all ${
                    isActive
                      ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-300"
                      : "border-white/[0.08] bg-white/[0.03] text-slate-400 hover:border-white/[0.16] hover:text-slate-200"
                  }`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
                  {c.rule}
                  <span className="opacity-60">·</span>
                  <span className="tabular-nums">{c.count}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!data && !error && <Loading label="Loading alerts" />}

      {data && data.items.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-3xl border border-white/[0.04] bg-white/[0.015] px-8 py-20 text-center">
          <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/10 to-violet-500/10 ring-1 ring-white/[0.06]">
            <svg className="h-8 w-8 text-cyan-400/60" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h3 className="text-[17px] font-semibold text-white/90">
            {hasFilters ? "No alerts match your filters" : "No alerts detected"}
          </h3>
          <p className="mt-2 max-w-sm text-[13px] leading-relaxed text-slate-400/80">
            {hasFilters
              ? "Try adjusting your filters to see more results"
              : "The system is monitoring for threats. Alerts will appear here when detected."}
          </p>
          {hasFilters && (
            <button
              type="button"
              onClick={reset}
              className="mt-5 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.06] px-5 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/12"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="space-y-2">
          {/* Select all bar */}
          <div className="flex items-center justify-between px-1">
            <label className="flex cursor-pointer items-center gap-2.5 text-[12px] font-medium text-slate-400/80">
              <input
                type="checkbox"
                checked={data.items.every((a) => selected.has(a.id))}
                onChange={(e) => selectVisible(e.target.checked)}
                aria-label="Select all visible alerts"
                className="h-[14px] w-[14px] cursor-pointer rounded-[3px] border-[1.5px] border-white/15 bg-transparent accent-cyan-500"
              />
              Select all on this page
            </label>
            <span className="text-[11px] text-slate-500/60">
              {data.items.length} of {data.total.toLocaleString()} alerts
            </span>
          </div>

          {/* Alert rows */}
          <div className="space-y-1.5">
            {(activeCluster
              ? data.items.filter((a) => (activeCluster.alert_ids || []).includes(a.id))
              : data.items
            ).map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                selected={selected.has(alert.id)}
                onToggle={toggleSelect}
                onFix={fixAlert}
                onQuickStatus={quickStatus}
              />
            ))}
            {activeCluster && data.items.length > 0 && !data.items.some((a) => (activeCluster.alert_ids || []).includes(a.id)) && (
              <p className="py-6 text-center text-[13px] text-slate-500">
                This cluster's alerts are on other pages — use bulk selection from the cluster chip.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center pt-4">
          <Pagination page={page} totalPages={totalPages} onChange={setPage} />
        </div>
      )}
    </div>
  );
}
