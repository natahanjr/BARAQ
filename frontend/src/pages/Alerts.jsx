import { useEffect, useState } from "react";
import { Link } from "react-router";
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

const selectClass =
  "rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2 text-sm text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 transition-colors";

const STATUSES = ["open", "in_progress", "contained", "closed"];

function OrgChip({ org }) {
  if (!org) return null;
  return (
    <span
      className="max-w-[120px] truncate rounded bg-violet-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-violet-300"
      title={`Organization: ${org}`}
    >
      {org}
    </span>
  );
}

function AlertRow({ alert, selected, onToggle, onFix, onQuickStatus }) {
  return (
    <div
      className={`group flex items-start gap-3 rounded-xl border p-4 transition-all ${
        selected
          ? "border-cyan-500/50 bg-cyan-500/10"
          : "border-slate-700/50 bg-slate-800/30 hover:border-cyan-500/30 hover:bg-slate-800/50"
      }`}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(alert.id)}
        title="Select for bulk triage"
        aria-label={`Select alert ${alert.id}`}
        className="mt-1 h-4 w-4 shrink-0 cursor-pointer accent-cyan-500"
      />
      <Link to={`/alerts/${alert.id}`} className="block min-w-0 flex-1">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] text-slate-500">#{alert.id}</span>
              <h3 className="truncate text-sm font-semibold text-white group-hover:text-cyan-300">
                {alert.name}
              </h3>
            </div>
            <p className="mt-1.5 line-clamp-2 text-sm text-slate-300">{alert.evidence}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <RiskBadge level={alert.risk_level} score={alert.risk_score} />
              {isAdmin() && <OrgChip org={alert.org} />}
              {alert.mitre_id && (
                <span className="rounded bg-black/30 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                  {alert.mitre_id}
                </span>
              )}
              {(alert.intel_hits || 0) > 0 && (
                <span
                  title="Known-bad indicator(s) flagged at detection time"
                  className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold text-rose-300"
                >
                  ⚡ {alert.intel_hits} intel hit{alert.intel_hits > 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs font-medium text-slate-400">
              {alert.detection_method || "rule"}
            </p>
            <p className="mt-1 text-[11px] text-slate-500">
              {alert.created_at
                ? new Date(alert.created_at).toLocaleString([], {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })
                : "—"}
            </p>
          </div>
        </div>
      </Link>
      <div className="flex shrink-0 flex-col items-end gap-2">
        {/* Quick triage: change status without opening the alert */}
        <select
          value={alert.status}
          onChange={(e) => onQuickStatus(alert.id, e.target.value)}
          title="Quick triage status"
          aria-label={`Quick status for alert ${alert.id}`}
          className="rounded-lg border border-slate-700 bg-slate-800/70 px-2 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
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
            className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-bold text-emerald-400 transition-colors hover:bg-emerald-500/25"
          >
            Fix
          </button>
        )}
      </div>
    </div>
  );
}

export default function Alerts() {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [error, setError] = useState("");
  const [clearing, setClearing] = useState(false);
  const [clearResult, setClearResult] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);

  const load = () => {
    setError("");
    api
      .alerts({ page, page_size: PAGE_SIZE, status, severity })
      .then(setData)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Security Alerts"
        subtitle="All detected threats and security events"
        actions={
          <div className="flex items-center gap-3">
            {data ? (
              <span className="inline-flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-800/60 px-3.5 py-2 text-sm text-slate-300">
                <AlertsIcon className="h-4 w-4 text-cyan-400" />
                <strong className="text-white">{data.total.toLocaleString()}</strong>
                alerts
              </span>
            ) : null}
            {isAdmin() && (
              <button
                type="button"
                onClick={clearAll}
                disabled={clearing || !data || data.total === 0}
                title="Close all open alerts and force-generate an incident report"
                className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2 text-sm font-semibold text-rose-300 transition-colors hover:bg-rose-500/25 disabled:opacity-40"
              >
                {clearing ? "Clearing..." : "Clear Alerts"}
              </button>
            )}
          </div>
        }
      />

      {clearResult && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          <p className="font-semibold">{clearResult.message}</p>
          {clearResult.report && (
            <a
              href={`/reports/${clearResult.report.file_path.split(/[\\/]/).pop()}`}
              target="_blank"
              rel="noreferrer"
              className="mt-1 inline-block font-medium text-cyan-400 underline-offset-2 hover:underline"
            >
              View incident report ({clearResult.report.title}, {clearResult.report.format}) →
            </a>
          )}
        </div>
      )}

      {/* Bulk triage bar */}
      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-cyan-500/40 bg-cyan-500/10 px-4 py-3">
          <span className="text-sm font-semibold text-cyan-200">
            {selected.size} selected
          </span>
          <button
            type="button"
            onClick={() => bulkStatus("in_progress")}
            disabled={bulkBusy}
            className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-bold text-amber-300 transition-colors hover:bg-amber-500/25 disabled:opacity-40"
          >
            Investigating
          </button>
          <button
            type="button"
            onClick={() => bulkStatus("contained")}
            disabled={bulkBusy}
            className="rounded-lg border border-violet-500/40 bg-violet-500/10 px-3 py-1.5 text-xs font-bold text-violet-300 transition-colors hover:bg-violet-500/25 disabled:opacity-40"
          >
            Contained
          </button>
          <button
            type="button"
            onClick={() => bulkStatus("closed")}
            disabled={bulkBusy}
            className="rounded-lg border border-slate-500/50 bg-slate-700/40 px-3 py-1.5 text-xs font-bold text-slate-200 transition-colors hover:bg-slate-600/50 disabled:opacity-40"
          >
            Close
          </button>
          {isAdmin() && (
            <button
              type="button"
              onClick={bulkFix}
              disabled={bulkBusy}
              className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-bold text-emerald-400 transition-colors hover:bg-emerald-500/25 disabled:opacity-40"
            >
              Fix all
            </button>
          )}
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            disabled={bulkBusy}
            className="ml-auto rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-40"
          >
            Clear selection
          </button>
        </div>
      )}

      {/* Filters */}
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            className={selectClass}
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
            className={selectClass}
            aria-label="Filter by severity"
          >
            <option value="">All Severities</option>
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
              className="rounded-lg border border-slate-600 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-700"
            >
              Reset
            </button>
          )}
        </div>
      </Card>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!data && !error && <Loading label="Loading alerts" />}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No alerts found"
          subtitle={hasFilters ? "No alerts match your filters" : "No alerts have been detected yet"}
          icon="🛡"
        />
      )}

      {data && data.items.length > 0 && (
        <Card>
          <div className="space-y-2">
            <div className="flex items-center justify-between border-b border-slate-700/40 pb-2">
              <label className="flex cursor-pointer items-center gap-2 text-xs font-medium text-slate-400">
                <input
                  type="checkbox"
                  checked={data.items.every((a) => selected.has(a.id))}
                  onChange={(e) => selectVisible(e.target.checked)}
                  aria-label="Select all visible alerts"
                  className="h-4 w-4 cursor-pointer accent-cyan-500"
                />
                Select all on this page
              </label>
              <span className="text-[11px] text-slate-500">
                tick the boxes to bulk-triage
              </span>
            </div>
            {data.items.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                selected={selected.has(alert.id)}
                onToggle={toggleSelect}
                onFix={fixAlert}
                onQuickStatus={quickStatus}
              />
            ))}
          </div>
        </Card>
      )}

      {totalPages > 1 && (
        <Card>
          <Pagination page={page} totalPages={totalPages} onChange={setPage} />
        </Card>
      )}
    </div>
  );
}
