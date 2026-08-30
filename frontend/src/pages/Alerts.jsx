import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, isAdmin } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { ConfirmDialog, ContextMenu } from "../components/ui/index.js";

const PAGE_SIZE = 25;

const STATUSES = ["open", "in_progress", "contained", "closed"];

function OrgChip({ org }) {
  if (!org) return null;
  return (
    <span
      className="max-w-[120px] truncate rounded-md px-2.5 py-1 font-mono text-[11px] font-semibold tracking-wide"
      style={{ background: "var(--accent-violet)", color: "var(--fg-primary)", opacity: 0.7 }}
      title={`Organization: ${org}`}
    >
      {org}
    </span>
  );
}

function AlertRow({ alert, selected, onToggle, onFix, onQuickStatus }) {
  const [hovered, setHovered] = useState(false);

  const formatTime = (iso) => {
    if (!iso) return "\u2014";
    return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };

  const contextItems = [
    { label: "Investigate", icon: "🔍", onClick: () => onQuickStatus(alert.id, "in_progress") },
    { label: "Contain", icon: "🛡️", onClick: () => onQuickStatus(alert.id, "contained") },
    { separator: true },
    { label: "View details", icon: "📋", onClick: () => window.location.href = `/alerts/${alert.id}` },
    { separator: true },
    ...(isAdmin() && alert.status !== "closed" ? [
      { label: "Fix alert", icon: "✅", onClick: () => onFix(alert.id) },
    ] : []),
    { label: "Close alert", icon: "✕", onClick: () => onQuickStatus(alert.id, "closed"), danger: true },
  ];

  return (
    <ContextMenu items={contextItems}>
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className={`group relative flex items-start gap-4 rounded-[var(--radius-xl)] border p-5 transition-all duration-300 ${
        selected
          ? "border-[var(--accent-cyan)] bg-[var(--bg-surface)] shadow-lg"
          : "border-[var(--border-default)] bg-[var(--bg-surface)] hover:border-[var(--border-strong)] hover:shadow-lg"
      }`}
    >
      <div
        className={`absolute left-0 top-4 bottom-4 w-[2px] rounded-full transition-all duration-300 ${
          alert.severity === "critical"
            ? "bg-gradient-to-b from-[var(--severity-critical)] to-transparent"
            : alert.severity === "high"
            ? "bg-gradient-to-b from-[var(--severity-high)] to-transparent"
            : alert.severity === "medium"
            ? "bg-gradient-to-b from-[var(--severity-low)] to-transparent"
            : "bg-gradient-to-b from-[var(--fg-faint)] to-transparent"
        }`}
      />

      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(alert.id)}
        title="Select for bulk triage"
        aria-label={`Select alert ${alert.id}`}
        className="mt-1.5 h-[15px] w-[15px] shrink-0 cursor-pointer rounded-[4px] border-[1.5px] border-[var(--border-default)] bg-transparent accent-[var(--accent-cyan)] transition-all checked:border-[var(--accent-cyan)] checked:bg-[var(--accent-cyan)]"
      />

      <Link to={`/alerts/${alert.id}`} className="block min-w-0 flex-1">
        <div className="flex items-start justify-between gap-5">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-3">
              <span className="font-mono text-[11px] font-medium text-[var(--fg-muted)]">
                #{alert.id}
              </span>
              <h3 className="truncate text-[14px] font-semibold leading-snug tracking-[-0.01em] text-[var(--fg-primary)] transition-colors group-hover:text-[var(--accent-cyan)]">
                {alert.name}
              </h3>
            </div>

            <p className="mt-2 line-clamp-2 text-[13px] leading-relaxed text-[var(--fg-secondary)]">
              {alert.evidence}
            </p>

            <div className="mt-3.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <RiskBadge level={alert.risk_level} score={alert.risk_score} />
              {alert.host && (
                <span className="rounded-md bg-[var(--bg-inset)] px-2.5 py-1 font-mono text-[11px] font-medium text-[var(--fg-secondary)] ring-1 ring-[var(--border-subtle)]">
                  {alert.host}
                </span>
              )}
              {isAdmin() && <OrgChip org={alert.org} />}
              {alert.mitre_id && (
                <span className="rounded-md bg-[var(--bg-inset)] px-2.5 py-1 font-mono text-[11px] font-medium text-[var(--fg-secondary)] ring-1 ring-[var(--border-subtle)]">
                  {alert.mitre_id}
                </span>
              )}
              {(alert.intel_hits || 0) > 0 && (
                <span
                  title="Known-bad indicator(s) flagged at detection time"
                  className="inline-flex items-center gap-1 rounded-md border border-[var(--severity-critical)]/25 bg-[var(--severity-critical)]/[0.08] px-2.5 py-1 text-[11px] font-semibold text-[var(--severity-critical)]"
                >
                  <span className="text-[11px]">&#9889;</span>
                  {alert.intel_hits} intel hit{alert.intel_hits > 1 ? "s" : ""}
                </span>
              )}
            </div>
          </div>

          <div className="shrink-0 text-right">
            <span className="inline-block rounded-md bg-[var(--bg-inset)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] ring-1 ring-[var(--border-subtle)]">
              {alert.detection_method || "rule"}
            </span>
            <div className="mt-2 space-y-1">
              {alert.first_seen && (
                <p className="text-[11px] text-[var(--fg-muted)]" title="First seen">
                  {formatTime(alert.first_seen)}
                </p>
              )}
              <p className="text-[11px] font-medium text-[var(--fg-muted)]" title="Last seen">
                {alert.last_seen ? formatTime(alert.last_seen) : formatTime(alert.created_at)}
              </p>
            </div>
          </div>
        </div>
      </Link>

      <div className="flex shrink-0 flex-col items-end gap-2.5">
        <select
          value={alert.status}
          onChange={(e) => onQuickStatus(alert.id, e.target.value)}
          title="Quick triage status"
          aria-label={`Quick status for alert ${alert.id}`}
          className="form-select rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] px-3 py-2 text-[11px] font-medium text-[var(--fg-secondary)] transition-all duration-[var(--duration-normal)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
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
            className="rounded-xl border border-[var(--status-healthy)]/25 bg-[var(--status-healthy)]/[0.08] px-3.5 py-2 text-[11px] font-semibold text-[var(--status-healthy)] transition-all hover:border-[var(--status-healthy)]/40 hover:bg-[var(--status-healthy)]/15"
          >
            Fix
          </button>
        )}
      </div>
    </div>
    </ContextMenu>
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
  const [sortBy, setSortBy] = useState(() => searchParams.get("sort") || "created_at");
  const [sortDir, setSortDir] = useState(() => searchParams.get("dir") || "desc");
  const [error, setError] = useState("");
  const [clearing, setClearing] = useState(false);
  const [clearResult, setClearResult] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [clusters, setClusters] = useState(null);
  const [activeCluster, setActiveCluster] = useState(null);

  // Confirm dialog state
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmConfig, setConfirmConfig] = useState({ title: "", message: "", onConfirm: () => {}, variant: "danger" });
  const [confirmBusy, setConfirmBusy] = useState(false);

  const showConfirm = (title, message, onConfirm, variant = "danger") => {
    setConfirmConfig({ title, message, onConfirm, variant });
    setConfirmOpen(true);
  };

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
    if (sortBy !== "created_at") next.set("sort", sortBy);
    if (sortDir !== "desc") next.set("dir", sortDir);
    setSearchParams(next, { replace: true });
  }, [status, severity, sortBy, sortDir]);

  const load = () => {
    setError("");
    api
      .alerts({ page, page_size: PAGE_SIZE, status, severity, sort: sortBy, dir: sortDir })
      .then(setData)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
  }, [page, status, severity, sortBy, sortDir]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const hasFilters = status !== "" || severity !== "";

  const reset = () => {
    setStatus("");
    setSeverity("");
    setSortBy("created_at");
    setSortDir("desc");
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

  const doBulkStatus = async (status) => {
    if (selected.size === 0) return;
    setConfirmBusy(true);
    setError("");
    try {
      const results = await Promise.allSettled(
        [...selected].map((id) => api.setAlertStatus(id, status))
      );
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} alert(s) failed to update`);
      setSelected(new Set());
      setConfirmOpen(false);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setConfirmBusy(false);
    }
  };

  const bulkStatus = (status) => {
    if (selected.size === 0) return;
    const label = status === "in_progress" ? "investigating" : status;
    if (status === "closed") {
      showConfirm(
        `Close ${selected.size} alert(s)?`,
        `This will change ${selected.size} alert(s) to closed status. You can reopen them later if needed.`,
        () => doBulkStatus(status),
        "warning"
      );
    } else {
      doBulkStatus(status);
    }
  };

  const doBulkFix = async () => {
    if (selected.size === 0) return;
    setConfirmBusy(true);
    setError("");
    try {
      const results = await Promise.allSettled([...selected].map((id) => api.fixAlert(id)));
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} alert(s) failed to fix`);
      setSelected(new Set());
      setConfirmOpen(false);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setConfirmBusy(false);
    }
  };

  const bulkFix = () => {
    if (selected.size === 0) return;
    showConfirm(
      `Fix ${selected.size} alert(s)?`,
      `This will mark ${selected.size} alert(s) as resolved and restore your security score.`,
      doBulkFix,
      "primary"
    );
  };

  const doClearAll = async () => {
    setClearing(true);
    setError("");
    setClearResult(null);
    try {
      const result = await api.clearAlerts();
      setClearResult(result);
      setStatus("");
      setSeverity("");
      setPage(1);
      setConfirmOpen(false);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setClearing(false);
    }
  };

  const clearAll = () => {
    if (!data || data.total === 0) return;
    showConfirm(
      "Clear all open alerts?",
      "A forced security report will be generated first. This will close all open alerts and create an incident report.",
      doClearAll,
      "warning"
    );
  };

  return (
    <div className="space-y-6 pb-16">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Security Operations</p>
          <h1 className="mt-1 text-page-title text-[var(--fg-primary)]">Alerts</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">All detected threats and security events</p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <div className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-300 p-5 hover:border-[var(--border-strong)] hover:shadow-lg">
              <div className="absolute -right-6 -top-6 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-40" style={{ background: "var(--accent-cyan)" }} />
              <div className="relative flex items-start justify-between">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Alerts</p>
                  <p className="mt-2 text-[28px] font-bold tabular-nums leading-none" style={{ color: "var(--accent-cyan)", fontFeatureSettings: '"tnum"' }}>{data.total.toLocaleString()}</p>
                </div>
                <span className="text-[18px] opacity-50">&#9888;</span>
              </div>
            </div>
          )}
          {isAdmin() && (
            <button
              type="button"
              onClick={clearAll}
              disabled={clearing || !data || data.total === 0}
              title="Close all open alerts and force-generate an incident report"
              className="rounded-xl bg-[var(--accent-cyan)] px-4 py-2.5 text-[13px] font-semibold text-white shadow-lg shadow-[var(--accent-cyan)]/25 transition-all hover:shadow-xl disabled:opacity-40"
            >
              {clearing ? (
                <span className="flex items-center gap-2">
                  <span className="h-3 w-3 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  Clearing...
                </span>
              ) : (
                "Clear Alerts"
              )}
            </button>
          )}
        </div>
      </header>

      {clearResult && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-5">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[var(--status-healthy)]/15 text-xs text-[var(--status-healthy)]">
              &#10003;
            </span>
            <div>
              <p className="text-sm font-semibold text-[var(--fg-primary)]">{clearResult.message}</p>
              {clearResult.report && (
                <a
                  href={`/reports/${clearResult.report.file_path.split(/[\\/]/).pop()}`}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1.5 inline-flex items-center gap-1 text-[13px] font-medium text-[var(--accent-cyan)] transition-all hover:text-[var(--accent-cyan)]/80"
                >
                  View incident report ({clearResult.report.title}, {clearResult.report.format})
                  <span className="text-[11px]">&rarr;</span>
                </a>
              )}
            </div>
          </div>
        </div>
      )}

      {selected.size > 0 && (
        <div className="animate-in slide-in-from-top-2 rounded-[var(--radius-2xl)] border border-[var(--accent-cyan)]/25 bg-[var(--bg-surface)] p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--accent-cyan)]/15 text-[11px] font-bold text-[var(--accent-cyan)]">
                {selected.size}
              </span>
              <span className="text-[13px] font-semibold text-[var(--accent-cyan)]">selected</span>
            </div>
            <div className="h-4 w-px bg-[var(--border-default)]" />
            <button
              type="button"
              onClick={() => bulkStatus("in_progress")}
              disabled={bulkBusy}
              className="rounded-xl border border-[var(--severity-medium)]/25 bg-[var(--severity-medium)]/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-[var(--severity-medium)] transition-all hover:bg-[var(--severity-medium)]/12 disabled:opacity-40"
            >
              Investigating
            </button>
            <button
              type="button"
              onClick={() => bulkStatus("contained")}
              disabled={bulkBusy}
              className="rounded-xl border border-[var(--accent-violet)]/25 bg-[var(--accent-violet)]/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-[var(--accent-violet)] transition-all hover:bg-[var(--accent-violet)]/12 disabled:opacity-40"
            >
              Contained
            </button>
            <button
              type="button"
              onClick={() => bulkStatus("closed")}
              disabled={bulkBusy}
              className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-1.5 text-[11px] font-semibold text-[var(--fg-secondary)] hover:bg-[var(--bg-surface)] disabled:opacity-40"
            >
              Close
            </button>
            {isAdmin() && (
              <button
                type="button"
                onClick={bulkFix}
                disabled={bulkBusy}
                className="rounded-xl border border-[var(--status-healthy)]/25 bg-[var(--status-healthy)]/[0.06] px-3.5 py-1.5 text-[11px] font-semibold text-[var(--status-healthy)] transition-all hover:bg-[var(--status-healthy)]/12 disabled:opacity-40"
              >
                Fix all
              </button>
            )}
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              disabled={bulkBusy}
              className="ml-auto rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-1.5 text-[11px] font-medium text-[var(--fg-muted)] hover:bg-[var(--bg-surface)] disabled:opacity-40"
            >
              Clear selection
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-4">
        <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">
          Filter
        </span>
        <div className="h-4 w-px bg-[var(--border-default)]" />
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-2 text-[12px] font-medium text-[var(--fg-secondary)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
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
          className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-2 text-[12px] font-medium text-[var(--fg-secondary)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
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
            className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-2 text-[12px] font-medium text-[var(--fg-muted)] hover:bg-[var(--bg-surface)] hover:text-[var(--fg-secondary)]"
          >
            Reset
          </button>
        )}

        <div className="h-4 w-px bg-[var(--border-default)]" />
        <select
          value={sortBy}
          onChange={(e) => { setSortBy(e.target.value); setPage(1); }}
          className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-3.5 py-2 text-[12px] font-medium text-[var(--fg-secondary)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
          aria-label="Sort alerts by"
        >
          <option value="created_at">Last Seen</option>
          <option value="first_seen">First Seen</option>
          <option value="severity">Severity</option>
          <option value="risk_score">Risk Score</option>
          <option value="name">Alert Name</option>
        </select>
        <button
          type="button"
          onClick={() => setSortDir((d) => d === "desc" ? "asc" : "desc")}
          className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-2.5 py-2 text-[12px] font-medium text-[var(--fg-muted)] hover:bg-[var(--bg-surface)] hover:text-[var(--fg-secondary)]"
          aria-label={`Sort ${sortDir === "desc" ? "ascending" : "descending"}`}
        >
          {sortDir === "desc" ? "↓" : "↑"}
        </button>

        {hasFilters && (
          <span className="ml-auto text-[11px] text-[var(--fg-muted)]">
            Filtering active
          </span>
        )}
      </div>

      {clusters && clusters.cluster_count > 1 && (
        <div className="mb-4 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-4">
          <div className="mb-2.5 flex items-baseline justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">
              Behaviour clusters — {clusters.cluster_count} patterns covering{" "}
              {clusters.alerts_covered} open alerts
            </span>
            {activeCluster && (
              <button
                type="button"
                onClick={() => setActiveCluster(null)}
                className="text-[11px] font-medium text-[var(--accent-cyan)] hover:text-[var(--accent-cyan)]/80"
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
                      ? "border-[var(--accent-cyan)]/50 bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)]"
                      : "border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--fg-muted)] hover:border-[var(--border-strong)] hover:text-[var(--fg-secondary)]"
                  }`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-[var(--fg-muted)]" />
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
        <div className="flex flex-col items-center justify-center rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 px-8 py-20 text-center">
          <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-[var(--radius-xl)] bg-[var(--accent-cyan)]/10 ring-1 ring-[var(--border-subtle)]">
            <svg className="h-8 w-8 text-[var(--accent-cyan)]/60" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h3 className="text-[17px] font-semibold text-[var(--fg-primary)]">
            {hasFilters ? "No alerts match your filters" : "No alerts detected"}
          </h3>
          <p className="mt-2 max-w-sm text-[13px] leading-relaxed text-[var(--fg-secondary)]">
            {hasFilters
              ? "Try adjusting your filters to see more results"
              : "The system is monitoring for threats. Alerts will appear here when detected."}
          </p>
          {hasFilters && (
            <button
              type="button"
              onClick={reset}
              className="mt-5 rounded-xl bg-[var(--accent-cyan)] px-5 py-2.5 text-[13px] font-semibold text-white shadow-lg shadow-[var(--accent-cyan)]/25 transition-all hover:shadow-xl"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between px-1">
            <label className="flex cursor-pointer items-center gap-2.5 text-[12px] font-medium text-[var(--fg-secondary)]">
              <input
                type="checkbox"
                checked={data.items.every((a) => selected.has(a.id))}
                onChange={(e) => selectVisible(e.target.checked)}
                aria-label="Select all visible alerts"
                className="h-[14px] w-[14px] cursor-pointer rounded-[3px] border-[1.5px] border-[var(--border-default)] bg-transparent accent-[var(--accent-cyan)]"
              />
              Select all on this page
            </label>
            <span className="text-[11px] text-[var(--fg-muted)]">
              {data.items.length} of {data.total.toLocaleString()} alerts
            </span>
          </div>

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
              <p className="py-6 text-center text-[13px] text-[var(--fg-muted)]">
                This cluster's alerts are on other pages — use bulk selection from the cluster chip.
              </p>
            )}
          </div>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-4">
          <button
            type="button"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-4 py-2 text-[12px] font-medium text-[var(--fg-secondary)] hover:bg-[var(--bg-surface)] disabled:opacity-40"
          >
            Prev
          </button>
          <span className="text-[12px] text-[var(--fg-muted)]">
            Page {page} of {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200 px-4 py-2 text-[12px] font-medium text-[var(--fg-secondary)] hover:bg-[var(--bg-surface)] disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}

      <ConfirmDialog
        open={confirmOpen}
        onClose={() => { setConfirmOpen(false); setConfirmBusy(false); }}
        onConfirm={confirmConfig.onConfirm}
        title={confirmConfig.title}
        message={confirmConfig.message}
        confirmLabel={confirmConfig.variant === "warning" ? "Proceed" : confirmConfig.variant === "primary" ? "Fix all" : "Confirm"}
        variant={confirmConfig.variant}
        loading={confirmBusy}
      />
    </div>
  );
}
