import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, isAdmin } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const STATUSES = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

const SEVERITIES = ["critical", "high", "medium", "low"];

const inputClass =
  "w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10";

const selectClass =
  "rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10";

function confidenceTone(label) {
  return {
    high: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
    medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
    low: "bg-red-500/15 text-red-300 border-red-500/40",
  }[label] || "bg-slate-500/15 text-slate-300 border-slate-500/40";
}

function ConfidenceBadge({ score, label }) {
  const pct = Math.round((score ?? 0) * 100);
  return (
    <span
      className={`rounded border px-2 py-0.5 font-mono text-[10px] ${confidenceTone(label)}`}
      title={`Confidence: ${pct}%${label ? ` (${label})` : ""}`}
    >
      {pct}% {label || ""}
    </span>
  );
}

function IncidentCard({ incident, onOpen, onSelect, selected }) {
  return (
    <div
      className={`group flex cursor-pointer items-start gap-3 rounded-2xl border p-5 transition-all ${
        selected
          ? "border-cyan-500/40 bg-white/[0.025] shadow-[0_0_20px_-4px_rgba(0,240,255,0.15)]"
          : "border-white/[0.06] bg-white/[0.025] hover:border-white/[0.12] hover:bg-white/[0.035]"
      }`}
      onClick={() => onSelect(incident.id)}
      onDoubleClick={() => onOpen(incident)}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[11px] text-slate-500">{incident.ref}</span>
          <h3 className="truncate text-sm font-semibold text-white group-hover:text-cyan-300">
            {incident.title}
          </h3>
        </div>
        {incident.description && (
          <p className="mt-1.5 line-clamp-2 text-sm text-slate-400">{incident.description}</p>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          {incident.confidence != null && (
            <ConfidenceBadge score={incident.confidence} label={null} />
          )}
          {incident.alert_count > 0 && (
            <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-cyan-400 ring-1 ring-white/[0.06]">
              {incident.alert_count} alert{incident.alert_count === 1 ? "" : "s"}
            </span>
          )}
          {incident.mitre_id && (
            <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-slate-400 ring-1 ring-white/[0.06]">
              {incident.mitre_id}
            </span>
          )}
        </div>
      </div>
      <div className="shrink-0 text-right">
        {incident.owner && (
          <p className="text-xs font-medium text-slate-400">{incident.owner}</p>
        )}
        <p className="mt-1 text-[11px] text-slate-500">
          {incident.created_at
            ? new Date(incident.created_at).toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "—"}
        </p>
      </div>
    </div>
  );
}

function CreateIncident({ onCreated }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("high");
  const [owner, setOwner] = useState("");
  const [host, setHost] = useState("");
  const [alertIds, setAlertIds] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    if (!title.trim() || saving) return;
    setSaving(true);
    setError("");
    try {
      await api.createIncident({
        title: title.trim(),
        description,
        severity,
        owner,
        host,
        alert_ids: alertIds
          .split(",")
          .map((s) => parseInt(s, 10))
          .filter((n) => Number.isFinite(n)),
      });
      setTitle("");
      setDescription("");
      setOwner("");
      setHost("");
      setAlertIds("");
      setSeverity("high");
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold text-white">New Incident</h3>
        {isAdmin() && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]"
          >
            {open ? "Cancel" : "Create"}
          </button>
        )}
      </div>
      {open && (
        <form onSubmit={submit} className="mt-4 space-y-3">
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Incident title (e.g. Ransomware outbreak on WS-ALPHA)"
            className={inputClass}
            required
          />
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Summary of the incident..."
            rows={3}
            className={inputClass}
          />
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectClass}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="Owner"
              className={inputClass}
            />
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="Host"
              className={inputClass}
            />
            <input
              value={alertIds}
              onChange={(e) => setAlertIds(e.target.value)}
              placeholder="Alert IDs (csv)"
              className={inputClass}
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={saving || !title.trim()}
            className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
          >
            {saving ? "Creating..." : "Create Incident"}
          </button>
        </form>
      )}
    </div>
  );
}

function IncidentDetail({ incident, onChanged }) {
  const [comment, setComment] = useState("");
  const [linkIds, setLinkIds] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [investigation, setInvestigation] = useState(null);
  const [investigationError, setInvestigationError] = useState("");

  useEffect(() => {
    let alive = true;
    setInvestigation(null);
    setInvestigationError("");
    api
      .incidentInvestigation(incident.id)
      .then((res) => alive && setInvestigation(res))
      .catch((e) => alive && setInvestigationError(e.message));
    return () => {
      alive = false;
    };
  }, [incident.id]);

  const changeStatus = async (status) => {
    setSaving(true);
    setError("");
    try {
      await api.updateIncident(incident.id, { status });
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const updateField = async (patch) => {
    setSaving(true);
    setError("");
    try {
      await api.updateIncident(incident.id, patch);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const submitComment = async (e) => {
    e.preventDefault();
    if (!comment.trim() || saving) return;
    setSaving(true);
    setError("");
    try {
      await api.addIncidentComment(incident.id, comment.trim());
      setComment("");
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const linkAlerts = async (e) => {
    e.preventDefault();
    const ids = linkIds
      .split(",")
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n));
    if (!ids.length || saving) return;
    setSaving(true);
    setError("");
    try {
      await api.linkIncidentAlerts(incident.id, ids);
      setLinkIds("");
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
            {incident.ref} · {incident.title}
          </h2>
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          {incident.alerts?.length > 0 && (
            <Link
              to={`/investigation?alert=${incident.alerts[0].alert_id}`}
              className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]"
              title="Open the full investigation workspace for this incident's alerts"
            >
              Investigation workspace →
            </Link>
          )}
        </div>
        {incident.description && (
          <p className="mt-2 text-sm leading-relaxed text-slate-300">{incident.description}</p>
        )}
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
          {incident.owner && <span>Owner: <b className="text-slate-300">{incident.owner}</b></span>}
          {incident.host && <span>Host: <b className="text-slate-300">{incident.host}</b></span>}
          {incident.mitre_id && (
            <span>MITRE: <b className="font-mono text-cyan-400">{incident.mitre_id}</b> {incident.mitre_name}</span>
          )}
          {incident.risk_score ? (
            <span>Risk: <b className="text-amber-300">{incident.risk_level} ({incident.risk_score.toFixed(1)})</b></span>
          ) : null}
          {incident.confidence != null && (
            <span>
              Confidence:{" "}
              <b className="text-slate-300">
                {Math.round(incident.confidence * 100)}% (
                {incident.confidence >= 0.75 ? "high" : incident.confidence >= 0.5 ? "medium" : "low"})
              </b>
            </span>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400"><span className="h-1 w-1 rounded-full bg-cyan-400" />Status</h3>
        {isAdmin() ? (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {STATUSES.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => changeStatus(s.value)}
                  disabled={saving || incident.status === s.value}
                  className={`rounded-xl border px-3 py-2 text-xs font-semibold capitalize transition-all disabled:opacity-40 ${
                    incident.status === s.value
                      ? "border-cyan-500/40 bg-cyan-500/[0.12] text-cyan-300"
                      : "border-white/[0.06] bg-white/[0.02] text-slate-400 hover:bg-white/[0.04]"
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <label className="block">
                <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Severity
                </span>
                <select
                  value={incident.severity}
                  onChange={(e) => updateField({ severity: e.target.value })}
                  disabled={saving}
                  className={selectClass}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </label>
              <label className="block flex-1">
                <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Owner (assignee)
                </span>
                <input
                  type="text"
                  defaultValue={incident.owner || ""}
                  placeholder="Unassigned"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") updateField({ owner: e.target.value.trim() });
                  }}
                  onBlur={(e) => {
                    const v = e.target.value.trim();
                    if (v !== (incident.owner || "")) updateField({ owner: v });
                  }}
                  disabled={saving}
                  className={inputClass}
                />
              </label>
            </div>
            <p className="mt-2 text-[10px] text-slate-500">
              Changes are audited and recorded on the timeline.
            </p>
          </>
        ) : (
          <p className="text-xs text-slate-500">
            Current status: <strong className="text-slate-300">{incident.status}</strong> — only
            administrators can change it.
          </p>
        )}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400"><span className="h-1 w-1 rounded-full bg-cyan-400" />Linked Alerts ({incident.alerts?.length || 0})</h3>
        {incident.alerts?.length ? (
          <div className="space-y-1.5">
            {incident.alerts.map((l) => (
              <div
                key={l.alert_id}
                className="flex items-center gap-2 rounded-xl border border-white/[0.04] bg-white/[0.02] px-3 py-2"
              >
                <span className="font-mono text-[11px] text-slate-500">#{l.alert_id}</span>
                <span className="min-w-0 flex-1 truncate text-xs text-slate-200">{l.name}</span>
                <SeverityBadge severity={l.severity} />
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] text-slate-500">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            </div>
            <p className="text-sm font-semibold text-slate-300">No linked alerts</p>
            <p className="mt-1 text-xs text-slate-500">Link alerts to build this case</p>
          </div>
        )}
                {isAdmin() && (
          <form onSubmit={linkAlerts} className="mt-3 flex gap-2">
            <input
              value={linkIds}
              onChange={(e) => setLinkIds(e.target.value)}
              placeholder="Alert IDs to link, comma separated"
              className={inputClass}
            />
            <button
              type="submit"
              disabled={saving}
              className="shrink-0 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
            >
              Link
            </button>
          </form>
        )}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400"><span className="h-1 w-1 rounded-full bg-cyan-400" />Timeline ({incident.comments?.length || 0})</h3>
        <form onSubmit={submitComment} className="mb-4 flex gap-2">
          <input
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Add a note to the timeline..."
            className={inputClass}
          />
          <button
            type="submit"
            disabled={saving || !comment.trim()}
            className="shrink-0 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
          >
            Add
          </button>
        </form>
        {incident.comments?.length ? (
          <div className="space-y-2">
            {incident.comments.map((c) => (
              <div key={c.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-cyan-300">{c.author}</span>
                  {c.kind !== "comment" && (
                    <span className="rounded-md bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-violet-400">
                      {c.kind}
                    </span>
                  )}
                  <span className="ml-auto text-[11px] text-slate-500">
                    {c.created_at ? new Date(c.created_at).toLocaleString() : "—"}
                  </span>
                </div>
                <p className="mt-1.5 whitespace-pre-wrap text-xs leading-relaxed text-slate-300">
                  {c.body}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] text-slate-500">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg>
            </div>
            <p className="text-sm font-semibold text-slate-300">No timeline entries</p>
            <p className="mt-1 text-xs text-slate-500">Add a note to start the timeline</p>
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400"><span className="h-1 w-1 rounded-full bg-cyan-400" />Investigation</h3>
        {investigationError ? (
          <p className="text-xs text-red-400">{investigationError}</p>
        ) : !investigation ? (
          <Loading label="Building investigation..." />
        ) : (
          <div className="space-y-5">
            {(() => {
              const rc = investigation.enrichment.root_cause;
              if (!rc) return null;
              const riskLevel = rc.risk?.level || "";
              const tone =
                riskLevel === "CRITICAL" || riskLevel === "HIGH"
                  ? "text-red-400 border-red-500/40 bg-red-500/10"
                  : riskLevel === "MEDIUM"
                  ? "text-amber-400 border-amber-500/40 bg-amber-500/10"
                  : "text-emerald-400 border-emerald-500/40 bg-emerald-500/10";
              return (
                <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                      Root cause
                    </p>
                    <span className={`rounded border px-2 py-0.5 font-mono text-[11px] ${tone}`}>
                      {riskLevel} · {rc.risk?.risk ?? "—"}
                    </span>
                    <span className="text-[11px] font-medium text-slate-200">{rc.assessment}</span>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-300">{rc.summary}</p>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
                    {(rc.observations || []).map((o, idx) => (
                      <span
                        key={idx}
                        className={`text-[11px] ${
                          o.type === "warning"
                            ? "text-amber-300"
                            : o.type === "info"
                            ? "text-cyan-300"
                            : "text-emerald-300"
                        }`}
                      >
                        {o.type === "warning" ? "▲" : o.type === "info" ? "●" : "✓"} {o.text}
                      </span>
                    ))}
                  </div>
                  {(rc.risk?.adjustments || []).length > 0 && (
                    <p className="mt-2 font-mono text-[10px] text-slate-500">
                      risk adjustments:{" "}
                      {rc.risk.adjustments.map((a) => `${a.signal} ${a.delta >= 0 ? "+" : ""}${a.delta}`).join(" · ")}
                    </p>
                  )}
              </div>
            );
            })()}

            {(() => {
              const ch = incident.chain;
              if (!ch || !ch.sequence || ch.sequence.length < 2) return null;
              return (
                <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-violet-400">
                      Attack chain
                    </p>
                    <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-violet-300 ring-1 ring-white/[0.06]">
                      {ch.confidence.toFixed(2)} confidence
                    </span>
                    {ch.risk_boost > 0 && (
                      <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-red-300 ring-1 ring-white/[0.06]">
                        risk +{ch.risk_boost}
                      </span>
                    )}
                    {ch.cohesive_root && (
                      <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] text-emerald-300 ring-1 ring-white/[0.06]">
                        root: {ch.root_process}
                      </span>
                    )}
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    {ch.sequence.map((s, idx) => (
                      <span key={`${s}-${idx}`} className="flex items-center gap-1.5">
                        <span
                          className={`rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide ring-1 ring-white/[0.06] ${
                            ch.has_terminal && idx === ch.sequence.length - 1
                              ? "text-red-300 ring-red-400/30"
                              : "text-slate-300"
                          }`}
                        >
                          {s}
                        </span>
                        {idx < ch.sequence.length - 1 && (
                          <span className="text-slate-600">→</span>
                        )}
                      </span>
                    ))}
                  </div>
                  <p className="mt-2 text-[11px] leading-relaxed text-slate-400">{ch.narrative}</p>
                  {ch.span_min > 0 && (
                    <p className="mt-1 font-mono text-[10px] text-slate-600">
                      span {ch.span_min.toFixed(0)} min · max gap {ch.max_gap_min.toFixed(1)} min ·{" "}
                      {ch.ordered ? "canonical order" : `${(ch.ordered_ratio * 100).toFixed(0)}% ordered`}
                    </p>
                  )}
                </div>
              );
            })()}

            <div className="flex flex-wrap items-center gap-4">
              <ConfidenceBadge score={investigation.confidence?.score} label={investigation.confidence?.label} />
              <span className="font-mono text-[11px] text-slate-500">
                {investigation.enrichment.event_count} evidence events ·{" "}
                {investigation.enrichment.related_alerts} alerts
              </span>
            </div>

            {(investigation.confidence?.breakdown || []).length > 0 && (
              <div className="space-y-2">
                {investigation.confidence.breakdown.map((f) => (
                  <div key={f.factor} className="flex items-center gap-3">
                    <span className="w-40 shrink-0 text-[11px] capitalize text-slate-400">{f.factor}</span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                        style={{ width: `${Math.max(0, Math.min(100, (f.score + (f.weight === 0 ? 1 : 0)) * 100))}%` }}
                      />
                    </div>
                    <span className="w-10 shrink-0 text-right font-mono text-[11px] text-slate-300">
                      {f.score.toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {(() => {
              const w = investigation.enrichment.six_w || {};
              return (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">Who</p>
                    <p className="mt-1 text-xs text-slate-300">{(w.who || []).join(", ") || "—"}</p>
                  </div>
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">What</p>
                    <p className="mt-1 text-xs text-slate-300">{(w.what || []).join(", ") || "—"}</p>
                  </div>
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">When</p>
                    <p className="mt-1 text-xs text-slate-300">
                      {w.when?.first ? new Date(w.when.first).toLocaleString() : "—"}
                      {w.when?.span_seconds ? ` · ${Math.round(w.when.span_seconds)}s span` : ""}
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">Where</p>
                    <p className="mt-1 text-xs text-slate-300">{(w.where || []).join(", ") || "—"}</p>
                  </div>
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">How</p>
                    <p className="mt-1 text-xs text-slate-300">{(w.how || []).join(" → ") || "—"}</p>
                  </div>
                  <div className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">Why</p>
                    <p className="mt-1 text-xs text-slate-300">
                      {w.why?.mitre_id ? `${w.why.mitre_id} ${w.why.mitre_name || ""}` : "—"}
                    </p>
                  </div>
                </div>
              );
            })()}

            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                ["Events", investigation.enrichment.event_count],
                ["Files", investigation.enrichment.file_count],
                ["Processes", investigation.enrichment.process_count],
                ["Network", investigation.enrichment.network_count],
                ["Registry", investigation.enrichment.registry_count],
              ].map(([label, value]) => (
                <div key={label} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4 text-center">
                  <p className="font-mono text-xl font-bold text-white">{value}</p>
                  <p className="mt-0.5 text-[11px] uppercase tracking-wider text-slate-500">{label}</p>
                </div>
              ))}
            </div>

            {investigation.enrichment.process_tree?.chain?.length > 0 && (
              <div>
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                  Process chain
                </p>
                <div className="space-y-1">
                  {investigation.enrichment.process_tree.chain.map((n, idx) => (
                    <div key={`${n.pid}-${idx}`} className="flex items-center gap-2 font-mono text-[11px]">
                      {idx > 0 && <span className="text-slate-600">└─</span>}
                      <span className="text-slate-500">#{n.pid}</span>
                      <span className="text-slate-200">{n.name || n.path || "?"}</span>
                      {n.user && <span className="text-slate-500">({n.user})</span>}
                    </div>
                  ))}
                </div>
                <p className="mt-1.5 text-[11px] text-slate-500">
                  {investigation.enrichment.process_tree.node_count} nodes ·{" "}
                  {Math.round((investigation.enrichment.process_tree.completeness || 0) * 100)}% lineage verified
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <ErrorBanner message={error} />}
    </div>
  );
}

export default function Incidents() {
  const [items, setItems] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    api
      .incidents()
      .then((res) => {
        setItems(res.items || []);
        if (!res.items?.some((i) => i.id === selectedId)) setSelectedId(null);
      })
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const selected = useMemo(
    () => items?.find((i) => i.id === selectedId) || null,
    [items, selectedId]
  );

  const filtered = useMemo(() => {
    if (!items) return [];
    const q = filter.toLowerCase();
    return items.filter(
      (i) =>
        !q ||
        i.title.toLowerCase().includes(q) ||
        i.ref.toLowerCase().includes(q) ||
        (i.host || "").toLowerCase().includes(q) ||
        (i.owner || "").toLowerCase().includes(q)
    );
  }, [items, filter]);

  return (
    <div className="space-y-6 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Incidents</h1>
        <p className="mt-1 text-sm text-slate-400">Security cases: group alerts, track ownership and response status</p>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-1">
          <CreateIncident onCreated={load} />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search incidents..."
            className={inputClass}
          />
          <div className="space-y-2">
            {items === null ? (
              <Loading label="Loading incidents" />
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] text-slate-500">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                </div>
                <p className="text-sm font-semibold text-slate-300">No incidents</p>
                <p className="mt-1 text-xs text-slate-500">Create one above to start a case</p>
              </div>
            ) : (
              filtered.map((inc) => (
                <IncidentCard
                  key={inc.id}
                  incident={inc}
                  selected={inc.id === selectedId}
                  onSelect={setSelectedId}
                />
              ))
            )}
          </div>
        </div>

        <div className="lg:col-span-2">
          {selected ? (
            <IncidentDetail
              key={selected.id}
              incident={selected}
              onChanged={load}
            />
          ) : (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] text-slate-500">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/></svg>
                </div>
                <p className="text-sm font-semibold text-slate-300">Select an incident</p>
                <p className="mt-1 text-xs text-slate-500">Choose a case on the left to view its detail, timeline and linked alerts</p>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-center pt-4"><p className="text-[11px] font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p></div>
    </div>
  );
}
