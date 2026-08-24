import { useEffect, useState } from "react";
import { useParams, Link } from "react-router";
import { api, isAdmin } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const MITRE_LINK = (id) => `https://attack.mitre.org/techniques/${id}/`;

const FEATURE_LABELS = {
  event_id: "Event ID",
  logon_type: "Logon type",
  sub_status: "Status code",
  source_host: "Source host",
  is_locked: "Locked out",
  hour: "Hour (0\u201324)",
  is_night: "Night hours",
  is_weekend: "Weekend",
  unusual_logon_type: "Unusual logon type",
  has_encoded: "Encoded cmdline",
  has_download: "Download signal",
  has_hidden: "Hidden flag",
  group_sid: "Group SID",
  script_len: "Script length",
  cmdline_len: "Cmdline length",
  has_remote: "Remote SID",
  ip_code: "IP code",
  connection_count: "Connections",
  distinct_ports: "Distinct ports",
  bytes_sent_mb: "Bytes sent (MB)",
  bytes_recv_mb: "Bytes recv (MB)",
  duration_h: "Duration (h)",
  send_rate: "Send rate",
  is_novel: "Novel host",
};

const formatFeature = (name) => FEATURE_LABELS[name] || name.replaceAll("_", " ");

const STATUSES = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "closed", label: "Closed" },
];

const STATUS_ACTIVE = {
  open: "border-rose-500/40 bg-rose-500/[0.12] text-rose-300 shadow-[0_0_12px_-2px_rgba(255,61,113,0.3)]",
  in_progress: "border-amber-500/40 bg-amber-500/[0.12] text-amber-300 shadow-[0_0_12px_-2px_rgba(251,191,36,0.3)]",
  contained: "border-violet-500/40 bg-violet-500/[0.12] text-violet-300 shadow-[0_0_12px_-2px_rgba(139,92,246,0.3)]",
  closed: "border-emerald-500/40 bg-emerald-500/[0.12] text-emerald-300 shadow-[0_0_12px_-2px_rgba(16,185,129,0.3)]",
};

function InfoRow({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/[0.04] py-3 last:border-0">
      <span className="text-[12px] font-medium text-slate-500">{label}</span>
      <span className="break-all text-right text-[13px] font-semibold text-slate-200">{value || "\u2014"}</span>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
      <span className="h-1 w-1 rounded-full bg-cyan-400" />
      {children}
    </h3>
  );
}

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState({});
  const [warned, setWarning] = useState({});
  const [intel, setIntel] = useState(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [marking, setMarking] = useState(null);
  const [explain, setExplain] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState("");
  const [verdict, setVerdict] = useState(null);
  const [verdictNote, setVerdictNote] = useState("");
  const [verdictSuppress, setVerdictSuppress] = useState(true);
  const [soarRuns, setSoarRuns] = useState(null);

  const load = () => api.alert(id).then(setAlert).catch((e) => setError(e.message));
  useEffect(() => {
    load();
    api.alertVerdict(id).then((v) => { if (v) { setVerdict(v); setVerdictNote(v.note || ""); } }).catch(() => {});
    api.automationRuns(10, id).then((r) => setSoarRuns(r?.runs || [])).catch(() => setSoarRuns([]));
  }, [id]);

  const submitVerdict = async (value) => {
    if (saving) return;
    setSaving(true); setError(""); setNotice("");
    try {
      await api.submitAlertVerdict(alert.id, { verdict: value, note: verdictNote, suppress: value === "expected_behavior" && verdictSuppress });
      const saved = await api.alertVerdict(alert.id);
      setVerdict(saved);
      setNotice(value === "expected_behavior" ? `Marked as expected behavior${verdictSuppress ? " and suppressed" : ""}. ML updated.` : value === "false_positive" ? "Marked false positive. ML dampened." : "Confirmed true positive. ML strengthened.");
      await load();
    } catch (e) { setError(e.message); } finally { setSaving(false); }
  };

  const loadIntel = (refresh = false) => {
    if (!alert) return; setIntelLoading(true);
    api.intelAlert(alert.id, refresh).then(setIntel).catch(() => setIntel(null)).finally(() => setIntelLoading(false));
  };
  useEffect(() => { if (alert) loadIntel(); }, [alert?.id]);

  const loadExplain = () => {
    if (!alert || explainLoading) return; setExplainLoading(true); setExplainError("");
    api.mlExplainAlert(alert.id).then((r) => setExplain(r.explanations || [])).catch((e) => setExplainError(e.message)).finally(() => setExplainLoading(false));
  };
  useEffect(() => { if (alert) { setExplain(null); setExplainError(""); loadExplain(); } }, [alert?.id]);

  if (error) return <ErrorBanner message={error} onRetry={load} />;
  if (!alert) return <Loading label="Loading alert" />;

  const changeStatus = async (status) => {
    if (status === alert.status || saving) return; setSaving(true); setError("");
    try { await api.setAlertStatus(alert.id, status); await load(); } catch (e) { setError(e.message); } finally { setSaving(false); }
  };

  const submitNote = async (e) => {
    e.preventDefault(); if (!note.trim() || saving) return; setSaving(true); setError("");
    try { await api.addAlertNote(alert.id, note.trim()); setNote(""); await load(); } catch (err) { setError(err.message); } finally { setSaving(false); }
  };

  const fixAlert = async () => {
    if (saving) return; setSaving(true); setError(""); setNotice("");
    try { const res = await api.fixAlert(alert.id); setNotice(`Fix \u2192 ${res.status}: ${res.detail || "done"}`); await load(); } catch (e) { setError(e.message); } finally { setSaving(false); }
  };

  const runSoar = async (action) => {
    if (warned[action]) return;
    if (!window.confirm(`Run "${action}" against this alert (host: ${alert.host || "?"})?`)) return;
    setWarning((prev) => ({ ...prev, [action]: true })); setRunning((prev) => ({ ...prev, [action]: true })); setError(""); setNotice("");
    try { const res = await api.takeAction(alert.id, action); const label = soarButtons.find((b) => b.key === action)?.label || action; setNotice(`${label} \u2192 ${res.status}: ${res.detail || res.target || "done"}`); await load(); } catch (e) { setError(e.message); } finally { setRunning((prev) => ({ ...prev, [action]: false })); }
  };

  const markMalicious = async (indicator) => {
    if (marking) return; if (!window.confirm(`Mark "${indicator}" as malicious?`)) return; setMarking(indicator); setError("");
    try { await api.intelMarkMalicious(indicator); await loadIntel(true); } catch (e) { setError(e.message); } finally { setMarking(null); }
  };

  const intelTone = { malicious: "border-rose-500/25 bg-rose-500/[0.06] text-rose-300", suspicious: "border-amber-500/25 bg-amber-500/[0.06] text-amber-300", benign: "border-emerald-500/25 bg-emerald-500/[0.06] text-emerald-300", unknown: "border-white/[0.06] bg-white/[0.02] text-slate-300" };
  const intelDot = { malicious: "bg-rose-400 shadow-[0_0_5px_rgba(251,113,133,0.5)]", suspicious: "bg-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.5)]", benign: "bg-emerald-400", unknown: "bg-slate-400" };

  const soarButtons = [
    { key: "isolate", label: "Isolate Host", tone: "border-rose-500/25 bg-rose-500/[0.06] text-rose-400 hover:bg-rose-500/[0.12] hover:shadow-[0_0_16px_-4px_rgba(255,61,113,0.25)]" },
    { key: "block_ip", label: "Block Source IP", tone: "border-amber-500/25 bg-amber-500/[0.06] text-amber-400 hover:bg-amber-500/[0.12] hover:shadow-[0_0_16px_-4px_rgba(251,191,36,0.25)]" },
    { key: "disable_account", label: "Disable Account", tone: "border-orange-500/25 bg-orange-500/[0.06] text-orange-400 hover:bg-orange-500/[0.12] hover:shadow-[0_0_16px_-4px_rgba(251,146,60,0.25)]" },
    { key: "kill_process", label: "Kill Process", tone: "border-white/[0.08] bg-white/[0.03] text-slate-300 hover:bg-white/[0.06]" },
    { key: "quarantine", label: "Quarantine File", tone: "border-white/[0.08] bg-white/[0.03] text-slate-300 hover:bg-white/[0.06]" },
  ];

  return (
    <div className="space-y-6 pb-16">
      {/* Breadcrumb */}
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <Link to="/alerts" className="font-medium text-cyan-400 transition-colors hover:text-cyan-300">
          &larr; All alerts
        </Link>
        <span className="text-slate-600">/</span>
        <Link to={`/investigation?alert=${alert.id}`} className="font-medium text-slate-400 transition-colors hover:text-cyan-300">
          Deep-dive investigation &rarr;
        </Link>
      </div>

      {/* Header */}
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">
                <span className="text-slate-500 font-mono text-[18px]">#{alert.id}</span>{" "}
                {alert.name}
              </h1>
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <RiskBadge level={alert.risk_level} score={alert.risk_score} />
            </div>
            <p className="mt-2.5 text-[13px] text-slate-400/80">
              {alert.mitre_name && <>{alert.mitre_name} &middot; </>}
              <span className="font-mono text-cyan-400/80">{alert.mitre_id}</span>
              {alert.mitre_tactic && <> &middot; {alert.mitre_tactic}</>}
            </p>
          </div>
        </div>
      </div>

      {/* Notice */}
      {notice && (
        <div
          className="animate-in slide-in-from-top-2 flex items-start gap-3 rounded-2xl border p-4"
          style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)" }}
        >
          <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs" style={{ background: "rgba(16,185,129,0.15)", color: "var(--success-text, #065f46)" }}>&#10003;</span>
          <span className="flex-1 text-sm" style={{ color: "var(--success-text, #065f46)" }}>{notice}</span>
          <button type="button" onClick={() => setNotice("")} className="transition-colors" style={{ color: "var(--success-text, #065f46)", opacity: 0.6 }}>&times;</button>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main content */}
        <div className="space-y-6 lg:col-span-2">
          {/* Description + Evidence */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Description</SectionLabel>
            <p className="text-[13px] leading-relaxed text-slate-300">{alert.description}</p>

            <div className="mt-6">
              <SectionLabel>Evidence</SectionLabel>
              <pre
                className="max-h-72 overflow-auto whitespace-pre-wrap rounded-xl border p-5 font-mono text-[13px] leading-relaxed shadow-inner"
                style={{ background: "#0f172a", borderColor: "rgba(255,255,255,0.04)", color: "#e2e8f0" }}
              >
                {alert.evidence}
              </pre>
            </div>
          </div>

          {/* Recommended Action */}
          <div className="rounded-2xl border border-emerald-500/15 bg-gradient-to-br from-emerald-500/[0.04] to-transparent p-6">
            <SectionLabel>Recommended Action</SectionLabel>
            <p className="text-[13px] leading-relaxed text-slate-300">{alert.recommendation}</p>
          </div>

          {/* Analyst Verdict */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Analyst Verdict</SectionLabel>
            <p className="mb-4 text-[12px] leading-relaxed text-slate-400/80">
              Is this detection real, noise, or expected behaviour? Verdicts feed the ML feedback loop.
            </p>
            <div className="flex flex-wrap gap-2">
              {[
                { key: "true_positive", label: "True Positive", active: "border-rose-500/40 bg-rose-500/[0.12] text-rose-300", idle: "border-rose-500/20 bg-rose-500/[0.05] text-rose-400 hover:bg-rose-500/[0.1]" },
                { key: "false_positive", label: "False Positive", active: "border-amber-500/40 bg-amber-500/[0.12] text-amber-300", idle: "border-amber-500/20 bg-amber-500/[0.05] text-amber-400 hover:bg-amber-500/[0.1]" },
                { key: "expected_behavior", label: "Expected Behavior", active: "border-sky-500/40 bg-sky-500/[0.12] text-sky-300", idle: "border-sky-500/20 bg-sky-500/[0.05] text-sky-400 hover:bg-sky-500/[0.1]" },
              ].map((v) => (
                <button
                  key={v.key}
                  type="button"
                  disabled={saving}
                  onClick={() => submitVerdict(v.key)}
                  className={`rounded-xl border px-4 py-2 text-[12px] font-semibold transition-all disabled:opacity-40 ${
                    verdict?.verdict === v.key ? v.active : v.idle
                  }`}
                >
                  {v.label}
                </button>
              ))}
            </div>
            <input
              type="text"
              value={verdictNote}
              onChange={(e) => setVerdictNote(e.target.value)}
              placeholder="Why? (optional)"
              className="mt-3 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-2.5 text-[12px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            />
            <label className="mt-3 flex cursor-pointer items-center gap-2.5 text-[12px] text-slate-400">
              <input type="checkbox" checked={verdictSuppress} onChange={(e) => setVerdictSuppress(e.target.checked)} className="h-[14px] w-[14px] rounded-[3px] accent-cyan-500" />
              Suppress this rule on {alert.host || "this host"}
            </label>
            {verdict && (
              <p className="mt-3 text-xs text-slate-500/70">
                Last verdict: <span className="font-medium text-slate-300">{verdict.verdict}</span>
                {verdict.created_by && <> by {verdict.created_by}</>} &middot; {new Date(verdict.created_at).toLocaleString()}
              </p>
            )}
          </div>

          {/* Evidence Events */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <div className="mb-5 flex items-center justify-between">
              <SectionLabel>Events ({alert.events?.length || 0})</SectionLabel>
              {alert.event_count && (
                <span className="text-xs text-slate-500/70">from {alert.event_count} events</span>
              )}
            </div>
            {alert.events && alert.events.length > 0 ? (
              <div className="max-h-96 space-y-2 overflow-y-auto">
                {alert.events.map((ev) => (
                  <div key={ev.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4 transition-all hover:border-white/[0.08]">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <span className="rounded-md bg-cyan-500/10 px-2.5 py-1 font-mono text-xs font-semibold text-cyan-400 ring-1 ring-cyan-500/15">
                        Event {ev.event_id}
                      </span>
                      <span className="rounded-md bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-slate-400 ring-1 ring-white/[0.06]">
                        {ev.category}
                      </span>
                      {ev.is_anomaly && (
                        <span className="rounded-md bg-violet-500/10 px-2.5 py-1 text-xs font-semibold text-violet-400 ring-1 ring-violet-500/15">
                          ML anomaly
                        </span>
                      )}
                      <span className="ml-auto text-xs font-medium text-slate-500/70">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "\u2014"}
                      </span>
                    </div>
                    <p className="text-[12px] leading-relaxed text-slate-300">{ev.message}</p>
                    {ev.ml_score && (
                      <p className="mt-2 text-xs font-medium text-violet-400">
                        ML score: {ev.ml_score.toFixed(3)}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center py-10 text-center">
                <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-white/[0.03] ring-1 ring-white/[0.06]">
                  <svg className="h-6 w-6 text-slate-500/40" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
                  </svg>
                </div>
                <p className="text-[13px] font-medium text-slate-400">No evidence events</p>
                <p className="mt-1 text-[12px] text-slate-500/70">No linked events recorded for this alert</p>
              </div>
            )}
          </div>

          {/* ML Explanation */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <div className="mb-4 flex items-center justify-between">
              <SectionLabel>ML Explanation</SectionLabel>
              <div className="flex items-center gap-2">
                {explainError && <span className="text-xs text-amber-400">{explainError}</span>}
                <button type="button" onClick={loadExplain} disabled={explainLoading}
                  className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-white/[0.06] disabled:opacity-50">
                  {explainLoading ? "Computing..." : "\u21BB Recompute"}
                </button>
              </div>
            </div>
            <p className="mb-4 text-[12px] leading-relaxed text-slate-400/70">
              SHAP / LIME feature attribution \u2014 shows which signals pulled the anomaly score up or down.
            </p>
            {explain ? (
              explain.length > 0 ? (
                <div className="space-y-3">
                  {explain.map((ex, i) => (
                    <div key={i} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                      <div className="mb-3 flex flex-wrap items-center gap-2">
                        <span className="rounded-md bg-violet-500/10 px-2.5 py-1 font-mono text-xs font-semibold text-violet-400 ring-1 ring-violet-500/15">
                          Event {ex.event?._event_id}
                        </span>
                        <span className="rounded-md bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-slate-400">{ex.method}</span>
                        <span className="rounded-md bg-white/[0.04] px-2.5 py-1 text-xs font-medium text-slate-400">{ex.behavior}</span>
                        <span className={`ml-auto rounded-md px-2.5 py-1 text-xs font-bold ${ex.flagged ? "bg-rose-500/10 text-rose-400 ring-1 ring-rose-500/20" : "bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/20"}`}>
                          {ex.score?.toFixed(3)}
                        </span>
                      </div>
                      {(ex.features || []).filter((f) => Math.abs(f.contribution) > 0.001).slice(0, 5).map((f) => (
                        <div key={f.name} className="flex items-center gap-3 py-1">
                          <span className="w-36 shrink-0 truncate font-mono text-xs text-slate-400">{formatFeature(f.name)}</span>
                          <span className="flex h-[5px] flex-1 overflow-hidden rounded-full bg-white/[0.04]">
                            <span className={`h-full rounded-full ${f.contribution > 0 ? "bg-rose-500" : "bg-cyan-500"}`}
                              style={{ width: `${Math.min(100, Math.abs(f.contribution) * 220)}%` }} />
                          </span>
                          <span className={`w-20 shrink-0 text-right font-mono text-xs ${f.contribution > 0 ? "text-rose-400" : "text-cyan-400"}`}>
                            {f.contribution > 0 ? "+" : ""}{f.contribution?.toFixed(3)}
                          </span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="py-6 text-center text-[13px] text-slate-500">No explanations available</p>
              )
            ) : (
              <Loading label="Computing explanations" />
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Alert Details */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Alert Details</SectionLabel>
            <div className="space-y-0">
              <InfoRow label="Rule" value={alert.rule} />
              <InfoRow label="MITRE ID" value={alert.mitre_id} />
              <InfoRow label="Risk Score" value={alert.risk_score?.toFixed(2)} />
              <InfoRow label="Risk Level" value={alert.risk_level} />
              <InfoRow label="Detection" value={alert.detection_method} />
              <InfoRow label="Confidence" value={alert.confidence?.toFixed(2)} />
              <InfoRow label="Created" value={alert.created_at ? new Date(alert.created_at).toLocaleString() : "\u2014"} />
            </div>

            {alert.risk_composition && (
              <div className="mt-5 rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-cyan-400">Risk explanation</p>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
                  {alert.risk_composition.method === "hybrid" ? "Hybrid: 60% rule signal + 40% ML anomaly" : "Rule-only: no ML anomaly signal available"}
                </p>
                <div className="mt-3 flex h-[5px] overflow-hidden rounded-full bg-white/[0.04]">
                  <div className="bg-cyan-500 rounded-l-full" style={{ width: `${alert.risk_composition.rule_share}%` }} />
                  <div className="bg-violet-500 rounded-r-full" style={{ width: `${alert.risk_composition.ml_share}%` }} />
                </div>
                <div className="mt-2 flex justify-between font-mono text-xs text-slate-500/70">
                  <span>rule {alert.risk_composition.rule_share?.toFixed(1)}</span>
                  <span>ML {alert.risk_composition.ml_share?.toFixed(1)}</span>
                  <span>base {alert.risk_composition.base?.toFixed(1)} &times; {alert.context_modifier ?? 1.0}</span>
                </div>
                {(alert.risk_adjustments || []).length > 0 && (
                  <ul className="mt-3 space-y-1.5 border-t border-white/[0.04] pt-3">
                    {alert.risk_adjustments.map((a, idx) => (
                      <li key={idx} className="flex items-center gap-2 text-xs">
                        <span className={`font-mono font-bold ${a.delta > 0 ? "text-red-300" : a.delta < 0 ? "text-emerald-300" : "text-slate-400"}`}>
                          {a.delta > 0 ? "+" : ""}{a.delta}
                        </span>
                        <span className="text-slate-300">{a.signal}</span>
                        <span className="ml-auto truncate text-xs text-slate-500/60">{a.note}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {alert.mitre_id && (
              <a href={MITRE_LINK(alert.mitre_id)} target="_blank" rel="noreferrer"
                className="mt-5 block rounded-xl border border-cyan-500/20 bg-cyan-500/[0.06] px-4 py-2.5 text-center text-[12px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.12] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]">
                View {alert.mitre_id} on MITRE ATT&CK &rarr;
              </a>
            )}
          </div>

          {/* SOAR Actions */}
          {isAdmin() && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <SectionLabel>SOAR Actions</SectionLabel>
              <div className="grid grid-cols-1 gap-2">
                {soarButtons.map((b) => (
                  <button key={b.key} type="button" onClick={() => runSoar(b.key)}
                    disabled={running[b.key] || alert.status === "closed"}
                    className={`rounded-xl border px-4 py-2.5 text-[12px] font-semibold transition-all disabled:opacity-40 ${b.tone} ${running[b.key] ? "animate-pulse" : ""}`}>
                    {running[b.key] ? "Running..." : b.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Automation Runs */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Automation Runs</SectionLabel>
            {soarRuns === null ? (
              <Loading label="Loading playbook history" />
            ) : soarRuns.length === 0 ? (
              <p className="text-[12px] text-slate-500/70">No playbook runs recorded yet.</p>
            ) : (
              <ul className="space-y-2">
                {soarRuns.map((r) => (
                  <li key={r.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[12px] font-semibold text-slate-200">{r.playbook_name}</span>
                      <span className={`rounded-md px-2 py-0.5 text-xs font-bold ${r.status === "completed" ? "bg-emerald-500/10 text-emerald-300" : r.status === "partial" ? "bg-amber-500/10 text-amber-300" : "bg-rose-500/10 text-rose-300"}`}>
                        {r.status}
                      </span>
                      <span className="ml-auto text-xs text-slate-500/60">
                        {r.created_at ? new Date(r.created_at).toLocaleString() : ""}
                      </span>
                    </div>
                    {(r.results || []).length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {r.results.map((res, i) => (
                          <span key={i} title={res.detail}
                            className={`rounded-md px-2 py-0.5 font-mono text-xs ${res.status === "success" ? "bg-emerald-500/[0.06] text-emerald-300" : res.status === "failed" ? "bg-rose-500/[0.06] text-rose-300" : "bg-white/[0.03] text-slate-400"}`}>
                            {res.action}
                          </span>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Threat Intelligence */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <div className="mb-4 flex items-center justify-between">
              <SectionLabel>Threat Intelligence</SectionLabel>
              <button type="button" onClick={() => loadIntel(true)} disabled={intelLoading}
                className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-white/[0.06] disabled:opacity-50">
                {intelLoading ? "Checking..." : "\u21BB Refresh"}
              </button>
            </div>
            {alert?.intel_checked_at && (
              <div className="mb-4 rounded-xl border border-emerald-500/15 bg-emerald-500/[0.04] p-3.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">Detection-time intel</span>
                  <span className="text-xs text-slate-300">
                    {(alert.intel_hits || 0) > 0 ? `${alert.intel_hits} known-bad indicator(s)` : "All clean at detection"}
                  </span>
                  <span className="ml-auto text-xs text-slate-500/60">{new Date(alert.intel_checked_at).toLocaleString()}</span>
                </div>
              </div>
            )}
            {intel ? (
              <div className="space-y-3">
                {intel.actors && intel.actors.length > 0 && (
                  <div className="rounded-xl border border-rose-500/15 bg-rose-500/[0.04] p-3.5">
                    <p className="text-xs font-bold uppercase tracking-wider text-rose-400">Attributed actors</p>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {intel.actors.map((act) => (
                        <span key={act.name} title={act.items?.join(", ")}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/20 bg-white/[0.02] px-2.5 py-1 text-xs font-semibold text-rose-300">
                          <span className={`h-[5px] w-[5px] rounded-full ${intelDot[act.category] || intelDot.unknown}`} />
                          {act.name}
                          <span className="font-mono text-[9px] text-slate-500">{act.risk_score}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {intel.items.length > 0 ? (
                  <ul className="space-y-2">
                    {intel.items.map((it) => {
                      const attributed = (intel.actors || []).find((a) => (a.items || []).includes(it.indicator));
                      return (
                        <li key={it.indicator} className={`rounded-xl border p-3.5 ${intelTone[it.category] || intelTone.unknown}`}>
                          <div className="flex items-start justify-between gap-3">
                            <div className="break-all font-mono text-[12px] font-semibold text-slate-200">{it.indicator}</div>
                            <div className="flex shrink-0 items-center gap-1.5">
                              {attributed && (
                                <span className="inline-flex items-center gap-1 rounded-md bg-white/[0.04] px-2 py-0.5 text-xs font-semibold text-rose-300">
                                  {attributed.name}
                                </span>
                              )}
                              <span className="flex items-center gap-1 rounded-md bg-white/[0.04] px-2 py-0.5 text-xs font-bold uppercase">
                                <span className={`h-[5px] w-[5px] rounded-full ${intelDot[it.category] || intelDot.unknown}`} />
                                {it.category}
                              </span>
                            </div>
                          </div>
                          <p className="mt-1.5 text-xs leading-relaxed text-slate-400/80">{it.label}</p>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <span className="text-xs font-medium text-slate-400">{it.kind}</span>
                            <span className="text-xs text-slate-500/60">conf {(it.confidence * 100).toFixed(0)}%</span>
                            {it.sources?.length > 0 && <span className="text-xs text-slate-500/60">{it.sources.join(" \u00B7 ")}</span>}
                            {it.category !== "malicious" && (
                              <button type="button" onClick={() => markMalicious(it.indicator)} disabled={marking === it.indicator}
                                className={`ml-auto rounded-lg border px-2.5 py-1 text-xs font-semibold transition-all ${it.category === "suspicious" ? "border-rose-500/30 text-rose-400 hover:bg-rose-500/10" : "border-white/[0.08] text-slate-400 hover:bg-white/[0.04]"} disabled:opacity-50`}>
                                {marking === it.indicator ? "Marking..." : "Mark malicious"}
                              </button>
                            )}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p className="py-4 text-center text-[12px] text-slate-500/70">No indicators found</p>
                )}
              </div>
            ) : (
              <p className="py-4 text-center text-[12px] text-slate-500/70">No enrichment available</p>
            )}
          </div>

          {/* Status Management */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Status Management</SectionLabel>
            {isAdmin() && (
              <button type="button" onClick={fixAlert} disabled={saving || alert.status === "closed"}
                className="mb-4 w-full rounded-xl border border-emerald-500/25 bg-emerald-500/[0.08] px-4 py-3 text-[13px] font-bold text-emerald-400 transition-all hover:bg-emerald-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(16,185,129,0.3)] disabled:opacity-40">
                {alert.status === "closed" ? "\u2713 Alert Fixed" : "\u2713 Fix Alert (Restore Score)"}
              </button>
            )}
            <div className="grid grid-cols-2 gap-2">
              {STATUSES.map((s) => (
                <button key={s.value} type="button" onClick={() => changeStatus(s.value)} disabled={saving}
                  className={`rounded-xl border px-3 py-2.5 text-[12px] font-semibold capitalize transition-all disabled:opacity-50 ${
                    alert.status === s.value ? STATUS_ACTIVE[s.value] : "border-white/[0.06] bg-white/[0.02] text-slate-400 hover:bg-white/[0.04] hover:text-slate-200"
                  }`}>
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          {/* Analyst Notes */}
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <SectionLabel>Analyst Notes</SectionLabel>
            <form onSubmit={submitNote} className="space-y-3">
              <textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add investigation notes..." rows={3}
                className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10" />
              <button type="submit" disabled={saving || !note.trim()}
                className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50">
                {saving ? "Saving..." : "Add Note"}
              </button>
            </form>
          </div>

          {alert.notes && alert.notes.length > 0 && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <SectionLabel>Notes ({alert.notes.length})</SectionLabel>
              <div className="space-y-2">
                {alert.notes.map((n) => (
                  <div key={n.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                    <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-slate-300">{n.note}</p>
                    <p className="mt-2 text-xs text-slate-500/60">
                      {n.created_at ? new Date(n.created_at).toLocaleString() : "\u2014"}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="flex justify-center pt-4">
        <p className="text-xs font-medium text-slate-500/50">BARAQ &middot; Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
