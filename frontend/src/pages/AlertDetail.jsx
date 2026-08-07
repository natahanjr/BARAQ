import { useEffect, useState } from "react";
import { useParams, Link } from "react-router";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";

const MITRE_LINK = (id) => `https://attack.mitre.org/techniques/${id}/`;

const FEATURE_LABELS = {
  event_id: "Event ID",
  logon_type: "Logon type",
  sub_status: "Status code",
  source_host: "Source host",
  is_locked: "Locked out",
  hour: "Hour (0–24)",
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
  open: "border-rose-500/50 bg-rose-500/20 text-rose-300",
  in_progress: "border-amber-500/50 bg-amber-500/20 text-amber-300",
  contained: "border-violet-500/50 bg-violet-500/20 text-violet-300",
  closed: "border-emerald-500/50 bg-emerald-500/20 text-emerald-300",
};

function InfoRow({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-700/40 py-2.5 text-sm last:border-0">
      <span className="text-slate-500">{label}</span>
      <span className="break-all text-right font-medium text-slate-300">{value || "—"}</span>
    </div>
  );
}

function SectionHeading({ children }) {
  return <h3 className="mb-4 text-base font-semibold text-white">{children}</h3>;
}

export default function AlertDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState({});
  const [warned, setWarning] = useState({});
  const [intel, setIntel] = useState(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [marking, setMarking] = useState(null);
  const [explain, setExplain] = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState("");

  const load = () => api.alert(id).then(setAlert).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, [id]);

  const loadIntel = (refresh = false) => {
    if (!alert) return;
    setIntelLoading(true);
    api
      .intelAlert(alert.id, refresh)
      .then(setIntel)
      .catch(() => {
        /* non-fatal, panel hides */
        setIntel(null);
      })
      .finally(() => setIntelLoading(false));
  };
  useEffect(() => {
    if (!alert) return;
    loadIntel();
  }, [alert?.id]);

  const loadExplain = () => {
    if (!alert || explainLoading) return;
    setExplainLoading(true);
    setExplainError("");
    api
      .mlExplainAlert(alert.id)
      .then((r) => setExplain(r.explanations || []))
      .catch((e) => setExplainError(e.message))
      .finally(() => setExplainLoading(false));
  };
  useEffect(() => {
    if (!alert) return;
    setExplain(null);
    setExplainError("");
    loadExplain();
  }, [alert?.id]);

  if (error)
    return <ErrorBanner message={error} onRetry={load} />;
  if (!alert) return <Loading label="Loading alert" />;

  const changeStatus = async (status) => {
    if (status === alert.status || saving) return;
    setSaving(true);
    setError("");
    try {
      await api.setAlertStatus(alert.id, status);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const submitNote = async (e) => {
    e.preventDefault();
    if (!note.trim() || saving) return;
    setSaving(true);
    setError("");
    try {
      await api.addAlertNote(alert.id, note.trim());
      setNote("");
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const fixAlert = async () => {
    if (saving) return;
    setSaving(true);
    setError("");
    try {
      await api.fixAlert(alert.id);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const runSoar = async (action) => {
    if (warned[action]) return;
    if (!window.confirm(`Run SOAR action "${action}" against this alert (host: ${alert.host || "?"})?`)) return;
    setWarning((prev) => ({ ...prev, [action]: true }));
    setRunning((prev) => ({ ...prev, [action]: true }));
    setError("");
    try {
      await api.takeAction(alert.id, action);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning((prev) => ({ ...prev, [action]: false }));
    }
  };

  // ---- Threat intelligence enrichment ----
  const markMalicious = async (indicator) => {
    if (marking) return;
    if (!window.confirm(`Mark "${indicator}" as malicious? This overrides its reputation for all future lookups.`)) return;
    setMarking(indicator);
    setError("");
    try {
      await api.intelMarkMalicious(indicator);
      await loadIntel(true);
    } catch (e) {
      setError(e.message);
    } finally {
      setMarking(null);
    }
  };

  const intelTone = {
    malicious: "border-rose-500/40 bg-rose-500/10 text-rose-300",
    suspicious: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    benign: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    unknown: "border-slate-600 bg-slate-800/60 text-slate-300",
  };

  const intelDot = {
    malicious: "bg-rose-500",
    suspicious: "bg-amber-500",
    benign: "bg-emerald-500",
    unknown: "bg-slate-500",
  };

  // ---- ML explainability ----
  const soarButtons = [
    { key: "isolate", label: "Isolate Host", tone: "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20" },
    { key: "block_ip", label: "Block Source IP", tone: "border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20" },
    { key: "disable_account", label: "Disable Account", tone: "border-orange-500/40 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20" },
    { key: "kill_process", label: "Kill Process", tone: "border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700" },
    { key: "quarantine", label: "Quarantine File", tone: "border-slate-600 bg-slate-800 text-slate-300 hover:bg-slate-700" },
  ];

  return (
    <div className="space-y-6 pb-12">
      <div>
        <Link to="/alerts" className="text-sm font-medium text-cyan-400 hover:text-cyan-300">
          ← All alerts
        </Link>
        <div className="mt-3 flex flex-wrap items-center gap-2.5">
          <h2 className="text-xl font-bold tracking-tight text-white sm:text-2xl">
            #{alert.id} {alert.name}
          </h2>
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          <RiskBadge level={alert.risk_level} score={alert.risk_score} />
        </div>
        <p className="mt-2 text-sm text-slate-400">
          {alert.mitre_name && <>{alert.mitre_name} · </>}
          <span className="font-mono text-cyan-400">{alert.mitre_id}</span>
          {alert.mitre_tactic && <> · {alert.mitre_tactic}</>}
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main content */}
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <SectionHeading>Description</SectionHeading>
            <p className="text-sm leading-relaxed text-slate-300">{alert.description}</p>

            <SectionHeading>Evidence</SectionHeading>
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-700/50 bg-slate-950/70 p-4 font-mono text-xs leading-relaxed text-slate-300">
              {alert.evidence}
            </pre>
          </Card>

          <Card tone="emerald">
            <SectionHeading>Recommended Action</SectionHeading>
            <p className="text-sm leading-relaxed text-slate-300">{alert.recommendation}</p>
          </Card>

          <Card>
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-base font-semibold text-white">
                Evidence Events ({alert.events?.length || 0})
              </h3>
              {alert.event_count ? (
                <span className="text-xs text-slate-500">correlated from {alert.event_count} events</span>
              ) : null}
            </div>
            {alert.events && alert.events.length > 0 ? (
              <div className="max-h-96 space-y-2 overflow-y-auto">
                {alert.events.map((ev) => (
                  <div
                    key={ev.id}
                    className="rounded-lg border border-slate-700/50 bg-slate-800/30 p-3"
                  >
                    <div className="mb-1.5 flex flex-wrap items-center gap-2">
                      <span className="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-cyan-400">
                        Event {ev.event_id}
                      </span>
                      <span className="rounded bg-slate-700/50 px-2 py-0.5 text-[10px] text-slate-300">
                        {ev.category}
                      </span>
                      {ev.is_anomaly && (
                        <span className="rounded bg-violet-500/15 px-2 py-0.5 text-[10px] font-semibold text-violet-400">
                          ML anomaly
                        </span>
                      )}
                      <span className="ml-auto text-[11px] text-slate-500">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—"}
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed text-slate-300">{ev.message}</p>
                    {ev.ml_score && (
                      <p className="mt-1.5 text-[11px] text-violet-400">
                        ML anomaly score: {ev.ml_score.toFixed(3)}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No evidence events" subtitle="No linked events recorded for this alert" />
            )}
          </Card>

          <Card>
            <div className="mb-3 flex items-center justify-between">
              <SectionHeading>ML Explanation</SectionHeading>
              <div className="flex items-center gap-2">
                {explainError && (
                  <span className="text-[11px] text-amber-400">{explainError}</span>
                )}
                <button
                  type="button"
                  onClick={loadExplain}
                  disabled={explainLoading}
                  className="rounded-lg border border-slate-700 bg-slate-800/60 px-2.5 py-1 text-[11px] font-semibold text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-50"
                >
                  {explainLoading ? "Computing..." : "↻ Recompute"}
                </button>
              </div>
            </div>
            <p className="mb-3 text-xs leading-relaxed text-slate-400">
              SHAP / LIME feature attribution for each linked evidence event — shows which
              signals pulled the anomaly score up or down.
            </p>
            {explain ? (
              explain.length > 0 ? (
                <div className="space-y-3">
                  {explain.map((ex, i) => (
                    <div key={i} className="rounded-lg border border-slate-700/50 bg-slate-800/30 p-3">
                      <div className="mb-2 flex flex-wrap items-center gap-2">
                        <span className="rounded bg-violet-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-violet-400">
                          Event {ex.event?._event_id}
                        </span>
                        <span className="rounded bg-slate-700/50 px-2 py-0.5 text-[10px] text-slate-300">
                          {ex.method}
                        </span>
                        <span className="rounded bg-slate-700/50 px-2 py-0.5 text-[10px] text-slate-300">
                          {ex.behavior}
                        </span>
                        <span
                          className={`ml-auto rounded px-2 py-0.5 text-[10px] font-bold ${
                            ex.flagged
                              ? "bg-rose-500/15 text-rose-400"
                              : "bg-emerald-500/15 text-emerald-400"
                          }`}
                        >
                          score {ex.score?.toFixed(3)}
                        </span>
                      </div>
                      {(ex.features || [])
                        .filter((f) => Math.abs(f.contribution) > 0.001)
                        .slice(0, 5)
                        .map((f) => (
                          <div key={f.name} className="flex items-center gap-2 py-0.5">
                            <span className="w-36 shrink-0 truncate font-mono text-[11px] text-slate-400">
                              {formatFeature(f.name)}
                            </span>
                            <span className="flex h-1.5 flex-1 overflow-hidden rounded bg-slate-700/60">
                              <span
                                className={`h-full ${
                                  f.contribution > 0 ? "bg-rose-500" : "bg-cyan-500"
                                }`}
                                style={{
                                  width: `${Math.min(100, Math.abs(f.contribution) * 220)}%`,
                                }}
                              />
                            </span>
                            <span
                              className={`w-20 shrink-0 text-right font-mono text-[11px] ${
                                f.contribution > 0 ? "text-rose-400" : "text-cyan-400"
                              }`}
                            >
                              {f.contribution > 0 ? "+" : ""}
                              {f.contribution?.toFixed(3)}
                            </span>
                          </div>
                        ))}
                    </div>
                    ))}
                </div>
              ) : (
                <EmptyState title="No explanations" subtitle="No linked events to explain for this alert" />
              )
            ) : (
              <Loading label="Computing explanations" />
            )}
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <Card>
            <SectionHeading>Alert Details</SectionHeading>
            <div className="space-y-1">
              <InfoRow label="Rule" value={alert.rule} />
              <InfoRow label="MITRE ID" value={alert.mitre_id} />
              <InfoRow label="Risk Score" value={alert.risk_score?.toFixed(2)} />
              <InfoRow label="Risk Level" value={alert.risk_level} />
              <InfoRow label="Detection" value={alert.detection_method} />
              <InfoRow label="Confidence" value={alert.confidence?.toFixed(2)} />
              <InfoRow
                label="Created"
                value={alert.created_at ? new Date(alert.created_at).toLocaleString() : "—"}
              />
            </div>

            {alert.mitre_id && (
              <a
                href={MITRE_LINK(alert.mitre_id)}
                target="_blank"
                rel="noreferrer"
                className="mt-5 block rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2.5 text-center text-xs font-semibold text-cyan-400 transition-colors hover:bg-cyan-500/20"
              >
                View {alert.mitre_id} on MITRE ATT&CK →
              </a>
            )}
          </Card>

          <Card>
            <SectionHeading>SOAR Actions</SectionHeading>
            <div className="grid grid-cols-1 gap-2">
              {soarButtons.map((b) => (
                <button
                  key={b.key}
                  type="button"
                  onClick={() => runSoar(b.key)}
                  disabled={running[b.key] || alert.status === "closed"}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold transition-all disabled:opacity-40 ${b.tone} ${
                    running[b.key] ? "animate-pulse" : ""
                  }`}
                >
                  {running[b.key] ? "Running..." : b.label}
                </button>
              ))}
            </div>
          </Card>

          <Card>
            <div className="mb-3 flex items-center justify-between">
              <SectionHeading>Threat Intelligence</SectionHeading>
              <button
                type="button"
                onClick={() => loadIntel(true)}
                disabled={intelLoading}
                className="rounded-lg border border-slate-700 bg-slate-800/60 px-2.5 py-1 text-[11px] font-semibold text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-50"
              >
                {intelLoading ? "Checking..." : "↻ Refresh"}
              </button>
            </div>
            {intel ? (
              intel.items.length > 0 ? (
                <ul className="space-y-2">
                  {intel.items.map((it) => (
                    <li
                      key={it.indicator}
                      className={`rounded-lg border p-3 ${intelTone[it.category] || intelTone.unknown}`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="break-all font-mono text-xs font-semibold text-slate-200">
                          {it.indicator}
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <span className="flex items-center gap-1 rounded bg-black/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide">
                            <span className={`h-1.5 w-1.5 rounded-full ${intelDot[it.category] || intelDot.unknown}`} />
                            {it.category}
                          </span>
                        </div>
                      </div>
                      <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                        {it.label}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-medium text-slate-400">
                          {it.kind}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          conf {(it.confidence * 100).toFixed(0)}%
                        </span>
                        {it.sources && it.sources.length > 0 && (
                          <span className="text-[10px] text-slate-500">
                            {it.sources.join(" · ")}
                          </span>
                        )}
                        {it.category !== "malicious" && (
                          <button
                            type="button"
                            onClick={() => markMalicious(it.indicator)}
                            disabled={marking === it.indicator}
                            className={`ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold transition-colors ${
                              it.category === "suspicious"
                                ? "border-rose-500/50 text-rose-400 hover:bg-rose-500/20"
                                : "border-slate-600 text-slate-400 hover:bg-slate-700"
                            } disabled:opacity-50`}
                          >
                            {marking === it.indicator ? "Marking..." : "⚠ Mark malicious"}
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No indicators" subtitle="No IPs, domains or hashes found in this alert's evidence" />
              )
            ) : (
              <EmptyState title="Not enriched" subtitle="No threat-intel enrichment available" />
            )}
          </Card>

          <Card>
            <SectionHeading>Status Management</SectionHeading>
            <button
              type="button"
              onClick={fixAlert}
              disabled={saving || alert.status === "closed"}
              className="mb-4 w-full rounded-lg bg-gradient-to-r from-emerald-600 to-emerald-500 px-4 py-2.5 text-sm font-bold text-white transition-all hover:from-emerald-500 hover:to-emerald-400 disabled:opacity-40"
            >
              {alert.status === "closed"
                ? "✓ Alert Fixed — Security Score Restored"
                : "✓ Fix Alert (Restore Score to 100)"}
            </button>
            <div className="grid grid-cols-2 gap-2">
              {STATUSES.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => changeStatus(s.value)}
                  disabled={saving}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold capitalize transition-all disabled:opacity-50 ${
                    alert.status === s.value
                      ? STATUS_ACTIVE[s.value]
                      : "border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700"
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </Card>

          <Card>
            <SectionHeading>Analyst Notes</SectionHeading>
            <form onSubmit={submitNote} className="space-y-3">
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add investigation notes..."
                rows={3}
                className="w-full rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
              />
              <button
                type="submit"
                disabled={saving || !note.trim()}
                className="w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-2 text-sm font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
              >
                {saving ? "Saving..." : "Add Note"}
              </button>
            </form>
          </Card>

          {alert.notes && alert.notes.length > 0 && (
            <Card>
              <SectionHeading>Notes ({alert.notes.length})</SectionHeading>
              <div className="space-y-2">
                {alert.notes.map((n) => (
                  <div
                    key={n.id}
                    className="rounded-lg border border-slate-700/50 bg-slate-800/40 p-3"
                  >
                    <p className="whitespace-pre-wrap text-xs leading-relaxed text-slate-300">
                      {n.note}
                    </p>
                    <p className="mt-2 text-[11px] text-slate-500">
                      {n.created_at ? new Date(n.created_at).toLocaleString() : "—"}
                    </p>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
