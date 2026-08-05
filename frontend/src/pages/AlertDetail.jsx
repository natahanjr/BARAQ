import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";

const MITRE_LINK = (id) => `https://attack.mitre.org/techniques/${id}/`;

const STATUSES = [
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "resolved", label: "Resolved" },
  { value: "dismissed", label: "Dismissed" },
];

const STATUS_ACTIVE = {
  open: "border-rose-500/50 bg-rose-500/20 text-rose-300",
  investigating: "border-amber-500/50 bg-amber-500/20 text-amber-300",
  resolved: "border-emerald-500/50 bg-emerald-500/20 text-emerald-300",
  dismissed: "border-slate-500/50 bg-slate-600/30 text-slate-300",
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

  const load = () => api.alert(id).then(setAlert).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, [id]);

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
            <SectionHeading>Status Management</SectionHeading>
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
