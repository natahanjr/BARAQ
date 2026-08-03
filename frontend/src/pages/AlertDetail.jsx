import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading } from "../components/Feedback.jsx";

const MITRE_LINK = (id) => `https://attack.mitre.org/techniques/${id}/`;

function InfoRow({ label, value }) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-800/60 py-2 text-sm last:border-0">
      <span className="text-slate-500">{label}</span>
      <span className="text-right font-medium text-slate-300">{value || "—"}</span>
    </div>
  );
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

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!alert) return <Loading label="Loading alert" />;

  const changeStatus = async (status) => {
    setSaving(true);
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
    if (!note.trim()) return;
    setSaving(true);
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Link to="/alerts" className="text-sm text-cyan-400 hover:underline">← All alerts</Link>
        <h2 className="text-lg font-semibold text-slate-100">#{alert.id} {alert.name}</h2>
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        <RiskBadge level={alert.risk_level} score={alert.risk_score} />
        <span className="font-mono text-xs text-slate-500">rule: {alert.rule}</span>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Description</h3>
            <p className="text-sm text-slate-400">{alert.description}</p>
            <h3 className="mb-2 mt-4 text-sm font-semibold text-slate-300">Evidence</h3>
            <pre className="whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950/70 p-3 font-mono text-xs leading-relaxed text-slate-300">
              {alert.evidence}
            </pre>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Recommended action</h3>
            <p className="text-sm text-slate-400">{alert.recommendation}</p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Evidence events ({alert.events.length})</h3>
            <div className="max-h-80 space-y-2 overflow-y-auto">
              {alert.events.map((ev) => (
                <div key={ev.id} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                    <span className="font-mono text-cyan-400">Event {ev.event_id}</span>
                    <span>{ev.category}</span>
                    <span>user={ev.user}</span>
                    <span className="ml-auto font-mono">{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—"}</span>
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-400" title={ev.message}>{ev.message}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">Analyst notes</h3>
            <div className="space-y-2">
              {(alert.notes || []).map((n) => (
                <div key={n.id} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
                  <p className="text-xs text-slate-500">{new Date(n.created_at).toLocaleString()}</p>
                  <p className="mt-1 text-sm text-slate-300">{n.note}</p>
                </div>
              ))}
              {(!alert.notes || alert.notes.length === 0) && (
                <p className="text-xs text-slate-600">No notes yet.</p>
              )}
            </div>
            <form onSubmit={submitNote} className="mt-3 flex gap-2">
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add an analyst note..."
                className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={saving || !note.trim()}
                className="rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40"
              >
                Add
              </button>
            </form>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-300">MITRE ATT&CK</h3>
            <InfoRow label="Technique" value={
              <a href={MITRE_LINK(alert.mitre_id)} target="_blank" rel="noreferrer" className="font-mono text-violet-300 hover:underline">
                {alert.mitre_id} {alert.mitre_name}
              </a>
            } />
            <InfoRow label="Tactic" value={alert.mitre_tactic} />
            <InfoRow label="Confidence" value={`${(alert.confidence * 100).toFixed(0)}%`} />
            <InfoRow label="Score" value={alert.score} />
            <InfoRow
              label="Hybrid risk"
              value={
                <span className="font-mono">
                  {alert.risk_score != null ? alert.risk_score : "—"} / 100
                </span>
              }
            />
            <InfoRow
              label="Detection method"
              value={
                alert.detection_method === "hybrid"
                  ? "Hybrid (rule + ML)"
                  : alert.detection_method === "ml"
                  ? "ML anomaly"
                  : "Rule-based"
              }
            />
            <InfoRow label="Event count" value={alert.event_count} />
            <InfoRow label="Created" value={alert.created_at ? new Date(alert.created_at).toLocaleString() : "—"} />
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-3 text-sm font-semibold text-slate-300">Status</h3>
            <div className="grid grid-cols-2 gap-2">
              {["open", "investigating", "resolved", "dismissed"].map((s) => (
                <button
                  key={s}
                  disabled={saving || alert.status === s}
                  onClick={() => changeStatus(s)}
                  className={`rounded-md border px-3 py-2 text-xs font-medium capitalize transition-colors ${
                    alert.status === s
                      ? "border-cyan-500 bg-cyan-500/15 text-cyan-300"
                      : "border-slate-700 text-slate-400 hover:border-slate-500"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
            <Link
              to={`/investigation?alert=${alert.id}`}
              className="mt-3 block rounded-md bg-slate-800 px-3 py-2 text-center text-sm font-medium text-slate-200 hover:bg-slate-700"
            >
              Open investigation →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
