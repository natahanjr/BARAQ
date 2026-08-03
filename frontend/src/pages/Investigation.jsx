import { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { Loading, EmptyState } from "../components/Feedback.jsx";

export default function Investigation() {
  const [params, setParams] = useSearchParams();
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(params.get("alert") || "");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState("");

  useEffect(() => {
    api.alerts({ page_size: 100 }).then((r) => setAlerts(r.items || [])).catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const a = params.get("alert");
    if (a) setSelected(a);
  }, [params]);

  useEffect(() => {
    if (!selected) {
      setData(null);
      return;
    }
    setError("");
    setData(null);
    setExplanation("");
    api
      .investigate(selected)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [selected]);

  const chooseAlert = (id) => {
    setSelected(id);
    setParams(id ? { alert: id } : {});
  };

  const explain = async () => {
    setExplaining(true);
    setExplanation("");
    try {
      const res = await api.assistantExplain(selected ? Number(selected) : undefined);
      setExplanation(res.reply);
    } catch (e) {
      setError(e.message);
    } finally {
      setExplaining(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={selected}
          onChange={(e) => chooseAlert(e.target.value)}
          className="min-w-72 rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300 outline-none focus:border-cyan-500"
        >
          <option value="">Select an alert to investigate...</option>
          {alerts.map((a) => (
            <option key={a.id} value={a.id}>
              #{a.id} {a.name} ({a.severity})
            </option>
          ))}
        </select>
        {selected && (
          <button
            onClick={explain}
            disabled={explaining}
            className="rounded-md bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-40"
          >
            {explaining ? "Thinking..." : "✦ AI explanation"}
          </button>
        )}
      </div>

      {explanation && (
        <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-4">
          <h3 className="mb-1 text-sm font-semibold text-violet-300">AI Assistant</h3>
          <p className="text-sm leading-relaxed text-slate-300">{explanation}</p>
        </div>
      )}

      {error && <p className="text-sm text-red-400">{error}</p>}

      {!selected && <EmptyState message="Select an alert to reconstruct its attack chain" />}
      {selected && !data && !error && <Loading label="Reconstructing attack chain" />}

      {data && (
        <div className="space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <Link to={`/alerts/${data.alert.id}`} className="font-medium text-cyan-300 hover:underline">
                #{data.alert.id} {data.alert.name}
              </Link>
              <SeverityBadge severity={data.alert.severity} />
              <span className="font-mono text-xs text-violet-300">{data.alert.mitre_id} · {data.alert.mitre_tactic}</span>
            </div>
            <p className="mt-2 text-sm text-slate-400">{data.summary}</p>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <h3 className="mb-3 text-sm font-semibold text-slate-300">Incident timeline</h3>
            <div className="flex flex-wrap gap-2">
              {data.related_events.map((ev, i) => (
                <div key={ev.id} className="flex items-center gap-2">
                  <div className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-1.5">
                    <p className="font-mono text-[10px] text-slate-500">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "—"}
                    </p>
                    <p className="text-xs font-medium text-slate-300">
                      {ev.event_id === 4625 ? "Failed Login"
                        : ev.event_id === 4624 ? "Login Success"
                        : ev.event_id === 4740 ? "Account Locked"
                        : ev.event_id === 4720 ? "User Created"
                        : ev.event_id === 4726 ? "User Deleted"
                        : ev.event_id === 4732 ? "Privilege Assigned"
                        : ev.event_id === 4672 ? "Privileged Logon"
                        : ev.event_id === 4104 ? "PowerShell Script"
                        : ev.event_id === 7045 ? "Service Installed"
                        : ev.event_id === 4698 ? "Scheduled Task"
                        : `Event ${ev.event_id}`}
                    </p>
                  </div>
                  {i < data.related_events.length - 1 && (
                    <span className="text-slate-700">→</span>
                  )}
                </div>
              ))}
              <div className="flex items-center gap-2">
                <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-1.5">
                  <p className="font-mono text-[10px] text-amber-500/80">
                    {data.alert.created_at ? new Date(data.alert.created_at).toLocaleTimeString() : "—"}
                  </p>
                  <p className="text-xs font-semibold text-amber-300">Alert Created</p>
                </div>
              </div>
            </div>
            {data.related_events.length === 0 && (
              <p className="text-xs text-slate-600">No surrounding events in the ±30 min window.</p>
            )}
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-slate-300">Attack chain (kill chain steps)</h3>
              <div className="space-y-3">
                {data.attack_chain.map((step, i) => (
                  <div key={i} className="relative rounded-md border border-slate-800 bg-slate-950/50 p-3">
                    <div className="flex items-center gap-2">
                      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-500/15 font-mono text-[10px] text-cyan-300">
                        {i + 1}
                      </span>
                      <span className="text-sm font-semibold text-slate-200">{step.step}</span>
                    </div>
                    <ul className="mt-2 space-y-1 pl-7">
                      {step.details.map((d, j) => (
                        <li key={j} className="text-xs leading-relaxed text-slate-500">{d}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-slate-300">Related events (±30 min window)</h3>
              <div className="max-h-96 space-y-2 overflow-y-auto">
                {data.related_events.map((ev) => (
                  <div key={ev.id} className="rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                      <span className="font-mono text-cyan-400">Event {ev.event_id}</span>
                      <span>{ev.category}</span>
                      <span>user={ev.user}</span>
                      <span className="ml-auto font-mono">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "—"}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-400">{ev.message}</p>
                  </div>
                ))}
                {data.related_events.length === 0 && <EmptyState message="No related events in window" />}
              </div>
            </div>
          </div>

          {data.network_context.length > 0 && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <h3 className="mb-3 text-sm font-semibold text-slate-300">Network context (T1046 reconnaissance)</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                      <th className="px-3 py-2">Process</th>
                      <th className="px-3 py-2">Local</th>
                      <th className="px-3 py-2">Remote</th>
                      <th className="px-3 py-2">State</th>
                      <th className="px-3 py-2">Observed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.network_context.map((c) => (
                      <tr key={c.id} className="border-b border-slate-800/50">
                        <td className="px-3 py-2 text-slate-300">{c.process || "—"}</td>
                        <td className="px-3 py-2 font-mono text-slate-500">{c.local_ip}:{c.local_port}</td>
                        <td className="px-3 py-2 font-mono text-slate-500">{c.remote_ip}:{c.remote_port}</td>
                        <td className="px-3 py-2 text-slate-400">{c.state}</td>
                        <td className="px-3 py-2 font-mono text-slate-600">
                          {c.observed_at ? new Date(c.observed_at).toLocaleTimeString() : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
