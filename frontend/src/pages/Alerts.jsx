import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { Loading, EmptyState } from "../components/Feedback.jsx";

const PAGE_SIZE = 25;

export default function Alerts() {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    api
      .alerts({ page, page_size: PAGE_SIZE, status, severity })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [page, status, severity]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        {data && (
          <span className="ml-auto text-sm text-slate-500">
            {data.total} alert(s) · page {page}/{totalPages}
          </span>
        )}
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {!data && !error && <Loading label="Loading alerts" />}

      {data && data.items.length === 0 && <EmptyState message="No alerts match the filters" />}

      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3">Alert</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">MITRE</th>
                <th className="px-4 py-3">Tactic</th>
                <th className="px-4 py-3">Events</th>
                <th className="px-4 py-3">Detected</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id} className="border-b border-slate-800/60 transition-colors hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <Link to={`/alerts/${a.id}`} className="font-medium text-cyan-300 hover:underline">
                      #{a.id} {a.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-violet-300">{a.mitre_id}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{a.mitre_tactic}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{a.event_count}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {a.created_at ? new Date(a.created_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <button
            disabled={page <= 1}
            onClick={() => setPage(page - 1)}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 disabled:opacity-40 hover:border-slate-500"
          >
            Previous
          </button>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage(page + 1)}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 disabled:opacity-40 hover:border-slate-500"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
