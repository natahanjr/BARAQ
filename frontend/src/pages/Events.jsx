import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, EmptyState } from "../components/Feedback.jsx";

const PAGE_SIZE = 50;

export default function Events() {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [eventId, setEventId] = useState("");
  const [user, setUser] = useState("");
  const [category, setCategory] = useState("");
  const [anomaly, setAnomaly] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    api
      .events({
        page,
        page_size: PAGE_SIZE,
        event_id: eventId || undefined,
        user: user || undefined,
        category: category || undefined,
        anomaly: anomaly === "" ? undefined : anomaly === "true",
      })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [page, eventId, user, category, anomaly]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <input
          value={eventId}
          onChange={(e) => { setEventId(e.target.value); setPage(1); }}
          placeholder="Event ID (e.g. 4625)"
          className="w-36 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        />
        <input
          value={user}
          onChange={(e) => { setUser(e.target.value); setPage(1); }}
          placeholder="User"
          className="w-36 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        />
        <input
          value={category}
          onChange={(e) => { setCategory(e.target.value); setPage(1); }}
          placeholder="Category"
          className="w-36 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        />
        <select
          value={anomaly}
          onChange={(e) => { setAnomaly(e.target.value); setPage(1); }}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-300 outline-none focus:border-cyan-500"
        >
          <option value="">All events</option>
          <option value="true">ML anomalies only</option>
          <option value="false">Normal only</option>
        </select>
        {data && (
          <span className="ml-auto text-sm text-slate-500">
            {data.total} event(s) · page {page}/{totalPages}
          </span>
        )}
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}
      {!data && !error && <Loading label="Loading events" />}
      {data && data.items.length === 0 && <EmptyState message="No events match the filters" />}

      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Event ID</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">ML</th>
                <th className="px-4 py-3">Message</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                  <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-slate-500">
                    {e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-cyan-400">{e.event_id}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-400">{e.category}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-400">{e.user}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                        e.risk === "High" ? "bg-red-500/15 text-red-400"
                        : e.risk === "Medium" ? "bg-amber-500/15 text-amber-400"
                        : "bg-slate-500/15 text-slate-400"
                      }`}
                    >
                      {e.risk}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    {e.is_anomaly ? (
                      <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-violet-300">
                        {e.ml_score != null ? `${(e.ml_score * 100).toFixed(1)}%` : "ANOMALY"}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-700">—</span>
                    )}
                  </td>
                  <td className="max-w-80 px-4 py-2.5 text-xs text-slate-400">
                    <span className="line-clamp-2">{e.message}</span>
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
