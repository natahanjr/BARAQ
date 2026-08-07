import { useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import Pagination from "../components/Pagination.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { EventsIcon } from "../components/icons.jsx";

const PAGE_SIZE = 50;

const selectClass =
  "rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 transition-colors";

function EventRow({ event }) {
  const categoryColor = {
    Authentication: "border-blue-500/40 bg-blue-500/10",
    "Account Management": "border-purple-500/40 bg-purple-500/10",
    Service: "border-amber-500/40 bg-amber-500/10",
    PowerShell: "border-emerald-500/40 bg-emerald-500/10",
    Other: "border-slate-500/40 bg-slate-500/10",
  };

  const category = event.category || "Other";
  const colors = categoryColor[category] || categoryColor.Other;

  return (
    <div className={`rounded-xl border ${colors} p-4 transition-colors`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-black/30 px-2 py-0.5 font-mono text-[10px] text-slate-200">
              Event {event.event_id}
            </span>
            <span className="rounded bg-black/30 px-2 py-0.5 text-[10px] text-slate-200">
              {category}
            </span>
            {event.is_anomaly ? (
              <span className="rounded bg-violet-500/15 px-2 py-0.5 text-[10px] font-semibold text-violet-400">
                ML Anomaly
              </span>
            ) : (
              <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-400">
                Normal
              </span>
            )}
          </div>
          <p className="mt-2 text-sm font-medium text-white">{event.message || "Security Event"}</p>
        </div>
        <div className="shrink-0 text-right">
          <p className="text-xs text-slate-400">
            Risk:{" "}
            <strong className={event.is_anomaly ? "text-violet-300" : "text-slate-200"}>
              {event.risk_score != null
                ? `${event.risk_score.toFixed(0)}`
                : event.risk || "—"}
            </strong>
          </p>
          <p className="mt-1 text-[11px] text-slate-500">
            {event.timestamp
              ? new Date(event.timestamp).toLocaleString([], {
                  month: "short",
                  day: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "—"}
          </p>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-current/10 pt-3 text-[11px] text-slate-400">
        <span>
          User: <strong className="text-slate-200">{event.user || "—"}</strong>
        </span>
        <span>
          Host: <strong className="text-slate-200">{event.host || "—"}</strong>
        </span>
        {event.ml_score != null && (
          <span>
            ML Score: <strong className="text-cyan-400">{event.ml_score.toFixed(3)}</strong>
          </span>
        )}
      </div>
    </div>
  );
}

export default function Events() {
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [categories, setCategories] = useState([]);
  const [eventId, setEventId] = useState("");
  const [user, setUser] = useState("");
  const [category, setCategory] = useState("");
  const [anomaly, setAnomaly] = useState("");
  const [error, setError] = useState("");

  const load = () => {
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
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, eventId, user, category, anomaly]);

  useEffect(() => {
    api
      .eventStatistics()
      .then((stats) => setCategories(stats.by_category || []))
      .catch(() => setCategories([]));
  }, []);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const hasFilters = eventId || user || category || anomaly;

  const reset = () => {
    setEventId("");
    setUser("");
    setCategory("");
    setAnomaly("");
    setPage(1);
  };

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Security Events"
        subtitle="Normalized Windows security events and telemetry"
        actions={
          data ? (
            <span className="inline-flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-800/60 px-3.5 py-2 text-sm text-slate-300">
              <EventsIcon className="h-4 w-4 text-cyan-400" />
              <strong className="text-white">{data.total.toLocaleString()}</strong>
              events
            </span>
          ) : undefined
        }
      />

      {/* Filters */}
      <Card>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3 lg:grid-cols-5">
          <input
            value={eventId}
            onChange={(e) => {
              setEventId(e.target.value);
              setPage(1);
            }}
            placeholder="Event ID (4625, 4688...)"
            className={selectClass}
          />
          <input
            value={user}
            onChange={(e) => {
              setUser(e.target.value);
              setPage(1);
            }}
            placeholder="Username"
            className={selectClass}
          />
          <select
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setPage(1);
            }}
            className={selectClass}
            aria-label="Filter by category"
          >
            <option value="">All Categories</option>
            {categories.map((c) => (
              <option key={c.category} value={c.category}>
                {c.category} ({c.count})
              </option>
            ))}
          </select>
          <select
            value={anomaly}
            onChange={(e) => {
              setAnomaly(e.target.value);
              setPage(1);
            }}
            className={selectClass}
            aria-label="Filter by anomaly status"
          >
            <option value="">All Events</option>
            <option value="true">ML Anomalies</option>
            <option value="false">Normal Only</option>
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

      {!data && !error && <Loading label="Loading events" />}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No events found"
          subtitle={hasFilters ? "No events match your filters" : "No events have been collected yet"}
          icon="📝"
        />
      )}

      {data && data.items.length > 0 && (
        <Card>
          <div className="space-y-2">
            {data.items.map((event) => (
              <EventRow key={event.id} event={event} />
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
