import { memo, useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { api, isAdmin } from "../api.js";
import Pagination from "../components/Pagination.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { EventsIcon } from "../components/icons.jsx";

const EVENTS_PAGE_SIZE = 50;

const CATEGORY_COLORS = {
  Authentication: "border-cyan-400/40 bg-cyan-500/10",
  "Account Management": "border-violet-500/40 bg-violet-500/10",
  Service: "border-amber-500/40 bg-amber-500/10",
  PowerShell: "border-emerald-500/40 bg-emerald-500/10",
  Other: "border-slate-500/40 bg-slate-500/10",
};

const EventRow = memo(function EventRow({ event }) {
  const categoryColor = CATEGORY_COLORS;

  const category = event.category || "Other";
  const colors = categoryColor[category] || categoryColor.Other;

  return (
    <div className={`rounded-xl border ${colors} p-4 transition-colors`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-xs text-slate-400 ring-1 ring-white/[0.06]">
              Event {event.event_id}
            </span>
            <span className="rounded-md bg-white/[0.04] px-2.5 py-1 text-xs text-slate-400 ring-1 ring-white/[0.06]">
              {category}
            </span>
            {event.is_anomaly ? (
              <span className="rounded-md bg-violet-500/10 px-2.5 py-1 text-xs font-semibold text-violet-400 ring-1 ring-violet-500/15">
                ML Anomaly
              </span>
            ) : (
              <span className="rounded-md bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400 ring-1 ring-emerald-500/15">
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
          <p className="mt-1 text-xs text-slate-500">
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
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-white/[0.06] pt-3 text-xs text-slate-400">
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
});

function EventsPanel() {
  const [searchParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [categories, setCategories] = useState([]);
  const [eventId, setEventId] = useState("");
  const [user, setUser] = useState("");
  const [category, setCategory] = useState("");
  const [anomaly, setAnomaly] = useState(() => {
    const v = searchParams.get("anomaly");
    return v === "true" || v === "false" ? v : "";
  });
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    api
      .events({
        page,
        page_size: EVENTS_PAGE_SIZE,
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
  }, [page, eventId, user, category, anomaly]);

  useEffect(() => {
    api
      .eventStatistics()
      .then((stats) => setCategories(stats.by_category || []))
      .catch(() => setCategories([]));
  }, []);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / EVENTS_PAGE_SIZE)) : 1;
  const hasFilters = eventId || user || category || anomaly;

  const reset = () => {
    setEventId("");
    setUser("");
    setCategory("");
    setAnomaly("");
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3 lg:grid-cols-5">
          <input
            value={eventId}
            onChange={(e) => {
              setEventId(e.target.value);
              setPage(1);
            }}
            placeholder="Event ID (4625, 4688...)"
            className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
          />
          <input
            value={user}
            onChange={(e) => {
              setUser(e.target.value);
              setPage(1);
            }}
            placeholder="Username"
            className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
          />
          <select
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setPage(1);
            }}
            className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
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
            className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
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
              className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-[13px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!data && !error && <Loading label="Loading events" />}

      {data && data.items.length === 0 && (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] py-16">
          <div className="text-4xl">📝</div>
          <h3 className="mt-4 text-[15px] font-semibold text-white">No events found</h3>
          <p className="mt-1 text-[13px] text-slate-400">
            {hasFilters ? "No events match your filters" : "No events have been collected yet"}
          </p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <div className="space-y-2">
            {data.items.map((event) => (
              <EventRow key={event.id} event={event} />
            ))}
          </div>
        </div>
      )}

      {totalPages > 1 && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <Pagination page={page} totalPages={totalPages} onChange={setPage} />
        </div>
      )}
    </div>
  );
}

function processNote(process) {
  return [
    {
      title: "What is this?",
      text: `${process.name} (PID ${process.pid}) is a running program at "${process.path || "unknown location"}". Every running program on the system appears here.`,
    },
    {
      title: "Started by",
      text: `It runs under the user account "${process.user || "unknown"}". Processes under Local System / Local Service / Network Service are Windows background services; processes under your account are programs you (or something you opened) started.`,
    },
    {
      title: "Started from",
      text: process.parent_name
        ? `It was launched by ${process.parent_name} (PID ${process.ppid}) — the program that created it. This chain can help you understand who is starting what.`
        : `No parent process was recorded (PID ${process.ppid}).`,
    },
    {
      title: "When to worry",
      text: "Alerts are meant for legitimate apps. Be suspicious of: a program you never installed, one running from a temp or config folder, or a process from an unexpected user. 'NEW' badge means the process did not exist on the previous scan.",
    },
  ];
}

const ProcessRow = memo(function ProcessRow({ process }) {
  const [showNote, setShowNote] = useState(false);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => setShowNote((s) => !s)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setShowNote((s) => !s);
        }
      }}
      aria-expanded={showNote}
      title="Tap for a detailed explanation"
      className={`cursor-pointer rounded-xl border p-4 transition-all select-none ${
        showNote
          ? "border-cyan-500/40 bg-cyan-500/[0.06]"
          : "border-white/[0.04] bg-white/[0.02] hover:border-white/[0.08] active:scale-[0.995]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-cyan-500/10 px-2.5 py-1 font-mono text-xs font-semibold text-cyan-400 ring-1 ring-cyan-500/15">
              PID {process.pid}
            </span>
            {process.is_new && (
              <span className="rounded-md bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-400 ring-1 ring-amber-500/15">
                NEW
              </span>
            )}
          </div>
          <p className="mt-2 text-sm font-semibold text-white">{process.name}</p>
          <p className="mt-0.5 line-clamp-2 font-mono text-xs text-slate-400">
            {process.path || "—"}
          </p>
        </div>
        <span className="shrink-0 text-xs text-slate-500">
          {process.observed_at
            ? new Date(process.observed_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })
            : "—"}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-white/[0.06] pt-3 text-xs text-slate-400">
        <span>
          User: <strong className="text-slate-200">{process.user || "—"}</strong>
        </span>
        <span>
          Parent PID: <strong className="font-mono text-slate-200">{process.ppid}</strong>
        </span>
        {process.parent_name && (
          <span>
            Parent: <strong className="text-slate-200">{process.parent_name}</strong>
          </span>
        )}
      </div>
      {showNote && (
        <div className="mt-3 space-y-2 rounded-lg border border-cyan-500/20 bg-cyan-500/[0.08] px-3 py-2.5 text-xs leading-relaxed">
          {processNote(process).map(({ title, text }) => (
            <p key={title}>
              <span className="font-semibold uppercase tracking-wider text-cyan-300">
                {title} —
              </span>{" "}
              <span className="text-cyan-50/90">{text}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
});

const STATE_HELP = {
  ESTABLISHED:
    "Active connection — this process is talking to the remote address right now; data flows both ways. Normal for browsers, API clients and agents, but remote addresses you do not recognize can be worth investigating.",
  LISTEN:
    "Listening — the process keeps this local port open to accept incoming connections; it has no active remote partner yet (e.g. a web server or agent waiting for traffic).",
  SYN_SENT:
    "Connecting — the process just reached out and is waiting for the remote host to accept the session.",
  TIME_WAIT:
    "Closing — the session ended cleanly and the port is being released; it will disappear in seconds.",
};

const PORT_PURPOSE = {
  20: "FTP data transfer",
  21: "FTP (file transfer)",
  22: "SSH (secure remote shell)",
  23: "Telnet (unencrypted remote shell)",
  25: "SMTP (sending email)",
  53: "DNS (domain-name lookups)",
  80: "HTTP (web, unencrypted)",
  123: "NTP (time synchronisation)",
  443: "HTTPS (secure web traffic)",
  445: "SMB / Windows file sharing",
  1900: "UPnP device discovery",
  3306: "MySQL database",
  3389: "RDP (Windows remote desktop)",
  5353: "mDNS / local device discovery",
  5432: "PostgreSQL database",
  8001: "BARAQ API",
};

function portDetail(ip, port) {
  const purpose = PORT_PURPOSE[port];
  if (purpose) {
    return `Port ${port} is the well-known port for ${purpose}, so this specific traffic type is expected here.`;
  }
  const host = !ip || ip === "0.0.0.0" || ip === "::" || ip === "*" ? "any interface" : ip;
  return host === "any interface"
    ? `Port ${port} is not a standard port, so the meaning is unclear — check which service uses it.`
    : `Port ${port} is not a standard port — it is either a dynamically assigned (ephemeral) port or a custom service; the address is more meaningful than the port.`;
}

function meaningOf(ip) {
  if (!ip) return "another host";
  const p = ip.split(".").map(Number);
  if (ip.includes(":")) return ip === "::1" ? "this computer itself (IPv6 loopback)" : "another host (IPv6)";
  if (p.length === 4 && p.every((n) => Number.isInteger(n))) {
    if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)) {
      return "another device on your local network (RFC1918 private range)";
    }
    if (p[0] === 127) return "this computer itself (loopback)";
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return "the ISP's CGNAT gateway (carrier-grade NAT)";
    if (p[0] >= 224 && p[0] <= 239) return "a multicast group (broadcast-style traffic)";
    return "a public server on the internet";
  }
  return "another host";
}

function connectionNote(connection) {
  const proc = connection.process || "This application";
  const local = `${connection.local_ip}:${connection.local_port}`;
  const hasRemote = connection.remote_ip && connection.remote_port != null;
  const remote = hasRemote ? `${connection.remote_ip}:${connection.remote_port}` : null;

  if (connection.is_listening) {
    return [
      {
        title: "What is this?",
        text: `${proc} keeps ${local} open and waits for other devices to connect to it. No connection is active in this row yet.`,
      },
      {
        title: "How it works",
        text: "A listening address is a door: the moment another device connects there, the OS records a separate ESTABLISHED pair. Web servers, database services, agents and game hosts all show up like this.",
      },
      {
        title: "About the port",
        text: portDetail(connection.local_ip, connection.local_port),
      },
      {
        title: "When to worry",
        text: "Listening is normal for software you installed (BARAQ API on 8001, web servers, etc.). A program you never installed that keeps an unusual port open can be a sign of malware accepting remote commands.",
      },
    ];
  }

  const stateText = {
    ESTABLISHED:
      "the connection succeeded and traffic flows in both directions — the normal state for a live session",
    SYN_SENT:
      "the local side sent a connection request and is still waiting for the remote host to accept it",
    TIME_WAIT:
      "the session ended cleanly and the operating system is briefly holding the port before it frees itself",
  }[connection.state];

  return [
    {
      title: "What is this?",
      text: remote
        ? `${proc} on this device has an active network session with ${remote}.`
        : `${proc} currently shows a network session in state '${connection.state}'.`,
    },
    {
      title: "Local side",
      text: `${local} is this computer's own address and its chosen port. This port is usually assigned randomly by the operating system and carries no special meaning.`,
    },
    {
      title: "Remote side",
      text: remote
        ? `${remote} is the other end of the session — ${meaningOf(connection.remote_ip)}. ${portDetail(connection.remote_ip, connection.remote_port)}`
        : "—",
    },
    {
      title: "State",
      text: `${connection.state} — ${stateText}.`,
    },
    {
      title: "Is this normal?",
      text:
        "For a browser this is routine traffic (HTTPS, fetch, updates) and is not a problem by itself. Pay attention when a process opens sessions you do not understand, the remote address is unknown/unexpected, or an unusual port appears repeatedly.",
    },
  ];
}

const NETWORK_STATE_COLORS = {
  ESTABLISHED: "bg-emerald-500/15 text-emerald-400",
  LISTEN: "bg-cyan-500/15 text-cyan-400",
  SYN_SENT: "bg-amber-500/15 text-amber-400",
  TIME_WAIT: "bg-slate-500/15 text-slate-400",
};

const NetworkRow = memo(function NetworkRow({ connection }) {
  const [showNote, setShowNote] = useState(false);
  const color = NETWORK_STATE_COLORS[connection.state] || "bg-slate-500/15 text-slate-400";

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => setShowNote((s) => !s)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setShowNote((s) => !s);
        }
      }}
      aria-expanded={showNote}
      title="Tap for a detailed explanation"
      className={`cursor-pointer rounded-xl border p-4 transition-all select-none ${
        showNote
          ? "border-cyan-500/40 bg-cyan-500/[0.06]"
          : "border-white/[0.04] bg-white/[0.02] hover:border-white/[0.08] active:scale-[0.995]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-cyan-400">
              {connection.process || "Unknown"}
            </span>
            {connection.is_listening && (
              <span className="rounded-md bg-blue-500/10 px-2.5 py-1 text-xs font-semibold text-blue-400 ring-1 ring-blue-500/15">
                LISTENING
              </span>
            )}
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div
              className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]"
              title="Local — the address on this device used for the connection"
            >
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Local
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.local_ip}:{connection.local_port}
              </p>
            </div>
            <div
              className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]"
              title="Remote — the other end of the connection (the address this process is talking to)"
            >
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Remote
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.remote_ip || "—"}:{connection.remote_port ?? "—"}
              </p>
            </div>
          </div>
        </div>
        <span
          className={`shrink-0 rounded-md px-2.5 py-1 font-mono text-xs font-semibold ring-1 ring-white/[0.06] ${color}`}
          title={STATE_HELP[connection.state]}
        >
          {connection.state}
        </span>
      </div>
      {showNote && (
        <div className="mt-3 space-y-2 rounded-lg border border-cyan-500/20 bg-cyan-500/[0.08] px-3 py-2.5 text-xs leading-relaxed">
          {connectionNote(connection).map(({ title, text }) => (
            <p key={title}>
              <span className="font-semibold uppercase tracking-wider text-cyan-300">
                {title} —
              </span>{" "}
              <span className="text-cyan-50/90">{text}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
});

function DatasetCollectorPanel() {
  const [data, setData] = useState(null);
  const [stats, setStats] = useState(null);
  const [exportsList, setExportsList] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState("");
  const [expanded, setExpanded] = useState(null);

  const admin = isAdmin();

  const load = () => {
    Promise.all([
      api.datasetStatus(),
      api.datasetStats().catch(() => null),
      api.datasetExports(20).catch(() => null),
    ])
      .then(([st, sts, ex]) => {
        setData(st);
        setStats(sts);
        setExportsList(ex);
      })
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const act = (fn, label, okMsg) => {
    setBusy(label);
    setMsg("");
    fn()
      .then(() => {
        setMsg(okMsg);
        load();
      })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(""));
  };

  const saveConfig = (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const body = {
      name: form.get("name"),
      target_events: Number(form.get("target_events")),
      events_per_file: Number(form.get("events_per_file")),
      export_interval_hours: Number(form.get("export_interval_hours")),
      anonymize: form.get("anonymize") === "on",
      include_labels: form.get("include_labels") === "on",
    };
    act(() => api.datasetUpdateConfig(body), "saving", "Settings saved");
  };

  if (!data) {
    return (
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <Loading label="Loading dataset collector" />
      </div>
    );
  }

  const coll = data.collection;
  const statusColor =
    coll?.status === "complete"
      ? "bg-emerald-500/15 text-emerald-400"
      : coll?.status === "paused"
        ? "bg-amber-500/15 text-amber-400"
        : coll?.status === "active"
          ? "bg-cyan-500/15 text-cyan-400"
          : "bg-slate-500/15 text-slate-400";

  return (
    <div className="space-y-4">
      {error && <ErrorBanner message={error} onRetry={load} />}
      {msg && (
        <div className="rounded-xl border px-5 py-3 text-sm" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
          {msg}
        </div>
      )}

      {!data.enabled ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.025] py-16">
          <div className="text-4xl">🗄</div>
          <h3 className="mt-4 text-[15px] font-semibold text-white">Dataset collector disabled</h3>
          <p className="mt-1 text-[13px] text-slate-400">
            Enable it in backend config to start collecting research data
          </p>
        </div>
      ) : (
        <>
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-white">{coll.name}</p>
                <p className="mt-0.5 text-xs text-slate-500">
                  Collector v{data.collector_version} · Format: {coll.format} · Schema v
                  {coll.schema_version ?? "—"}
                </p>
              </div>
              <span className={`rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ring-white/[0.06] ${statusColor}`}>
                {coll.status?.toUpperCase() || "INACTIVE"}
              </span>
            </div>

            <div className="mt-4">
              <div className="flex items-baseline justify-between text-xs">
                <span className="text-slate-400">
                  {coll.total_events.toLocaleString()} / {coll.target_events.toLocaleString()} events
                </span>
                <span className="font-semibold text-cyan-300">{data.progress_percent}%</span>
              </div>
              <div className="mt-1.5 h-2.5 overflow-hidden rounded-full bg-white/[0.04]">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500 transition-all"
                  style={{ width: `${Math.min(100, Math.max(0, data.progress_percent))}%` }}
                />
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
              <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Remaining
                </p>
                <p className="mt-0.5 font-mono text-slate-200">
                  {data.remaining.toLocaleString()}
                </p>
              </div>
              <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Parts exported
                </p>
                <p className="mt-0.5 font-mono text-slate-200">{coll.parts ?? 0}</p>
              </div>
              <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Next export
                </p>
                <p className="mt-0.5 font-mono text-slate-200">
                  {data.next_export
                    ? new Date(data.next_export).toLocaleString([], {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })
                    : "—"}
                </p>
              </div>
              <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Anonymized
                </p>
                <p className="mt-0.5 font-mono text-slate-200">{coll.anonymize ? "Yes" : "No"}</p>
              </div>
            </div>

            {admin && (
              <div className="mt-4 flex flex-wrap gap-2 border-t border-white/[0.06] pt-4">
                {coll.status === "paused" && (
                  <button
                    type="button"
                    disabled={busy === "resume"}
                    onClick={() => act(() => api.datasetResume(), "resume", "Collection resumed")}
                    className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-emerald-400 transition-all hover:bg-emerald-500/[0.15] disabled:opacity-50"
                  >
                    {busy === "resume" ? "Resuming…" : "Resume"}
                  </button>
                )}
                {(coll.status === "active" || coll.status === "complete") && (
                  <button
                    type="button"
                    disabled={busy === "pause"}
                    onClick={() => act(() => api.datasetPause(), "pause", "Collection paused")}
                    className="rounded-xl border border-amber-500/25 bg-amber-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-amber-400 transition-all hover:bg-amber-500/[0.15] disabled:opacity-50"
                  >
                    {busy === "pause" ? "Pausing…" : "Pause"}
                  </button>
                )}
                <button
                  type="button"
                  disabled={busy === "export"}
                  onClick={() =>
                    act(() => api.datasetExportNow(), "export", "Export started in background")
                  }
                  className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
                >
                  {busy === "export" ? "Exporting…" : "Export now"}
                </button>
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <p className="text-sm font-semibold text-white">Dataset settings</p>
            <form onSubmit={saveConfig} className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-xs">
                <span className="font-semibold uppercase tracking-wider text-slate-500">
                  Dataset name
                </span>
                <input
                  name="name"
                  defaultValue={coll.name}
                  className="mt-1 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="block text-xs">
                <span className="font-semibold uppercase tracking-wider text-slate-500">
                  Target events
                </span>
                <input
                  name="target_events"
                  type="number"
                  min="1"
                  defaultValue={coll.target_events}
                  className="mt-1 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="block text-xs">
                <span className="font-semibold uppercase tracking-wider text-slate-500">
                  Events per file (split boundary)
                </span>
                <input
                  name="events_per_file"
                  type="number"
                  min="1"
                  defaultValue={coll.events_per_file}
                  className="mt-1 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="block text-xs">
                <span className="font-semibold uppercase tracking-wider text-slate-500">
                  Export interval (hours)
                </span>
                <input
                  name="export_interval_hours"
                  type="number"
                  min="1"
                  defaultValue={coll.export_interval_hours}
                  className="mt-1 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  name="anonymize"
                  type="checkbox"
                  defaultChecked={coll.anonymize}
                  className="h-4 w-4 accent-cyan-500"
                />
                Anonymize hosts/users (pseudonyms)
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300">
                <input
                  name="include_labels"
                  type="checkbox"
                  defaultChecked={coll.include_labels}
                  className="h-4 w-4 accent-cyan-500"
                />
                Include alert verdict labels
              </label>
              {admin && (
                <button
                  type="submit"
                  disabled={busy === "saving"}
                  className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-[13px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06] disabled:opacity-50 sm:col-span-2 sm:justify-self-start"
                >
                  {busy === "saving" ? "Saving…" : "Save settings"}
                </button>
              )}
            </form>
          </div>

          {stats && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              <p className="text-sm font-semibold text-white">Composition</p>
              <div className="mt-3 grid grid-cols-2 gap-3 text-xs sm:grid-cols-3 lg:grid-cols-5">
                <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Hosts
                  </p>
                  <p className="mt-0.5 font-mono text-slate-200">{stats.hosts ?? 0}</p>
                </div>
                <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Users
                  </p>
                  <p className="mt-0.5 font-mono text-slate-200">{stats.users ?? 0}</p>
                </div>
                <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Alerts
                  </p>
                  <p className="mt-0.5 font-mono text-slate-200">{stats.alerts ?? 0}</p>
                </div>
                <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Incidents
                  </p>
                  <p className="mt-0.5 font-mono text-slate-200">{stats.incidents ?? 0}</p>
                </div>
                <div className="rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]">
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    MITRE techniques
                  </p>
                  <p className="mt-0.5 font-mono text-slate-200">
                    {Object.keys(stats.mitre_techniques ?? {}).length}
                  </p>
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {Object.entries(stats.by_event_type ?? {}).map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded-md bg-white/[0.04] px-2.5 py-1 font-mono text-xs text-slate-300 ring-1 ring-white/[0.06]"
                  >
                    {k}: <strong className="text-cyan-300">{v.toLocaleString()}</strong>
                  </span>
                ))}
              </div>
              {(stats.first_timestamp || stats.last_timestamp) && (
                <p className="mt-3 text-xs text-slate-500">
                  Range:{" "}
                  <span className="font-mono text-slate-300">
                    {stats.first_timestamp
                      ? new Date(stats.first_timestamp).toLocaleString()
                      : "—"}
                  </span>{" "}
                  →{" "}
                  <span className="font-mono text-slate-300">
                    {stats.last_timestamp ? new Date(stats.last_timestamp).toLocaleString() : "—"}
                  </span>
                </p>
              )}
            </div>
          )}

          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
            <p className="text-sm font-semibold text-white">Export history</p>
            {!exportsList || exportsList.items.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="text-3xl">📦</div>
                <h3 className="mt-3 text-[14px] font-semibold text-white">No exports yet</h3>
                <p className="mt-1 text-[12px] text-slate-400">Exports will appear here once started</p>
              </div>
            ) : (
              <div className="mt-3 space-y-2">
                {exportsList.items.map((e) => (
                  <div key={e.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4 transition-all hover:border-white/[0.08]">
                    <button
                      type="button"
                      className="flex w-full items-center justify-between gap-3 text-left"
                      onClick={() => {
                        if (expanded === e.id) {
                          setExpanded(null);
                        } else {
                          setExpanded(e.id);
                          api
                            .datasetExportDetail(e.id)
                            .then((detail) => {
                              setExportsList((prev) =>
                                prev
                                  ? { ...prev, items: prev.items.map((x) => (x.id === detail.id ? detail : x)) }
                                  : prev
                              );
                            })
                            .catch((err) => setError(err.message));
                        }
                      }}
                    >
                      <span className="text-xs text-slate-300">
                        <span className="font-mono font-semibold text-cyan-300">#{e.id}</span>{" "}
                        <span className="text-slate-500">({e.trigger})</span>
                      </span>
                      <span className="flex items-center gap-2">
                        <span
                          className={`rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ring-white/[0.06] ${
                            e.status === "completed"
                              ? "bg-emerald-500/10 text-emerald-400 ring-emerald-500/15"
                              : e.status === "failed"
                                ? "bg-rose-500/10 text-rose-400 ring-rose-500/15"
                                : "bg-amber-500/10 text-amber-400 ring-amber-500/15"
                          }`}
                        >
                          {e.status.toUpperCase()}
                        </span>
                        <span className="font-mono text-xs text-slate-400">
                          {e.event_count.toLocaleString()} events · {e.files_count} part
                          {e.files_count === 1 ? "" : "s"}
                        </span>
                      </span>
                    </button>
                    {expanded === e.id && (
                      <div className="mt-2 border-t border-white/[0.06] pt-2 text-xs text-slate-400">
                        <p>
                          Started:{" "}
                          <span className="font-mono text-slate-300">
                            {e.started_at ? new Date(e.started_at).toLocaleString() : "—"}
                          </span>{" "}
                          · Finished:{" "}
                          <span className="font-mono text-slate-300">
                            {e.completed_at ? new Date(e.completed_at).toLocaleString() : "—"}
                          </span>
                        </p>
                        {e.error_message && (
                          <p className="mt-1 text-rose-400">Error: {e.error_message}</p>
                        )}
                        <div className="mt-2 space-y-1.5">
                          {(e.files ?? []).map((f) => (
                            <div
                              key={f.id}
                              className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-white/[0.04] px-3 py-2 ring-1 ring-white/[0.06]"
                            >
                              <div className="min-w-0">
                                <p className="truncate font-mono text-slate-200">{f.filename}</p>
                                <p className="mt-0.5 text-xs text-slate-500">
                                  {f.event_count.toLocaleString()} events ·{" "}
                                  <span className="font-mono">sha256:{f.sha256.slice(0, 16)}…</span>
                                </p>
                              </div>
                              {admin && (
                                <button
                                  type="button"
                                  onClick={() =>
                                    api.datasetDownload(f.id).catch((err) => setError(err.message))
                                  }
                                  className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-2.5 py-1 text-xs font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15]"
                                >
                                  Download
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default function Telemetry() {
  const [tab, setTab] = useState("processes");
  const [processes, setProcesses] = useState([]);
  const [network, setNetwork] = useState([]);
  const [eventsTotal, setEventsTotal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = () => {
    setLoading(true);
    setError("");
    Promise.all([api.processes(), api.network()])
      .then(([p, n]) => {
        setProcesses(p.items || []);
        setNetwork(n.items || []);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    api
      .events({ page: 1, page_size: 1 })
      .then((r) => setEventsTotal(r.total))
      .catch(() => setEventsTotal(null));
  }, []);

  const tabClass = (active) =>
    active
      ? "rounded-xl border border-cyan-500/30 bg-cyan-500/[0.1] px-4 py-2.5 text-[13px] font-semibold text-cyan-300 transition-all"
      : "rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-2.5 text-[13px] font-semibold text-slate-400 transition-all hover:bg-white/[0.04] hover:text-slate-200";

  return (
    <div className="space-y-6 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Telemetry</h1>
        <p className="mt-1 text-[13px] text-slate-400">Real-time processes, network connections and security events</p>
      </div>

      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => setTab("processes")} className={tabClass(tab === "processes")}>
            Running Processes ({processes.length})
          </button>
          <button type="button" onClick={() => setTab("network")} className={tabClass(tab === "network")}>
            Network Connections ({network.length})
          </button>
          <button type="button" onClick={() => setTab("events")} className={tabClass(tab === "events")}>
            <span className="inline-flex items-center gap-2">
              <EventsIcon className="h-4 w-4" />
              Events{eventsTotal != null ? ` (${eventsTotal.toLocaleString()})` : ""}
            </span>
          </button>
          <button type="button" onClick={() => setTab("dataset")} className={tabClass(tab === "dataset")}>
            Dataset Collector
          </button>
          <button
            type="button"
            onClick={load}
            className="ml-auto rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-2.5 text-[13px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {tab === "events" ? (
        <EventsPanel />
      ) : tab === "dataset" ? (
        <DatasetCollectorPanel />
      ) : (
        <>
          {loading && <Loading label="Loading telemetry" />}
          {!loading && tab === "processes" && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              {processes.length > 0 ? (
                <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                  {processes.map((process) => (
                    <ProcessRow key={process.id} process={process} />
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16">
                  <div className="text-4xl">⚙</div>
                  <h3 className="mt-4 text-[15px] font-semibold text-white">No processes</h3>
                  <p className="mt-1 text-[13px] text-slate-400">No process data available yet</p>
                </div>
              )}
            </div>
          )}

          {!loading && tab === "network" && (
            <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
              {network.length > 0 ? (
                <div className="space-y-2">
                  {network.map((conn) => (
                    <NetworkRow key={conn.id} connection={conn} />
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-16">
                  <div className="text-4xl">🔌</div>
                  <h3 className="mt-4 text-[15px] font-semibold text-white">No connections</h3>
                  <p className="mt-1 text-[13px] text-slate-400">No network data available yet</p>
                </div>
              )}
            </div>
          )}
        </>
      )}

      <div className="flex justify-center pt-4">
        <p className="text-xs font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}