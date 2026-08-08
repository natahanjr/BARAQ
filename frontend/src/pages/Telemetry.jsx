import { useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";

function ProcessRow({ process }) {
  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/30 p-4 transition-colors hover:border-slate-600/60">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-cyan-400">
              PID {process.pid}
            </span>
            {process.is_new && (
              <span className="rounded bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-400">
                NEW
              </span>
            )}
          </div>
          <p className="mt-2 text-sm font-semibold text-white">{process.name}</p>
          <p className="mt-0.5 line-clamp-2 font-mono text-xs text-slate-400">
            {process.path || "—"}
          </p>
        </div>
        <span className="shrink-0 text-[11px] text-slate-500">
          {process.observed_at
            ? new Date(process.observed_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })
            : "—"}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-slate-700/50 pt-3 text-[11px] text-slate-400">
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
    </div>
  );
}

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
  8001: "SentinelSOC API",
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
        text: "Listening is normal for software you installed (SentinelSOC API on 8001, web servers, etc.). A program you never installed that keeps an unusual port open can be a sign of malware accepting remote commands.",
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

function NetworkRow({ connection }) {
  const [showNote, setShowNote] = useState(false);
  const stateColor = {
    ESTABLISHED: "bg-emerald-500/15 text-emerald-400",
    LISTEN: "bg-blue-500/15 text-blue-400",
    SYN_SENT: "bg-amber-500/15 text-amber-400",
    TIME_WAIT: "bg-slate-500/15 text-slate-400",
  };

  const color = stateColor[connection.state] || "bg-slate-500/15 text-slate-400";

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
          : "border-slate-700/50 bg-slate-800/30 hover:border-cyan-500/30 active:scale-[0.995]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-cyan-400">
              {connection.process || "Unknown"}
            </span>
            {connection.is_listening && (
              <span className="rounded bg-blue-500/15 px-2 py-0.5 text-[10px] font-semibold text-blue-400">
                LISTENING
              </span>
            )}
            {!showNote && (
              <span className="ml-auto inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Tap for details
              </span>
            )}
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div
              className="rounded-lg bg-black/20 px-3 py-2"
              title="Local — the address on this device used for the connection"
            >
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Local
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.local_ip}:{connection.local_port}
              </p>
            </div>
            <div
              className="rounded-lg bg-black/20 px-3 py-2"
              title="Remote — the other end of the connection (the address this process is talking to)"
            >
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Remote
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.remote_ip || "—"}:{connection.remote_port ?? "—"}
              </p>
            </div>
          </div>
        </div>
        <span
          className={`shrink-0 rounded px-2 py-1 font-mono text-[10px] font-semibold ${color}`}
          title={STATE_HELP[connection.state]}
        >
          {connection.state}
        </span>
      </div>
      {showNote && (
        <div className="mt-3 space-y-2 rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2.5 text-[11px] leading-relaxed">
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
}

export default function Telemetry() {
  const [tab, setTab] = useState("processes");
  const [processes, setProcesses] = useState([]);
  const [network, setNetwork] = useState([]);
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
  }, []);

  const tabClass = (active) =>
    `rounded-lg px-4 py-2 text-sm font-medium transition-all ${
      active
        ? "border border-cyan-500/30 bg-cyan-500/15 text-cyan-300"
        : "border border-transparent text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
    }`;

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Processes & Network"
        subtitle="Real-time system telemetry and active connections"
      />

      <Card>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => setTab("processes")} className={tabClass(tab === "processes")}>
            Running Processes ({processes.length})
          </button>
          <button type="button" onClick={() => setTab("network")} className={tabClass(tab === "network")}>
            Network Connections ({network.length})
          </button>
          <button
            type="button"
            onClick={load}
            className="ml-auto rounded-lg border border-slate-700/60 bg-slate-800/60 px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-700/60"
          >
            Refresh
          </button>
        </div>
      </Card>

      {error && <ErrorBanner message={error} onRetry={load} />}

      {loading && <Loading label="Loading telemetry" />}

      {!loading && tab === "processes" && (
        <Card>
          {processes.length > 0 ? (
            <div className="space-y-2">
              {processes.map((process) => (
                <ProcessRow key={process.id} process={process} />
              ))}
            </div>
          ) : (
            <EmptyState title="No processes" subtitle="No process data available yet" icon="⚙" />
          )}
        </Card>
      )}

      {!loading && tab === "network" && (
        <Card>
          {network.length > 0 ? (
            <div className="space-y-2">
              {network.map((conn) => (
                <NetworkRow key={conn.id} connection={conn} />
              ))}
            </div>
          ) : (
            <EmptyState
              title="No connections"
              subtitle="No network data available yet"
              icon="🔌"
            />
          )}
        </Card>
      )}
    </div>
  );
}
