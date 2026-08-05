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

function NetworkRow({ connection }) {
  const stateColor = {
    ESTABLISHED: "bg-emerald-500/15 text-emerald-400",
    LISTEN: "bg-blue-500/15 text-blue-400",
    SYN_SENT: "bg-amber-500/15 text-amber-400",
    TIME_WAIT: "bg-slate-500/15 text-slate-400",
  };

  const color = stateColor[connection.state] || "bg-slate-500/15 text-slate-400";

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/30 p-4 transition-colors hover:border-slate-600/60">
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
          </div>
          <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div className="rounded-lg bg-black/20 px-3 py-2">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Local
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.local_ip}:{connection.local_port}
              </p>
            </div>
            <div className="rounded-lg bg-black/20 px-3 py-2">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Remote
              </p>
              <p className="mt-0.5 truncate font-mono text-xs text-slate-200">
                {connection.remote_ip || "—"}:{connection.remote_port ?? "—"}
              </p>
            </div>
          </div>
        </div>
        <span className={`shrink-0 rounded px-2 py-1 font-mono text-[10px] font-semibold ${color}`}>
          {connection.state}
        </span>
      </div>
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
