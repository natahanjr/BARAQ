import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, EmptyState } from "../components/Feedback.jsx";

function ProcessTable({ rows }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
            <th className="px-3 py-2.5">PID</th>
            <th className="px-3 py-2.5">Parent</th>
            <th className="px-3 py-2.5">Process</th>
            <th className="px-3 py-2.5">User</th>
            <th className="px-3 py-2.5">New</th>
            <th className="px-3 py-2.5">Observed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
              <td className="px-3 py-2 font-mono text-xs text-cyan-400">{p.pid}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{p.ppid}</td>
              <td className="px-3 py-2">
                <p className="text-xs font-medium text-slate-300">{p.name}</p>
                <p className="max-w-md truncate font-mono text-[10px] text-slate-600" title={p.path}>
                  {p.path || "—"}
                </p>
              </td>
              <td className="px-3 py-2 text-xs text-slate-400">{p.user || "—"}</td>
              <td className="px-3 py-2">
                {p.is_new ? (
                  <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-400">NEW</span>
                ) : (
                  <span className="text-xs text-slate-700">—</span>
                )}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                {p.observed_at ? new Date(p.observed_at).toLocaleString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function NetworkTable({ rows }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
            <th className="px-3 py-2.5">Process</th>
            <th className="px-3 py-2.5">Local</th>
            <th className="px-3 py-2.5">Remote</th>
            <th className="px-3 py-2.5">State</th>
            <th className="px-3 py-2.5">Listening</th>
            <th className="px-3 py-2.5">Observed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
              <td className="px-3 py-2 text-xs text-slate-300">{c.process || "—"}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{c.local_ip}:{c.local_port}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">
                {c.is_listening ? "—" : `${c.remote_ip}:${c.remote_port}`}
              </td>
              <td className="px-3 py-2 text-xs text-slate-400">{c.state}</td>
              <td className="px-3 py-2">
                {c.is_listening ? (
                  <span className="rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-400">LISTEN</span>
                ) : (
                  <span className="text-xs text-slate-700">—</span>
                )}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                {c.observed_at ? new Date(c.observed_at).toLocaleString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Telemetry() {
  const [tab, setTab] = useState("processes");
  const [processes, setProcesses] = useState(null);
  const [network, setNetwork] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setError("");
    if (tab === "processes") {
      api.processes().then(setProcesses).catch((e) => setError(e.message));
    } else {
      api.network().then(setNetwork).catch((e) => setError(e.message));
    }
  }, [tab]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button
          onClick={() => setTab("processes")}
          className={`rounded-md px-4 py-1.5 text-sm font-medium ${
            tab === "processes" ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Processes ({processes?.total ?? "…"})
        </button>
        <button
          onClick={() => setTab("network")}
          className={`rounded-md px-4 py-1.5 text-sm font-medium ${
            tab === "network" ? "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30" : "text-slate-400 hover:text-slate-200"
          }`}
        >
          Network connections ({network?.total ?? "…"})
        </button>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}
      {!error && tab === "processes" && !processes && <Loading label="Loading processes" />}
      {!error && tab === "network" && !network && <Loading label="Loading connections" />}

      {tab === "processes" && processes && (
        processes.items.length === 0 ? <EmptyState message="No process records" /> : (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60">
            <ProcessTable rows={processes.items} />
          </div>
        )
      )}
      {tab === "network" && network && (
        network.items.length === 0 ? <EmptyState message="No network records" /> : (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60">
            <NetworkTable rows={network.items} />
          </div>
        )
      )}
    </div>
  );
}
