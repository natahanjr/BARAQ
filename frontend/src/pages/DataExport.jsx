import { useEffect, useState, useCallback } from "react";
import { api } from "../api.js";

const DATA_TYPE_META = {
  events: { icon: "⚡", color: "from-cyan-500 to-blue-500", desc: "Normalized security events from all collectors" },
  alerts: { icon: "🚨", color: "from-red-500 to-rose-500", desc: "Detection alerts with MITRE ATT&CK mapping" },
  network: { icon: "🌐", color: "from-violet-500 to-purple-500", desc: "TCP/UDP connections, DNS, HTTP traffic" },
  processes: { icon: "⚙️", color: "from-amber-500 to-orange-500", desc: "Running process snapshots with parent chains" },
  dns: { icon: "🔍", color: "from-emerald-500 to-green-500", desc: "DNS queries from Sysmon and network collectors" },
  http: { icon: "📡", color: "from-sky-500 to-cyan-500", desc: "HTTP/S request metadata" },
  emails: { icon: "✉️", color: "from-rose-500 to-pink-500", desc: "Email messages for phishing analysis" },
  usb: { icon: "🔌", color: "from-orange-500 to-yellow-500", desc: "USB/removable device insertions" },
  file_scans: { icon: "🦠", color: "from-red-500 to-red-600", desc: "Malware file scan results" },
  vulns: { icon: "🛡️", color: "from-purple-500 to-indigo-500", desc: "CVE vulnerability findings" },
  endpoints: { icon: "💻", color: "from-teal-500 to-cyan-500", desc: "Monitored host fleet" },
  incidents: { icon: "📋", color: "from-yellow-500 to-amber-500", desc: "Security incidents grouping alerts" },
  threat_intel: { icon: "🕵️", color: "from-fuchsia-500 to-purple-500", desc: "Threat intelligence indicators" },
  entity_risk: { icon: "📊", color: "from-indigo-500 to-blue-500", desc: "Risk-Based Alerting entity scores" },
  dataset_events: { icon: "📦", color: "from-lime-500 to-green-500", desc: "Normalized research dataset events" },
};

function ExportCard({ type, meta, onExport, exporting }) {
  const [format, setFormat] = useState("csv");
  const [count, setCount] = useState(null);

  useEffect(() => {
    const url = api.exportData(type, { format, limit: 1 });
    const token = localStorage.getItem("baraq_token") || sessionStorage.getItem("baraq_token");
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => setCount(d.total ?? null))
      .catch(() => {});
  }, [type, format]);

  return (
    <div className="group relative rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5 transition-all duration-300 hover:border-white/[0.12] hover:bg-white/[0.04] hover:shadow-lg hover:shadow-black/20">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={`flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br ${meta.color} text-lg shadow-lg`}>
            {meta.icon}
          </div>
          <div>
            <h3 className="text-[14px] font-bold text-[var(--fg-primary)]">{type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</h3>
            <p className="text-[11px] text-[var(--fg-muted)] mt-0.5">{meta.desc}</p>
          </div>
        </div>
        {count !== null && (
          <span className="rounded-full bg-white/[0.06] px-2.5 py-1 text-[10px] font-bold text-[var(--fg-muted)] tabular-nums">
            {count.toLocaleString()} rows
          </span>
        )}
      </div>

      <div className="mt-4 flex items-center gap-2">
        <div className="flex rounded-xl border border-white/[0.08] bg-white/[0.03] p-0.5">
          {["csv", "json"].map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`rounded-lg px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider transition-all ${
                format === f ? "bg-white/[0.1] text-[var(--fg-primary)]" : "text-[var(--fg-muted)] hover:text-[var(--fg-secondary)]"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <button
          onClick={() => onExport(type, format)}
          disabled={exporting}
          className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-2 text-[12px] font-bold text-white shadow-md shadow-cyan-500/20 transition-all hover:shadow-lg hover:shadow-cyan-500/30 hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
        >
          {exporting ? (
            <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
          ) : (
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
            </svg>
          )}
          Export {format.toUpperCase()}
        </button>
      </div>
    </div>
  );
}

export default function DataExport() {
  const [types, setTypes] = useState([]);
  const [exporting, setExporting] = useState(null);

  useEffect(() => {
    api.exportTypes().then((d) => setTypes(d.types || [])).catch(() => {});
  }, []);

  const handleExport = useCallback((type, format) => {
    setExporting(type);
    const token = localStorage.getItem("baraq_token") || sessionStorage.getItem("baraq_token");
    const url = api.exportData(type, { format, limit: 100000 });

    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => {
        if (!r.ok) throw new Error("Export failed");
        const disposition = r.headers.get("Content-Disposition");
        const filename = disposition?.match(/filename="?(.+?)"?$/)?.[1] || `baraq_${type}.${format}`;
        return r.blob().then((blob) => ({ blob, filename }));
      })
      .then(({ blob, filename }) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
      })
      .catch(() => {})
      .finally(() => setExporting(null));
  }, []);

  return (
    <div className="space-y-6 pb-16">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[20px] font-bold text-[var(--fg-primary)] tracking-tight">Data Export</h1>
          <p className="mt-1 text-[13px] text-[var(--fg-muted)]">Export all collected security data as CSV or JSON</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded-full bg-cyan-500/10 px-3 py-1.5 text-[10px] font-bold text-cyan-400 uppercase tracking-wider">
            {types.length} data types
          </span>
        </div>
      </div>

      <div className="rounded-2xl border border-cyan-500/15 bg-gradient-to-br from-cyan-500/[0.06] via-[var(--bg-surface)] to-blue-500/[0.04] p-4">
        <div className="flex items-start gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-cyan-500/15">
            <svg className="h-4 w-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
          </div>
          <div>
            <p className="text-[13px] font-semibold text-[var(--fg-primary)]">All data collected by BARAQ</p>
            <p className="text-[11px] text-[var(--fg-muted)] mt-0.5">
              Export includes events, alerts, network traffic, processes, DNS, HTTP, emails, USB devices, file scans, vulnerabilities, endpoints, incidents, threat intel, entity risk, and dataset events. All exports are filtered to your tenant scope.
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {types.map((t) => {
          const meta = DATA_TYPE_META[t.key] || { icon: "📄", color: "from-slate-500 to-gray-500", desc: t.label };
          return <ExportCard key={t.key} type={t.key} meta={meta} onExport={handleExport} exporting={exporting === t.key} />;
        })}
      </div>

      {types.length === 0 && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-12 text-center">
          <p className="text-[13px] text-[var(--fg-muted)]">Loading available data types...</p>
        </div>
      )}
    </div>
  );
}
