import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, EmptyState } from "../components/Feedback.jsx";

const FORMATS = [
  { value: "pdf", label: "PDF" },
  { value: "html", label: "HTML" },
  { value: "json", label: "JSON" },
  { value: "csv", label: "CSV" },
];

export default function Reports() {
  const [reports, setReports] = useState(null);
  const [type, setType] = useState("executive");
  const [format, setFormat] = useState("pdf");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () => api.listReports().then(setReports).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);

  const generate = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const res = await api.generateReport(type, format);
      setMessage(`Report generated: ${res.file_path}`);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 lg:col-span-1">
          <h2 className="text-sm font-semibold text-slate-300">Generate report</h2>
          <p className="mt-1 text-xs text-slate-500">
            Executive: score, threat summary, risk level. Technical: evidence, timeline, MITRE mappings, recommendations.
          </p>
          <label className="mt-4 block text-xs uppercase tracking-wider text-slate-500">Type</label>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500"
          >
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
          </select>
          <label className="mt-3 block text-xs uppercase tracking-wider text-slate-500">Format</label>
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500"
          >
            {FORMATS.map((f) => (
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
          <button
            onClick={generate}
            disabled={busy}
            className="mt-4 w-full rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40"
          >
            {busy ? "Generating..." : "Generate report"}
          </button>
          {message && <p className="mt-3 break-all rounded-md bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">{message}</p>}
          {error && <p className="mt-3 rounded-md bg-red-500/10 px-3 py-2 text-xs text-red-300">{error}</p>}
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold text-slate-300">Generated reports</h2>
          {!reports && <Loading label="Loading reports" />}
          {reports && reports.items.length === 0 && <EmptyState message="No reports generated yet" />}
          {reports && reports.items.length > 0 && (
            <div className="mt-3 max-h-[28rem] space-y-2 overflow-y-auto">
              {reports.items.map((r) => (
                <div key={r.id} className="flex items-center justify-between gap-4 rounded-md border border-slate-800 bg-slate-950/50 px-3 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate text-sm text-slate-300">{r.title}</p>
                    <p className="truncate font-mono text-[11px] text-slate-500">{r.file_path}</p>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] font-semibold uppercase text-slate-400">
                      {r.report_type} · {r.format}
                    </span>
                    <p className="mt-1 text-[10px] text-slate-600">
                      {r.created_at ? new Date(r.created_at).toLocaleString() : "—"}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
