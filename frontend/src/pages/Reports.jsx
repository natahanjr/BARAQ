import { useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { ReportsIcon, DownloadIcon } from "../components/icons.jsx";

const FORMATS = [
  { value: "pdf", label: "PDF" },
  { value: "html", label: "HTML" },
  { value: "json", label: "JSON" },
  { value: "csv", label: "CSV" },
];

function reportUrl(filePath) {
  if (!filePath) return null;
  const name = String(filePath).split(/[\\/]/).pop();
  return `/reports/${encodeURIComponent(name)}`;
}

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
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Security Reports"
        subtitle="Generate and manage executive & technical security reports"
      />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Generate panel */}
        <Card>
          <h3 className="text-base font-semibold text-white">Generate Report</h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            Executive: score, threat summary, risk level.
            <br />
            Technical: evidence, timeline, MITRE mappings, recommendations.
          </p>

          <label className="mt-5 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Report Type
          </label>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2 text-sm text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          >
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Analysis</option>
          </select>

          <label className="mt-5 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Format
          </label>
          <div className="mt-2 grid grid-cols-2 gap-2">
            {FORMATS.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setFormat(f.value)}
                className={`rounded-lg border px-4 py-2 text-sm font-medium transition-all ${
                  format === f.value
                    ? "border-cyan-500/40 bg-cyan-500/15 text-cyan-300"
                    : "border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-500"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={generate}
            disabled={busy}
            className="mt-6 w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-3 font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
          >
            {busy ? "Generating..." : "Generate Report"}
          </button>

          {message && (
            <p className="mt-4 break-all rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs text-emerald-300">
              ✓ {message}
            </p>
          )}
          {error && (
            <p className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs text-red-300">
              {error}
            </p>
          )}
        </Card>

        {/* Reports list */}
        <Card className="lg:col-span-2">
          <div className="mb-5 flex items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">Generated Reports</h3>
              <p className="mt-0.5 text-sm text-slate-400">All exported security reports</p>
            </div>
            {reports && reports.items?.length > 0 && (
              <span className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-400">
                <ReportsIcon className="h-3.5 w-3.5" />
                {reports.items.length} reports
              </span>
            )}
          </div>

          {!reports && <Loading label="Loading reports" />}
          {reports && reports.items?.length === 0 && (
            <EmptyState
              title="No reports generated"
              subtitle="Generate your first security report using the panel"
              icon="📄"
            />
          )}

          {reports && reports.items?.length > 0 && (
            <div className="max-h-[36rem] space-y-2.5 overflow-y-auto">
              {reports.items.map((r) => {
                const url = reportUrl(r.file_path);
                return (
                  <div
                    key={r.id}
                    className="flex items-center justify-between gap-4 rounded-xl border border-slate-700/50 bg-slate-800/30 px-4 py-3 transition-colors hover:border-slate-600/60"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-white">{r.title}</p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                        {r.file_path}
                      </p>
                    </div>
                    <div className="shrink-0 text-right">
                      <span className="rounded-lg border border-slate-700/60 bg-slate-900/60 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300">
                        {r.report_type} · {r.format}
                      </span>
                      <p className="mt-1.5 text-[11px] text-slate-500">
                        {r.created_at ? new Date(r.created_at).toLocaleString() : "—"}
                      </p>
                    </div>
                    {url && (
                      <a
                        href={url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-400 transition-colors hover:bg-cyan-500/20"
                        title="Open report"
                      >
                        <DownloadIcon className="h-3.5 w-3.5" />
                        Open
                      </a>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
