import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading } from "../components/Feedback.jsx";
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
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Security Reports</h1>
        <p className="mt-1 text-[13px] leading-relaxed text-slate-400">Generate and manage executive & technical security reports</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="text-base font-semibold text-white">Generate Report</h3>
          <p className="mt-1 text-[12px] leading-relaxed text-slate-400">
            Executive: score, threat summary, risk level.
            <br />
            Technical: evidence, timeline, MITRE mappings, recommendations.
          </p>

          <h3 className="mb-2 mt-5 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Report Type
          </h3>
          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="mt-1 w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
          >
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Analysis</option>
          </select>

          <h3 className="mb-2 mt-5 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Format
          </h3>
          <div className="mt-1 grid grid-cols-2 gap-2">
            {FORMATS.map((f) => (
              <button
                key={f.value}
                type="button"
                onClick={() => setFormat(f.value)}
                className={`rounded-xl border px-4 py-2 text-[13px] font-medium transition-all ${
                  format === f.value
                    ? "border-cyan-500/30 bg-cyan-500/[0.1] text-cyan-300"
                    : "border-white/[0.06] bg-white/[0.02] text-slate-400 hover:bg-white/[0.04]"
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
            className="mt-6 w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-5 py-3 text-[14px] font-bold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_24px_-4px_rgba(0,240,255,0.25)] disabled:opacity-50"
          >
            {busy ? "Generating..." : "Generate Report"}
          </button>

          {message && (
            <div className="mt-4 rounded-xl border p-4" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)" }}>
              <p className="break-all text-sm" style={{ color: "var(--success-text, #065f46)" }}>✓ {message}</p>
            </div>
          )}
          {error && (
            <div className="mt-4 rounded-xl border p-4" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)" }}>
              <p className="text-sm" style={{ color: "var(--error-text, #991b1b)" }}>{error}</p>
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6 lg:col-span-2">
          <div className="mb-5 flex items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-white">Generated Reports</h3>
              <p className="mt-0.5 text-[13px] text-slate-400">All exported security reports</p>
            </div>
            {reports && reports.items?.length > 0 && (
              <span className="inline-flex items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300">
                <ReportsIcon className="h-3.5 w-3.5" />
                {reports.items.length} reports
              </span>
            )}
          </div>

          {!reports && <Loading label="Loading reports" />}
          {reports && reports.items?.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.03]">
                <ReportsIcon className="h-7 w-7 text-slate-500" />
              </div>
              <p className="text-[15px] font-semibold text-white">No reports generated</p>
              <p className="mt-1 text-[13px] text-slate-400">Generate your first security report using the panel</p>
            </div>
          )}

          {reports && reports.items?.length > 0 && (
            <div className="max-h-[36rem] space-y-2.5 overflow-y-auto">
              {reports.items.map((r) => {
                const url = reportUrl(r.file_path);
                return (
                  <div
                    key={r.id}
                    className="flex items-center justify-between gap-4 rounded-xl border border-white/[0.04] bg-white/[0.02] px-4 py-3 transition-all hover:border-white/[0.08]"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] font-medium text-white">{r.title}</p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-500">
                        {r.file_path}
                      </p>
                    </div>
                    <div className="shrink-0 text-right">
                      <span className="rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300">
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
                        className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-3 py-2 text-[11px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15]"
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
        </div>
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-[11px] font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
