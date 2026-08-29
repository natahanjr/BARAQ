import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

const FORMATS = [
  { value: "pdf", label: "PDF" },
  { value: "html", label: "HTML" },
  { value: "json", label: "JSON" },
  { value: "csv", label: "CSV" },
];

const REPORT_TYPES = [
  { value: "executive", label: "Executive Summary", desc: "Score, threat summary, risk level" },
  { value: "technical", label: "Technical Analysis", desc: "Evidence, timeline, MITRE mappings, recommendations" },
];

function reportUrl(filePath) {
  if (!filePath) return null;
  const name = String(filePath).split(/[\\/]/).pop();
  return `/reports/${encodeURIComponent(name)}`;
}

function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [type, setType] = useState("executive");
  const [format, setFormat] = useState("pdf");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await api.listReports();
      setReports(res?.items || []);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

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

  if (loading) return <Loading label="Loading reports" />;

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Security Reports"
        subtitle="Generate and manage executive & technical security reports"
      />

      <div className="grid gap-5 lg:grid-cols-3">
        {/* Generator */}
        <Card>
          <CardHeader>
            <CardTitle>Generate Report</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-3">Report Type</p>
              <div className="space-y-2">
                {REPORT_TYPES.map((rt) => (
                  <button
                    key={rt.value}
                    type="button"
                    onClick={() => setType(rt.value)}
                    className={`w-full rounded-[var(--radius-lg)] border p-3 text-left transition-all ${
                      type === rt.value
                        ? "border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan)]/[0.06]"
                        : "border-[var(--border-subtle)] hover:border-[var(--border-default)]"
                    }`}
                  >
                    <p className={`text-[13px] font-semibold ${type === rt.value ? "text-[var(--accent-cyan)]" : "text-[var(--fg-primary)]"}`}>{rt.label}</p>
                    <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{rt.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-2">Format</p>
              <div className="grid grid-cols-2 gap-2">
                {FORMATS.map((f) => (
                  <button
                    key={f.value}
                    type="button"
                    onClick={() => setFormat(f.value)}
                    className={`rounded-[var(--radius-md)] border px-3 py-2 text-[12px] font-semibold transition-all ${
                      format === f.value
                        ? "border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan)]/[0.08] text-[var(--accent-cyan)]"
                        : "border-[var(--border-subtle)] text-[var(--fg-muted)] hover:border-[var(--border-default)]"
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            <Button
              onClick={generate}
              disabled={busy}
              className="w-full"
              size="md"
            >
              {busy ? "Generating..." : "Generate Report"}
            </Button>

            {message && (
              <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">{message}</div>
            )}
            {error && (
              <div className="rounded-[var(--radius-lg)] border border-[var(--severity-critical-border)] bg-[var(--severity-critical)]/[0.06] p-3 text-[12px] text-[var(--severity-critical)]">{error}</div>
            )}
          </CardContent>
        </Card>

        {/* Generated reports list */}
        <div className="lg:col-span-2">
          <Card padding={false}>
            <div className="flex items-center justify-between px-5 pt-4 pb-3">
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--fg-primary)]">Generated Reports</h3>
                <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{reports.length} report{reports.length === 1 ? "" : "s"}</p>
              </div>
            </div>

            {reports.length === 0 ? (
              <div className="py-16 text-center text-[13px] text-[var(--fg-muted)]">
                No reports generated yet
              </div>
            ) : (
              <div className="divide-y divide-[var(--border-subtle)]">
                {reports.map((r) => {
                  const url = reportUrl(r.file_path);
                  return (
                    <div key={r.id} className="flex items-center gap-4 px-5 py-3 hover:bg-[var(--bg-surface-hover)] transition-colors">
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[13px] font-medium text-[var(--fg-primary)]">{r.title}</p>
                        <p className="mt-0.5 truncate font-mono text-[11px] text-[var(--fg-muted)]">{r.file_path}</p>
                      </div>
                      <div className="shrink-0 text-right">
                        <Badge severity="info" size="sm">{r.report_type} · {r.format}</Badge>
                        <p className="mt-1 text-[11px] text-[var(--fg-muted)]">
                          {r.created_at ? new Date(r.created_at).toLocaleString() : "—"}
                        </p>
                      </div>
                      {url && (
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex shrink-0 items-center gap-1 rounded-[var(--radius-md)] border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/[0.06] px-3 py-1.5 text-[11px] font-semibold text-[var(--accent-cyan)] transition-colors hover:bg-[var(--accent-cyan)]/[0.12]"
                        >
                          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
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
    </div>
  );
}

export default memo(Reports);
