import { memo, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge } from "../components/ui/index.js";

const FRAMEWORKS = ["SOC2", "ISO27001", "NIST-CSF"];

const STATUS_STYLES = {
  compliant: { severity: "low", label: "Compliant" },
  partial: { severity: "medium", label: "Partial" },
  "non-compliant": { severity: "critical", label: "Non-Compliant" },
  unassessed: { severity: "info", label: "Unassessed" },
};

function ProgressBar({ value, color = "var(--accent-cyan)" }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: color }}
      />
    </div>
  );
}

function ComplianceGap() {
  const [framework, setFramework] = useState("SOC2");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    setData(null);
    api
      .get(`/api/compliance/report?framework=${framework}`)
      .then(setData)
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, [framework]);

  const stats = useMemo(() => {
    if (!data?.controls) return null;
    const controls = data.controls;
    const total = controls.length;
    const compliant = controls.filter((c) => c.status === "compliant").length;
    const partial = controls.filter((c) => c.status === "partial").length;
    const nonCompliant = controls.filter((c) => c.status === "non-compliant").length;
    const unassessed = controls.filter((c) => c.status === "unassessed").length;
    const pct = total > 0 ? ((compliant / total) * 100).toFixed(1) : 0;
    return { total, compliant, partial, nonCompliant, unassessed, pct };
  }, [data]);

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Compliance Gap Analysis"
        subtitle="Identify gaps against security frameworks"
        label="Compliance"
      />

      <div className="flex items-center gap-2">
        {FRAMEWORKS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFramework(f)}
            className={`rounded-lg px-4 py-2 text-[12px] font-semibold transition-all ${
              framework === f
                ? "bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30"
                : "bg-[var(--bg-inset)] text-[var(--fg-muted)] border border-[var(--border-default)] hover:text-[var(--fg-secondary)]"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {error && <ErrorBanner message={error} onRetry={load} />}
      {!data && !error && <Loading label="Loading compliance data" />}

      {data && stats && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            {[
              ["Total", stats.total, "var(--fg-primary)"],
              ["Compliant", stats.compliant, "var(--status-healthy)"],
              ["Partial", stats.partial, "var(--severity-medium)"],
              ["Non-Compliant", stats.nonCompliant, "var(--severity-critical)"],
              ["Unassessed", stats.unassessed, "var(--fg-muted)"],
            ].map(([label, value, color]) => (
              <Card key={label} className="p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{label}</p>
                <p className="mt-1 text-[22px] font-bold tabular-nums" style={{ color, fontFeatureSettings: '"tnum"' }}>
                  {value}
                </p>
              </Card>
            ))}
          </div>

          <Card>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[13px] font-semibold text-[var(--fg-primary)]">Compliance Score</span>
              <span className="text-[14px] font-bold text-[var(--accent-cyan)]">{stats.pct}%</span>
            </div>
            <ProgressBar value={stats.pct} />
          </Card>

          <Card>
            <CardHeader><CardTitle>Controls</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-[var(--border-subtle)]">
                      <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">ID</th>
                      <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Control</th>
                      <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Status</th>
                      <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)] hidden lg:table-cell">Gap</th>
                      <th className="pb-2 font-semibold text-[var(--fg-muted)] hidden lg:table-cell">Remediation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)]">
                    {data.controls.map((c) => {
                      const s = STATUS_STYLES[c.status] || STATUS_STYLES.unassessed;
                      return (
                        <tr key={c.id || c.control_id} className="group">
                          <td className="py-3 pr-4 font-mono text-[11px] font-medium text-[var(--fg-muted)]">{c.id || c.control_id}</td>
                          <td className="py-3 pr-4 text-[12px] text-[var(--fg-primary)]">{c.name || c.control}</td>
                          <td className="py-3 pr-4"><Badge severity={s.severity} size="sm">{s.label}</Badge></td>
                          <td className="py-3 pr-4 text-[11px] text-[var(--fg-secondary)] hidden lg:table-cell max-w-[200px] truncate">{c.gap || "\u2014"}</td>
                          <td className="py-3 text-[11px] text-[var(--fg-secondary)] hidden lg:table-cell max-w-[200px] truncate">{c.remediation || "\u2014"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

export default memo(ComplianceGap);
