import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { Button, Tabs } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

const SEVERITY_COLORS = {
  critical: { bg: "var(--severity-critical)", text: "var(--severity-critical)" },
  high: { bg: "var(--severity-high)", text: "var(--severity-high)" },
  medium: { bg: "var(--severity-medium)", text: "var(--severity-medium)" },
  low: { bg: "var(--severity-low)", text: "var(--severity-low)" },
}

function DetectionRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [tab, setTab] = useState("all");
  const [selectedRule, setSelectedRule] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", severity: "medium", mitre: "", description: "" });
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const result = await api.detectors();
      setRules(result?.detectors || result?.rules || (Array.isArray(result) ? result : []));
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = rules.filter((r) => {
    const enabled = r.enabled !== false;
    if (tab === "enabled" && !enabled) return false;
    if (tab === "disabled" && enabled) return false;
    if (search) {
      const q = search.toLowerCase();
      return (r.name || "").toLowerCase().includes(q) || (r.id || "").toLowerCase().includes(q) || (r.mitre_technique || "").toLowerCase().includes(q);
    }
    return true;
  });

  const enabledCount = rules.filter((r) => r.enabled !== false).length;
  const disabledCount = rules.filter((r) => r.enabled === false).length;
  const categories = new Set(rules.map((r) => r.category).filter(Boolean)).size;

  if (loading) return <Loading label="Loading detection rules" />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  const statCards = [
    { label: "Total Rules", value: rules.length, color: "var(--accent-cyan)", icon: "\uD83D\uDCCB" },
    { label: "Enabled", value: enabledCount, color: "var(--status-healthy)", icon: "\u25B6" },
    { label: "Disabled", value: disabledCount, color: "var(--fg-muted)", icon: "\u23F8" },
    { label: "Categories", value: categories, color: "var(--accent-violet)", icon: "\uD83C\uDFF7" },
  ];

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* Header */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Security Rules</p>
          <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">Detection Rules</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Manage and configure security detection rules</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>+ New Rule</Button>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((s) => (
          <div key={s.label} className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5 transition-all duration-300 hover:border-[var(--border-strong)] hover:shadow-lg">
            <div className="absolute -right-6 -top-6 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-40" style={{ background: s.color }} />
            <div className="relative flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-2 text-[28px] font-bold tabular-nums leading-none" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>{s.value}</p>
              </div>
              <span className="text-[18px] opacity-50">{s.icon}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Search + Tabs */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative sm:w-80">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[14px] text-[var(--fg-faint)]">{"\uD83D\uDD0D"}</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules..."
            className="w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] py-2.5 pl-9 pr-3 text-[13px] text-[var(--fg-primary)] placeholder:text-[var(--fg-faint)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
          />
        </div>
        <Tabs
          tabs={[
            { id: "all", label: `All (${rules.length})` },
            { id: "enabled", label: `Enabled (${enabledCount})` },
            { id: "disabled", label: `Disabled (${disabledCount})` },
          ]}
          active={tab}
          onChange={setTab}
        />
      </div>

      {/* Rules List */}
      {filtered.length === 0 ? (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-12 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-cyan-muted)]">
            <span className="text-2xl">{"\uD83D\uDCCA"}</span>
          </div>
          <h3 className="mt-4 text-[16px] font-semibold text-[var(--fg-primary)]">No Rules Found</h3>
          <p className="mt-1 text-[13px] text-[var(--fg-muted)]">{search ? "Try a different search term." : "Create your first detection rule to get started."}</p>
          {!search && <Button size="sm" className="mt-4" onClick={() => setShowCreate(true)}>+ Create Rule</Button>}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((rule) => {
            const enabled = rule.enabled !== false;
            const sev = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.medium;
            return (
              <div
                key={rule.id}
                onClick={() => setSelectedRule(selectedRule?.id === rule.id ? null : rule)}
                className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] px-5 py-4 transition-all duration-200 hover:border-[var(--border-strong)] hover:shadow-md cursor-pointer"
              >
                <div className="flex items-center justify-between gap-4">
                  {/* Left */}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <span className="flex h-2 w-2 shrink-0 rounded-full" style={{ background: sev.text }} />
                      <h4 className="truncate text-[14px] font-semibold text-[var(--fg-primary)]">{rule.name}</h4>
                    </div>
                    {rule.description && <p className="mt-1 pl-5 text-[12px] text-[var(--fg-muted)] truncate max-w-[500px]">{rule.description}</p>}
                    <div className="mt-2 flex items-center gap-4 pl-5 text-[11px] text-[var(--fg-muted)]">
                      {rule.mitre_technique && <span className="font-mono">{rule.mitre_technique}</span>}
                      {rule.category && <span>{rule.category}</span>}
                    </div>
                  </div>

                  {/* Right: status + severity */}
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[10px] font-semibold" style={{ background: `${sev.text}14`, color: sev.text }}>
                      {rule.severity || "info"}
                    </span>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold ${enabled ? "bg-[var(--status-healthy)]/[0.10] text-[var(--status-healthy)]" : "bg-[var(--fg-muted)]/[0.10] text-[var(--fg-muted)]"}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${enabled ? "bg-[var(--status-healthy)]" : "bg-[var(--fg-muted)]"}`} />
                      {enabled ? "On" : "Off"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Rule Detail Panel ────────────────────────────── */}
      {selectedRule && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--accent-cyan-muted)]">
                <span className="text-[16px]">{"\uD83D\uDCCA"}</span>
              </div>
              <div>
                <h2 className="text-[16px] font-bold text-[var(--fg-primary)]">{selectedRule.name}</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">{selectedRule.id}</p>
              </div>
            </div>
            <button onClick={() => setSelectedRule(null)} className="rounded-lg p-1.5 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] transition-colors">{"\u2715"}</button>
          </div>

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 mb-4">
            {[
              { label: "Severity", value: selectedRule.severity || "info", color: SEVERITY_COLORS[selectedRule.severity]?.text || "var(--fg-primary)" },
              { label: "Status", value: selectedRule.enabled !== false ? "Enabled" : "Disabled", color: selectedRule.enabled !== false ? "var(--status-healthy)" : "var(--fg-muted)" },
              { label: "MITRE", value: selectedRule.mitre_technique || "\u2014", color: "var(--accent-cyan)" },
              { label: "Category", value: selectedRule.category || "general", color: "var(--accent-violet)" },
            ].map((s) => (
              <div key={s.label} className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-1 text-[14px] font-semibold" style={{ color: s.color }}>{s.value}</p>
              </div>
            ))}
          </div>

          {selectedRule.description && (
            <div className="mb-4">
              <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-1">Description</p>
              <p className="text-[13px] text-[var(--fg-secondary)]">{selectedRule.description}</p>
            </div>
          )}

          {selectedRule.logic && (
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-1">Logic</p>
              <pre className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4 text-[12px] font-mono text-[var(--fg-secondary)] overflow-x-auto">
                {typeof selectedRule.logic === "string" ? selectedRule.logic : JSON.stringify(selectedRule.logic, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* ── Create Rule Modal ────────────────────────────── */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowCreate(false)}>
          <div className="w-full max-w-lg mx-4 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)]/95 p-6 shadow-2xl backdrop-blur-xl" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-[18px] font-bold text-[var(--fg-primary)]">Create Detection Rule</h2>
              <button onClick={() => setShowCreate(false)} className="rounded-lg p-1.5 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] transition-colors">{"\u2715"}</button>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setSubmitting(true);
                try {
                  await api.request("/api/detectors", { method: "POST", body: JSON.stringify(form) });
                  toast({ title: "Rule created", type: "success" });
                  setShowCreate(false);
                  setForm({ name: "", severity: "medium", mitre: "", description: "" });
                  load();
                } catch (err) {
                  toast({ title: "Failed to create rule", description: err.message, type: "error" });
                } finally {
                  setSubmitting(false);
                }
              }}
              className="space-y-4"
            >
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Name</label>
                <input
                  required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
                  placeholder="e.g., Suspicious PowerShell Execution"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Severity</label>
                  <select
                    value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
                    className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
                  >
                    <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">MITRE Technique</label>
                  <input
                    value={form.mitre} onChange={(e) => setForm({ ...form, mitre: e.target.value })}
                    className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] font-mono text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
                    placeholder="T1059"
                  />
                </div>
              </div>
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Description</label>
                <textarea
                  value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={3}
                  className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20 resize-none"
                  placeholder="Describe what this rule detects..."
                />
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-subtle)]">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
                <Button size="sm" type="submit" disabled={submitting || !form.name}>
                  {submitting ? "Creating\u2026" : "Create Rule"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(DetectionRules);
