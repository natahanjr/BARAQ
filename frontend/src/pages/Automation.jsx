import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button, Tabs, SearchInput } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

const ACTIONS = [
  { id: "block_ip", label: "Block IP", icon: "\uD83D\uDEAB", color: "var(--severity-critical)" },
  { id: "kill_process", label: "Kill Process", icon: "\u2620\uFE0F", color: "var(--severity-high)" },
  { id: "quarantine", label: "Quarantine", icon: "\uD83E\uDDF0", color: "var(--severity-high)" },
  { id: "isolate", label: "Isolate Endpoint", icon: "\uD83D\uDD17", color: "var(--severity-critical)" },
  { id: "disable_account", label: "Disable Account", icon: "\uD83D\uDD12", color: "var(--accent-violet)" },
  { id: "escalate", label: "Escalate", icon: "\u2B06\uFE0F", color: "var(--accent-cyan)" },
  { id: "create_incident", label: "Create Incident", icon: "\uD83D\uDCCB", color: "var(--severity-low)" },
  { id: "notify", label: "Notify", icon: "\uD83D\uDD14", color: "var(--fg-muted)" },
];

const STATUS_STYLES = {
  success: { bg: "bg-[var(--status-healthy)]/[0.10]", text: "text-[var(--status-healthy)]", dot: "bg-[var(--status-healthy)]", label: "Success" },
  failed: { bg: "bg-[var(--severity-critical)]/[0.10]", text: "text-[var(--severity-critical)]", dot: "bg-[var(--severity-critical)]", label: "Failed" },
  running: { bg: "bg-[var(--accent-cyan)]/[0.10]", text: "text-[var(--accent-cyan)]", dot: "bg-[var(--accent-cyan)]", label: "Running" },
  pending: { bg: "bg-[var(--severity-medium)]/[0.10]", text: "text-[var(--severity-medium)]", dot: "bg-[var(--severity-medium)]", label: "Pending" },
};

function formatTime(iso) {
  if (!iso) return "\u2014";
  try { return new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); } catch { return iso; }
}

function timeAgo(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function Automation() {
  const [playbooks, setPlaybooks] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("playbooks");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", triggers: { severity: [], tactics: [] }, actions: [] });
  const [submitting, setSubmitting] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const [pb, rn] = await Promise.allSettled([
        api.automationPlaybooks(),
        api.automationRuns(30),
      ]);
      setPlaybooks(pb.status === "fulfilled" ? (Array.isArray(pb.value) ? pb.value : pb.value?.playbooks || pb.value?.items || []) : []);
      setRuns(rn.status === "fulfilled" ? (Array.isArray(rn.value) ? rn.value : rn.value?.runs || rn.value?.items || []) : []);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <Loading label="Loading automation" />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  const activeCount = playbooks.filter((p) => p.enabled).length;
  const successRate = runs.length > 0 ? Math.round((runs.filter((r) => r.status === "success").length / runs.length) * 100) : 0;

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* Header */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">SOAR</p>
          <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">Automation</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Playbooks, execution history, and response orchestration</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>+ New Playbook</Button>
      </header>

      {/* Stats Row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: "Playbooks", value: playbooks.length, color: "var(--accent-cyan)", icon: "\u2699\uFE0F" },
          { label: "Active", value: activeCount, color: "var(--status-healthy)", icon: "\u25B6" },
          { label: "Executions", value: runs.length, color: "var(--accent-violet)", icon: "\u26A1" },
          { label: "Success Rate", value: `${successRate}%`, color: successRate >= 80 ? "var(--status-healthy)" : successRate >= 50 ? "var(--severity-medium)" : "var(--severity-critical)", icon: "\u2705" },
        ].map((s) => (
          <div
            key={s.label}
            className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5 transition-all duration-300 hover:border-[var(--border-strong)] hover:shadow-lg"
          >
            <div className="absolute -right-6 -top-6 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-40" style={{ background: s.color }} />
            <div className="relative flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-2 text-[28px] font-bold tabular-nums leading-none text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>
                  {s.value}
                </p>
              </div>
              <span className="text-[18px] opacity-50">{s.icon}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "playbooks", label: `Playbooks (${playbooks.length})` },
          { id: "runs", label: `Execution History (${runs.length})` },
        ]}
        active={tab}
        onChange={setTab}
      />

      {/* ── Playbooks ──────────────────────────────────────── */}
      {tab === "playbooks" && (
        <div className="space-y-3">
          {playbooks.length === 0 ? (
            <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-12 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-cyan-muted)]">
                <span className="text-2xl">{"\u2699\uFE0F"}</span>
              </div>
              <h3 className="mt-4 text-[16px] font-semibold text-[var(--fg-primary)]">No Playbooks Yet</h3>
              <p className="mt-1 text-[13px] text-[var(--fg-muted)]">Create your first playbook to automate incident responses.</p>
              <Button size="sm" className="mt-4" onClick={() => setShowCreate(true)}>+ Create Playbook</Button>
            </div>
          ) : (
            playbooks.map((pb) => (
              <div
                key={pb.id}
                className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5 transition-all duration-300 hover:border-[var(--border-strong)] hover:shadow-lg"
              >
                {/* Subtle top-left glow */}
                <div className="absolute -left-8 -top-8 h-24 w-24 rounded-full bg-gradient-to-br from-[var(--accent-cyan)]/[0.04] to-transparent blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-100" />

                <div className="relative">
                  {/* Header */}
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-cyan-muted)] transition-transform duration-300 group-hover:scale-110">
                          <span className="text-[15px]">{"\u2699\uFE0F"}</span>
                        </div>
                        <div>
                          <h3 className="text-[15px] font-semibold text-[var(--fg-primary)]">{pb.name}</h3>
                          {pb.description && <p className="mt-0.5 text-[12px] text-[var(--fg-muted)] line-clamp-1">{pb.description}</p>}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold ${pb.enabled ? "bg-[var(--status-healthy)]/[0.10] text-[var(--status-healthy)]" : "bg-[var(--fg-muted)]/[0.10] text-[var(--fg-muted)]"}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${pb.enabled ? "bg-[var(--status-healthy)]" : "bg-[var(--fg-muted)]"}`} />
                        {pb.enabled ? "Active" : "Disabled"}
                      </span>
                      <Button variant="ghost" size="xs">Edit</Button>
                    </div>
                  </div>

                  {/* Triggers */}
                  {(pb.triggers?.severity?.length > 0 || pb.triggers?.tactics?.length > 0) && (
                    <div className="mt-3.5 flex flex-wrap gap-1.5 pl-12">
                      {(pb.triggers?.severity || []).map((s) => (
                        <span key={s} className="rounded-full bg-[var(--severity-medium)]/[0.08] px-2 py-0.5 text-[10px] font-semibold text-[var(--severity-medium)] ring-1 ring-[var(--severity-medium)]/20">
                          {s}
                        </span>
                      ))}
                      {(pb.triggers?.tactics || []).map((t) => (
                        <span key={t} className="rounded-full bg-[var(--accent-cyan)]/[0.08] px-2 py-0.5 text-[10px] font-semibold text-[var(--accent-cyan)] ring-1 ring-[var(--accent-cyan)]/20">
                          {t}
                        </span>
                      ))}
                      {pb.triggers?.min_risk_level && pb.triggers.min_risk_level !== "LOW" && (
                        <span className="rounded-full bg-[var(--severity-high)]/[0.08] px-2 py-0.5 text-[10px] font-semibold text-[var(--severity-high)] ring-1 ring-[var(--severity-high)]/20">
                          {"\u2265"} {pb.triggers.min_risk_level}
                        </span>
                      )}
                    </div>
                  )}

                  {/* Actions Pipeline */}
                  {(pb.actions || []).length > 0 && (
                    <div className="mt-3.5 pl-12">
                      <div className="flex flex-wrap items-center gap-2">
                        {(pb.actions || []).map((a, i) => {
                          const action = typeof a === "string" ? a : a?.action;
                          const cfg = ACTIONS.find((ac) => ac.id === action);
                          return (
                            <div key={i} className="flex items-center gap-2">
                              {i > 0 && <span className="text-[10px] text-[var(--fg-faint)]">{"\u2192"}</span>}
                              <span
                                className="inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[10px] font-semibold transition-colors"
                                style={{
                                  borderColor: `${cfg?.color || "var(--border-default)"}22`,
                                  background: `${cfg?.color || "var(--border-default)"}08`,
                                  color: cfg?.color || "var(--fg-muted)",
                                }}
                              >
                                <span className="text-[11px]">{cfg?.icon || "\u25CF"}</span>
                                {cfg?.label || action}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ── Execution History ──────────────────────────────── */}
      {tab === "runs" && (
        <div className="space-y-3">
          {runs.length === 0 ? (
            <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-12 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-violet-muted)]">
                <span className="text-2xl">{"\u26A1"}</span>
              </div>
              <h3 className="mt-4 text-[16px] font-semibold text-[var(--fg-primary)]">No Executions Yet</h3>
              <p className="mt-1 text-[13px] text-[var(--fg-muted)]">Run a playbook to see execution history here.</p>
            </div>
          ) : (
            runs.map((run) => {
              const st = STATUS_STYLES[run.status] || STATUS_STYLES.pending;
              return (
                <div
                  key={run.id}
                  className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] px-5 py-4 transition-all duration-200 hover:border-[var(--border-strong)] hover:shadow-md"
                >
                  <div className="flex items-center justify-between gap-4">
                    {/* Left: playbook name + actions */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className={`flex h-2 w-2 shrink-0 rounded-full ${st.dot}`} />
                        <h4 className="truncate text-[14px] font-semibold text-[var(--fg-primary)]">
                          {run.playbook_name || run.playbook_id || "\u2014"}
                        </h4>
                      </div>
                      <div className="mt-1.5 flex items-center gap-4 pl-5 text-[12px] text-[var(--fg-muted)]">
                        <span>{Array.isArray(run.actions_executed) ? run.actions_executed.length : run.actions_count || 0} actions</span>
                        {run.duration && <span>{run.duration}</span>}
                      </div>
                    </div>

                    {/* Right: status + time */}
                    <div className="flex items-center gap-4 shrink-0">
                      <div className="text-right">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold ${st.bg} ${st.text}`}>
                          {st.label}
                        </span>
                        <p className="mt-1 text-[11px] text-[var(--fg-muted)]" title={run.started_at}>
                          {timeAgo(run.started_at)}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Create Playbook Modal ──────────────────────────── */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowCreate(false)}>
          <div
            className="w-full max-w-lg mx-4 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)]/95 p-6 shadow-2xl backdrop-blur-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-[18px] font-bold text-[var(--fg-primary)]">Create Playbook</h2>
              <button onClick={() => setShowCreate(false)} className="rounded-lg p-1.5 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] transition-colors">
                {"\u2715"}
              </button>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setSubmitting(true);
                try {
                  await api.automationCreatePlaybook(form);
                  toast({ title: "Playbook created", type: "success" });
                  setShowCreate(false);
                  setForm({ name: "", description: "", triggers: { severity: [], tactics: [] }, actions: [] });
                  load();
                } catch (err) {
                  toast({ title: "Failed to create playbook", description: err.message, type: "error" });
                } finally {
                  setSubmitting(false);
                }
              }}
              className="space-y-4"
            >
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Name</label>
                <input
                  required
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
                  placeholder="e.g., Auto-Block Malicious IPs"
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Description</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={2}
                  className="mt-1.5 w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-inset)] px-3.5 py-2.5 text-[13px] text-[var(--fg-primary)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20 resize-none"
                  placeholder="Describe what this playbook does..."
                />
              </div>
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Trigger Severities</label>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => {
                        const cur = form.triggers.severity;
                        setForm({ ...form, triggers: { ...form.triggers, severity: cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s] } });
                      }}
                      className={`rounded-full px-3 py-1 text-[11px] font-semibold transition-all ${
                        form.triggers.severity.includes(s)
                          ? "bg-[var(--accent-cyan)] text-white shadow-[0_0_12px_-3px_var(--accent-cyan)]"
                          : "border border-[var(--border-default)] text-[var(--fg-muted)] hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]"
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Actions</label>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {ACTIONS.map((a) => (
                    <button
                      key={a.id}
                      type="button"
                      onClick={() => {
                        const cur = form.actions;
                        setForm({ ...form, actions: cur.includes(a.id) ? cur.filter((x) => x !== a.id) : [...cur, a.id] });
                      }}
                      className={`rounded-full px-3 py-1 text-[11px] font-semibold transition-all ${
                        form.actions.includes(a.id)
                          ? "bg-[var(--accent-cyan)] text-white shadow-[0_0_12px_-3px_var(--accent-cyan)]"
                          : "border border-[var(--border-default)] text-[var(--fg-muted)] hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]"
                      }`}
                    >
                      {a.icon} {a.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-subtle)]">
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
                <Button size="sm" type="submit" disabled={submitting || !form.name}>
                  {submitting ? "Creating\u2026" : "Create Playbook"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(Automation);
