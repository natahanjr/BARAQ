import { useEffect, useState } from "react";
import { api, isAdmin } from "../api.js";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";

const ACTIONS = [
  "block_ip",
  "kill_process",
  "quarantine",
  "isolate",
  "disable_account",
  "escalate",
  "create_incident",
  "notify",
];

const ACTION_TONES = {
  block_ip: "border-rose-500/20 bg-rose-500/[0.06] text-rose-400",
  kill_process: "border-amber-500/20 bg-amber-500/[0.06] text-amber-400",
  quarantine: "border-orange-500/20 bg-orange-500/[0.06] text-orange-400",
  isolate: "border-red-500/20 bg-red-500/[0.06] text-red-400",
  disable_account: "border-violet-500/20 bg-violet-500/[0.06] text-violet-400",
  escalate: "border-cyan-500/20 bg-cyan-500/[0.06] text-cyan-400",
  create_incident: "border-sky-500/20 bg-sky-500/[0.06] text-sky-400",
  notify: "border-slate-500/20 bg-slate-500/[0.06] text-slate-400",
};

const ACTION_ICONS = {
  block_ip: "🛡",
  kill_process: "⚡",
  quarantine: "📦",
  isolate: "🔒",
  disable_account: "🚫",
  escalate: "🔔",
  create_incident: "📋",
  notify: "✉",
};

const EMPTY_FORM = {
  name: "",
  description: "",
  enabled: true,
  triggers: { rules: [], severity: [], tactics: [], min_risk_level: "MEDIUM" },
  actions: [{ action: "block_ip" }],
};

function commaText(list) {
  return Array.isArray(list) ? list.join(", ") : "";
}

function parseComma(text) {
  return text.split(",").map((s) => s.trim()).filter(Boolean);
}

function formatTime(iso) {
  if (!iso) return "\u2014";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function SectionLabel({ children }) {
  return (
    <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
      <span className="h-1 w-1 rounded-full bg-cyan-400" />
      {children}
    </h3>
  );
}

function TriggerTags({ triggers, onDelete }) {
  const tags = [
    ...(triggers.rules || []).map((r) => ({ type: "rule", label: r })),
    ...(triggers.severity || []).map((s) => ({ type: "severity", label: s })),
    ...(triggers.tactics || []).map((t) => ({ type: "tactic", label: t })),
  ];

  const tagTones = {
    rule: "border-cyan-500/20 bg-cyan-500/[0.06] text-cyan-400",
    severity: "border-amber-500/20 bg-amber-500/[0.06] text-amber-400",
    tactic: "border-violet-500/20 bg-violet-500/[0.06] text-violet-400",
  };

  return (
    <div className="flex flex-wrap gap-1.5">
      {tags.map((t, i) => (
        <span key={i} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${tagTones[t.type] || tagTones.rule}`}>
          {t.label}
          {onDelete && (
            <button type="button" onClick={() => onDelete(t)} className="ml-0.5 text-white/40 transition-colors hover:text-white/80">&times;</button>
          )}
        </span>
      ))}
      {triggers.min_risk_level && triggers.min_risk_level !== "LOW" && (
        <span className="inline-flex items-center gap-1 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-1 text-xs font-semibold text-slate-300">
          ≥ {triggers.min_risk_level}
        </span>
      )}
    </div>
  );
}

export default function Automation() {
  const [playbooks, setPlaybooks] = useState(null);
  const [runs, setRuns] = useState(null);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const load = () => {
    api.automationPlaybooks().then(setPlaybooks).catch((e) => setError(e.message));
    api.automationRuns(30).then(setRuns).catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const startCreate = () => {
    setForm({ ...EMPTY_FORM });
    setEditing(null);
  };

  const startEdit = (p) => {
    setEditing(p);
    setForm({
      name: p.name,
      description: p.description || "",
      enabled: p.enabled,
      triggers: {
        rules: p.triggers?.rules || [],
        severity: p.triggers?.severity || [],
        tactics: p.triggers?.tactics || [],
        min_risk_level: p.triggers?.min_risk_level || "MEDIUM",
      },
      actions: (p.actions || []).map((a) => (typeof a === "string" ? { action: a } : a)),
    });
  };

  const save = () => {
    if (!form.name.trim()) { setError("Playbook needs a name"); return; }
    const body = {
      name: form.name.trim(),
      description: form.description,
      enabled: form.enabled,
      triggers: {
        rules: parseComma(form.triggers.rulesText || commaText(form.triggers.rules)),
        severity: parseComma(form.triggers.severityText || commaText(form.triggers.severity)),
        tactics: parseComma(form.triggers.tacticsText || commaText(form.triggers.tactics)),
        min_risk_level: form.triggers.min_risk_level || "LOW",
      },
      actions: form.actions.filter((a) => a.action),
    };
    setBusy(true); setError("");
    const req = editing
      ? api.automationUpdatePlaybook(editing.id, body)
      : api.automationCreatePlaybook(body);
    req
      .then(() => { setSaved(true); setTimeout(() => setSaved(false), 2000); load(); })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const remove = (p) => {
    if (!window.confirm(`Delete playbook "${p.name}" and its run history?`)) return;
    api.automationDeletePlaybook(p.id).then(load).catch((e) => setError(e.message));
  };

  const toggleEnabled = (p) => {
    api.automationUpdatePlaybook(p.id, { enabled: !p.enabled }).then(load).catch((e) => setError(e.message));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Automation</h1>
            <p className="mt-2 text-[13px] leading-relaxed text-slate-400/80">
              SOAR playbooks: when an alert matches declared triggers, run ordered response actions automatically.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={startCreate}
              className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-5 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]"
            >
              + New Playbook
            </button>
          )}
        </div>
      </div>

      {error && <ErrorBanner message={error} onDismiss={() => setError("")} />}

      {/* Form */}
      {isAdmin() && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <div className="mb-6 flex items-center justify-between">
            <SectionLabel>{editing ? `Edit: ${editing.name}` : "New Playbook"}</SectionLabel>
            {editing && (
              <button onClick={() => { setEditing(null); setForm({ ...EMPTY_FORM }); }}
                className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-white/[0.06]">
                Cancel edit
              </button>
            )}
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Left: Name, Description, Enabled */}
            <div className="space-y-4">
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Name</span>
                <input
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Auto-isolate critical brute force"
                  className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="block">
                <span className="mb-1.5 block text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Description</span>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  rows={2}
                  placeholder="What this playbook does and when to use it"
                  className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                />
              </label>
              <label className="flex cursor-pointer items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3 transition-all hover:border-white/[0.1]">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                  className="h-[14px] w-[14px] rounded-[3px] accent-cyan-500"
                />
                <span className="text-[12px] font-medium text-slate-300">Enabled (fires automatically on matching alerts)</span>
              </label>
            </div>

            {/* Right: Triggers */}
            <div className="space-y-4">
              <span className="block text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">
                Triggers &mdash; AND together; comma-separated values OR
              </span>
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-500/70">Rules</span>
                  <input
                    defaultValue={commaText(form.triggers.rules)}
                    onChange={(e) => setForm((f) => ({ ...f, triggers: { ...f.triggers, rulesText: e.target.value } }))}
                    placeholder="brute_force, pass_the_hash"
                    className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-500/70">Severity</span>
                  <input
                    defaultValue={commaText(form.triggers.severity)}
                    onChange={(e) => setForm((f) => ({ ...f, triggers: { ...f.triggers, severityText: e.target.value } }))}
                    placeholder="high, critical"
                    className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-500/70">MITRE tactics</span>
                  <input
                    defaultValue={commaText(form.triggers.tactics)}
                    onChange={(e) => setForm((f) => ({ ...f, triggers: { ...f.triggers, tacticsText: e.target.value } }))}
                    placeholder="Credential Access, Persistence"
                    className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-slate-500/70">Min risk level</span>
                  <select
                    value={form.triggers.min_risk_level || "LOW"}
                    onChange={(e) => setForm((f) => ({ ...f, triggers: { ...f.triggers, min_risk_level: e.target.value } }))}
                    className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  >
                    {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((l) => <option key={l}>{l}</option>)}
                  </select>
                </label>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="mt-6">
            <span className="mb-3 block text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">
              Actions &mdash; run in order
            </span>
            <div className="space-y-2">
              {form.actions.map((a, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-white/[0.04] text-xs font-bold text-slate-500 ring-1 ring-white/[0.06]">
                    {i + 1}
                  </span>
                  <select
                    value={a.action}
                    onChange={(e) => setForm((f) => ({
                      ...f,
                      actions: f.actions.map((x, j) => (j === i ? { action: e.target.value } : x)),
                    }))}
                    className="flex-1 rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  >
                    {ACTIONS.map((act) => (
                      <option key={act} value={act}>{act}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => setForm((f) => ({ ...f, actions: f.actions.filter((_, j) => j !== i) }))}
                    className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/[0.06] bg-white/[0.02] text-slate-500 transition-all hover:border-rose-500/30 hover:bg-rose-500/[0.08] hover:text-rose-400"
                  >
                    &times;
                  </button>
                </div>
              ))}
            </div>
            <button
              onClick={() => setForm((f) => ({ ...f, actions: [...f.actions, { action: "notify" }] }))}
              className="mt-3 rounded-xl border border-dashed border-white/[0.08] bg-white/[0.02] px-4 py-2.5 text-[12px] font-semibold text-slate-400 transition-all hover:border-cyan-500/30 hover:bg-cyan-500/[0.04] hover:text-cyan-400"
            >
              + Add action
            </button>
          </div>

          {/* Submit */}
          <div className="mt-6 flex gap-3">
            <button
              onClick={save}
              disabled={busy}
              className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-6 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
            >
              {saved ? "\u2713 Saved" : busy ? "Saving..." : editing ? "Save Changes" : "Create Playbook"}
            </button>
          </div>
        </div>
      )}

      {/* Playbooks Grid */}
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <SectionLabel>Playbooks</SectionLabel>
        {playbooks === null ? (
          <Loading label="Loading playbooks" />
        ) : playbooks.playbooks.length === 0 ? (
          <div className="flex flex-col items-center py-14 text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-white/[0.03] ring-1 ring-white/[0.06]">
              <svg className="h-7 w-7 text-slate-500/40" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714a2.25 2.25 0 00.659 1.591L19 14.5m-4.25-11.396c.251.023.501.05.75.082M5 14.5l-1.085 1.085A2.25 2.25 0 003.5 17.293v.457m14-7.293l1.085 1.085A2.25 2.25 0 0120.5 17.293v.457" />
              </svg>
            </div>
            <p className="text-[14px] font-semibold text-slate-300">No playbooks yet</p>
            <p className="mt-1.5 max-w-sm text-[12px] leading-relaxed text-slate-500/70">
              Create a playbook to automate response: declare triggers (rule, severity, tactic, risk level) and the actions to run when they fire.
            </p>
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {playbooks.playbooks.map((p) => (
              <div key={p.id} className="group relative overflow-hidden rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5 transition-all hover:border-white/[0.12] hover:bg-white/[0.035] hover:shadow-[0_8px_32px_-8px_rgba(0,0,0,0.4)]">
                {/* Enabled indicator */}
                <div className={`absolute inset-x-0 top-0 h-[2px] transition-all ${p.enabled ? "bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-60" : "bg-white/[0.04]"}`} />

                {/* Header */}
                <div className="mb-3 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="truncate text-[14px] font-bold text-white">{p.name}</h3>
                    <p className="mt-1 line-clamp-2 text-[12px] leading-relaxed text-slate-400/70">{p.description || "No description"}</p>
                  </div>
                  <span className={`shrink-0 rounded-lg px-2.5 py-1 text-xs font-bold uppercase tracking-wider ${p.enabled ? "border border-emerald-500/30 bg-emerald-500/[0.1] text-emerald-400" : "border border-white/[0.06] bg-white/[0.03] text-slate-500"}`}>
                    {p.enabled ? "Active" : "Paused"}
                  </span>
                </div>

                {/* Triggers */}
                <div className="mb-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500/60">Triggers</p>
                  <TriggerTags triggers={p.triggers || {}} />
                </div>

                {/* Actions */}
                <div className="mb-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500/60">Actions</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(p.actions || []).map((a, i) => (
                      <span key={i} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-xs font-semibold ${ACTION_TONES[a.action] || ACTION_TONES.notify}`}>
                        <span>{ACTION_ICONS[a.action] || "\u2022"}</span>
                        {a.action}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Controls */}
                <div className="flex gap-2 border-t border-white/[0.04] pt-4">
                  <button onClick={() => toggleEnabled(p)}
                    className={`rounded-xl border px-3 py-1.5 text-xs font-semibold transition-all ${p.enabled ? "border-amber-500/20 bg-amber-500/[0.06] text-amber-400 hover:bg-amber-500/[0.12]" : "border-emerald-500/20 bg-emerald-500/[0.06] text-emerald-400 hover:bg-emerald-500/[0.12]"}`}>
                    {p.enabled ? "Pause" : "Activate"}
                  </button>
                  {isAdmin() && (
                    <>
                      <button onClick={() => startEdit(p)}
                        className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-white/[0.06]">
                        Edit
                      </button>
                      <button onClick={() => remove(p)}
                        className="ml-auto rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs font-semibold text-rose-400/70 transition-all hover:border-rose-500/30 hover:bg-rose-500/[0.08] hover:text-rose-400">
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Runs */}
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <SectionLabel>Recent Runs</SectionLabel>
        {runs === null ? (
          <Loading label="Loading run history" />
        ) : runs.runs.length === 0 ? (
          <div className="flex flex-col items-center py-14 text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-white/[0.03] ring-1 ring-white/[0.06]">
              <svg className="h-7 w-7 text-slate-500/40" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-[14px] font-semibold text-slate-300">No runs yet</p>
            <p className="mt-1.5 max-w-sm text-[12px] leading-relaxed text-slate-500/70">
              Playbook executions appear here — both automatic (from the detection pipeline) and manual.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {runs.runs.map((r) => (
              <div key={r.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4 transition-all hover:border-white/[0.08]">
                <div className="flex flex-wrap items-center gap-3">
                  {/* Status dot */}
                  <span className={`h-2 w-2 shrink-0 rounded-full ${r.status === "completed" ? "bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.5)]" : r.status === "failed" ? "bg-rose-400 shadow-[0_0_6px_rgba(251,113,133,0.5)]" : "bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.5)]"}`} />

                  {/* Playbook name */}
                  <span className="text-[13px] font-bold text-white">{r.playbook_name}</span>

                  {/* Manual badge */}
                  {r.triggered_by === "manual" && (
                    <span className="rounded-md bg-violet-500/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider text-violet-400 ring-1 ring-violet-500/15">
                      Manual
                    </span>
                  )}

                  {/* Alert */}
                  <span className="text-[12px] text-slate-400">
                    Alert <span className="font-mono text-slate-300">#{r.alert_id}</span> {r.alert_name && <span className="text-slate-500">&middot; {r.alert_name}</span>}
                  </span>

                  {/* Rule */}
                  {r.rule && (
                    <span className="rounded-md bg-white/[0.04] px-2 py-0.5 font-mono text-xs text-slate-400 ring-1 ring-white/[0.06]">
                      {r.rule}
                    </span>
                  )}

                  {/* Time */}
                  <span className="ml-auto text-xs text-slate-500/70">
                    {formatTime(r.created_at)}
                  </span>

                  {/* Status badge */}
                  <span className={`rounded-lg px-2.5 py-1 text-xs font-bold uppercase tracking-wider ${r.status === "completed" ? "border border-emerald-500/30 bg-emerald-500/[0.1] text-emerald-400" : r.status === "failed" ? "border border-rose-500/30 bg-rose-500/[0.1] text-rose-400" : "border border-amber-500/30 bg-amber-500/[0.1] text-amber-400"}`}>
                    {r.status}
                  </span>
                </div>

                {/* Action chips */}
                {(r.results || []).length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5 pl-5">
                    {r.results.map((x, i) => (
                      <span key={i} className={`inline-flex items-center gap-1 rounded-lg px-2 py-0.5 font-mono text-xs font-semibold ${x.status === "success" ? "bg-emerald-500/[0.06] text-emerald-400" : x.status === "failed" ? "bg-rose-500/[0.06] text-rose-400" : "bg-white/[0.04] text-slate-400"}`}>
                        {x.action}
                        <span className="text-white/30">:</span>
                        <span className="text-white/50">{x.status}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex justify-center pt-4">
        <p className="text-xs font-medium text-slate-500/50">BARAQ &middot; Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
