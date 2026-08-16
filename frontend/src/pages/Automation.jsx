import { useEffect, useState } from "react";
import { api, isAdmin } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
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
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
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

  useEffect(() => {
    load();
  }, []);

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
    if (!form.name.trim()) {
      setError("Playbook needs a name");
      return;
    }
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
    setBusy(true);
    setError("");
    const req = editing
      ? api.automationUpdatePlaybook(editing.id, body)
      : api.automationCreatePlaybook(body);
    req
      .then(() => {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
        load();
      })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const remove = (p) => {
    if (!window.confirm(`Delete playbook "${p.name}" and its run history?`)) return;
    api
      .automationDeletePlaybook(p.id)
      .then(load)
      .catch((e) => setError(e.message));
  };

  const toggleEnabled = (p) => {
    api
      .automationUpdatePlaybook(p.id, { enabled: !p.enabled })
      .then(load)
      .catch((e) => setError(e.message));
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Automation"
        subtitle="SOAR playbooks: when an alert matches declared triggers, run ordered response actions automatically."
        actions={
          isAdmin() && (
            <button
              onClick={startCreate}
              className="rounded-lg bg-violet-500 px-4 py-1.5 text-sm font-semibold text-white hover:bg-violet-500"
            >
              New Playbook
            </button>
          )
        }
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError("")} />}

      {isAdmin() && (
        <Card tone="violet">
          <h3 className="mb-3 text-lg font-semibold text-white">
            {editing ? `Edit: ${editing.name}` : "New Playbook"}
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">Name</span>
                <input
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">Description</span>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  rows={2}
                  className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                />
              </label>
              <label className="flex items-center gap-2 text-sm text-slate-200">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                  className="h-4 w-4 accent-violet-500"
                />
                Enabled (fires automatically on matching alerts)
              </label>
            </div>

            <div className="space-y-3">
              <span className="block text-xs font-semibold uppercase tracking-wide text-slate-400">
                Triggers (dimensions AND together; comma-separated values OR)
              </span>
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase text-slate-500">Rules</span>
                  <input
                    defaultValue={commaText(form.triggers.rules)}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        triggers: { ...f.triggers, rulesText: e.target.value },
                      }))
                    }
                    placeholder="brute_force, pass_the_hash"
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase text-slate-500">Severity</span>
                  <input
                    defaultValue={commaText(form.triggers.severity)}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        triggers: { ...f.triggers, severityText: e.target.value },
                      }))
                    }
                    placeholder="high, critical"
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase text-slate-500">MITRE tactics</span>
                  <input
                    defaultValue={commaText(form.triggers.tactics)}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        triggers: { ...f.triggers, tacticsText: e.target.value },
                      }))
                    }
                    placeholder="Credential Access, Persistence"
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] uppercase text-slate-500">Min risk level</span>
                  <select
                    value={form.triggers.min_risk_level || "LOW"}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        triggers: { ...f.triggers, min_risk_level: e.target.value },
                      }))
                    }
                    className="w-full rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                  >
                    {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((l) => (
                      <option key={l}>{l}</option>
                    ))}
                  </select>
                </label>
              </div>
              <span className="block text-xs font-semibold uppercase tracking-wide text-slate-400">
                Actions (run in order)
              </span>
              {form.actions.map((a, i) => (
                <div key={i} className="flex gap-2">
                  <select
                    value={a.action}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        actions: f.actions.map((x, j) => (j === i ? { action: e.target.value } : x)),
                      }))
                    }
                    className="flex-1 rounded-md border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100"
                  >
                    {ACTIONS.map((act) => (
                      <option key={act} value={act}>
                        {act}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() =>
                      setForm((f) => ({ ...f, actions: f.actions.filter((_, j) => j !== i) }))
                    }
                    className="rounded-md border border-slate-600 px-3 text-slate-400 hover:text-red-300"
                  >
                    ×
                  </button>
                </div>
              ))}
              <button
                onClick={() => setForm((f) => ({ ...f, actions: [...f.actions, { action: "notify" }] }))}
                className="rounded-md border border-dashed border-slate-600 px-3 py-1.5 text-xs text-slate-300 hover:border-violet-400"
              >
                + Add action
              </button>
            </div>
          </div>
          <div className="mt-4 flex gap-3">
            <button
              onClick={save}
              disabled={busy}
              className="rounded-lg bg-violet-500 px-4 py-1.5 text-sm font-semibold text-white hover:bg-violet-500 disabled:opacity-50"
            >
              {saved ? "Saved" : busy ? "Saving…" : editing ? "Save Changes" : "Create Playbook"}
            </button>
            <button
              onClick={() => {
                setEditing(null);
                setForm({ ...EMPTY_FORM });
              }}
              className="rounded-lg border border-slate-600 px-4 py-1.5 text-sm text-slate-300 hover:text-white"
            >
              Cancel
            </button>
          </div>
        </Card>
      )}

      <Card>
        <h3 className="mb-3 text-lg font-semibold text-white">Playbooks</h3>
        {playbooks === null ? (
          <Loading />
        ) : playbooks.playbooks.length === 0 ? (
          <EmptyState
            title="No playbooks yet"
            message="Create a playbook to automate response: declare triggers (rule, severity, tactic, risk level) and the actions to run when they fire."
          />
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {playbooks.playbooks.map((p) => (
              <div key={p.id} className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-4">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-semibold text-slate-100">{p.name}</span>
                  <span
                    className={`rounded px-2 py-0.5 text-[11px] font-semibold ${
                      p.enabled ? "bg-emerald-500/20 text-emerald-300" : "bg-slate-700 text-slate-400"
                    }`}
                  >
                    {p.enabled ? "active" : "paused"}
                  </span>
                </div>
                <p className="mb-3 text-xs text-slate-400">{p.description || "No description."}</p>
                <div className="mb-3 flex flex-wrap gap-1.5">
                  {(p.triggers?.rules || []).map((r) => (
                    <span key={r} className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-300">
                      {r}
                    </span>
                  ))}
                  {(p.triggers?.severity || []).map((s) => (
                    <RiskBadge key={s} level={s.toUpperCase()} />
                  ))}
                  {(p.triggers?.tactics || []).map((t) => (
                    <span key={t} className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-300">
                      {t}
                    </span>
                  ))}
                  {p.triggers?.min_risk_level && (
                    <span className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-violet-300">
                      ≥ {p.triggers.min_risk_level}
                    </span>
                  )}
                </div>
                <div className="mb-3 flex flex-wrap gap-1.5">
                  {p.actions.map((a, i) => (
                    <span key={i} className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-amber-300">
                      {a.action}
                    </span>
                  ))}
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => toggleEnabled(p)}
                    className="rounded-md border border-slate-600 px-2.5 py-1 text-xs text-slate-300 hover:text-white"
                  >
                    {p.enabled ? "Pause" : "Activate"}
                  </button>
                  {isAdmin() && (
                    <>
                      <button
                        onClick={() => startEdit(p)}
                        className="rounded-md border border-slate-600 px-2.5 py-1 text-xs text-slate-300 hover:text-white"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => remove(p)}
                        className="rounded-md border border-slate-600 px-2.5 py-1 text-xs text-red-300 hover:text-red-200"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card tone="slate">
        <h3 className="mb-3 text-lg font-semibold text-white">Recent Runs</h3>
        {runs === null ? (
          <Loading />
        ) : runs.runs.length === 0 ? (
          <EmptyState
            title="No runs yet"
            message="Playbook executions appear here - both automatic (from the detection pipeline) and manual."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table w-full">
              <thead className="text-xs uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Playbook</th>
                  <th className="px-3 py-2">Alert</th>
                  <th className="px-3 py-2">Rule</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {runs.runs.map((r) => (
                  <tr key={r.id}>
                    <td className="px-3 py-2 text-xs text-slate-400">{formatTime(r.created_at)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-200">
                      {r.playbook_name}
                      {r.triggered_by === "manual" && (
                        <span className="ml-2 rounded bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300">manual</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-300">#{r.alert_id} {r.alert_name}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-400">{r.rule}</td>
                    <td className="px-3 py-2 text-xs">
                      <span
                        className={`rounded px-2 py-0.5 font-semibold ${
                          r.status === "completed"
                            ? "bg-emerald-500/20 text-emerald-300"
                            : r.status === "failed"
                              ? "bg-red-500/20 text-red-300"
                              : "bg-amber-500/20 text-amber-300"
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-400">
                      {(r.results || [])
                        .map((x) => `${x.action}:${x.status}`)
                        .join(", ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}