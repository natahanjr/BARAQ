import { memo, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

const inputCls = "w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40";

function ProfileCard({ profile, expanded, onToggle, onDelete, onAssign, onUnassign }) {
  const [hostInput, setHostInput] = useState("");
  const isDefault = profile.is_default;

  const handleAssign = (e) => {
    e.preventDefault();
    if (hostInput.trim()) {
      onAssign(profile.id, hostInput.trim());
      setHostInput("");
    }
  };

  return (
    <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all hover:border-[var(--border-strong)]">
      <button type="button" onClick={onToggle} className="w-full px-5 py-4 text-left">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-[13px] font-semibold text-[var(--fg-primary)]">{profile.name}</span>
            {isDefault && <Badge severity="info" size="sm">default</Badge>}
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-[var(--fg-muted)]">{profile.host_count || 0} hosts</span>
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"
              className={`text-[var(--fg-muted)] transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}>
              <path d="M4 6l4 4 4-4" />
            </svg>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border-subtle)] px-5 pb-5 pt-4 space-y-4">
          {profile.settings && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Settings</p>
              <div className="rounded-lg bg-[var(--bg-inset)] p-3">
                <pre className="text-[11px] font-mono text-[var(--fg-secondary)] whitespace-pre-wrap">
                  {typeof profile.settings === "string" ? profile.settings : JSON.stringify(profile.settings, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {profile.assigned_hosts?.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Assigned Hosts</p>
              <div className="flex flex-wrap gap-1.5">
                {profile.assigned_hosts.map((h) => (
                  <span key={h} className="flex items-center gap-1.5 rounded-md bg-[var(--bg-inset)] px-2 py-1 font-mono text-[10px] font-medium text-[var(--fg-secondary)] ring-1 ring-[var(--border-subtle)]">
                    {h}
                    <button type="button" onClick={() => onUnassign(profile.id, h)} className="ml-0.5 text-[var(--fg-muted)] hover:text-[var(--severity-critical)]">&times;</button>
                  </span>
                ))}
              </div>
            </div>
          )}

          <form onSubmit={handleAssign} className="flex items-end gap-2">
            <div className="flex-1">
              <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Assign Host</label>
              <input
                placeholder="hostname or IP"
                value={hostInput}
                onChange={(e) => setHostInput(e.target.value)}
                className={inputCls}
              />
            </div>
            <Button type="submit" size="xs" disabled={!hostInput.trim()}>Assign</Button>
          </form>

          {!isDefault && (
            <Button variant="danger-ghost" size="xs" onClick={() => onDelete(profile.id)}>
              Delete Profile
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function FleetConfig() {
  const [profiles, setProfiles] = useState(null);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", settings: "" });
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");

  const load = () => {
    setError("");
    api
      .get("/api/fleet/profiles")
      .then((data) => setProfiles(Array.isArray(data) ? data : data.items || []))
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    setMessage("");
    try {
      await api.post("/api/fleet/profiles", {
        name: form.name.trim(),
        settings: form.settings.trim() ? JSON.parse(form.settings) : {},
      });
      setMessage("Profile created");
      setForm({ name: "", settings: "" });
      setShowForm(false);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this profile?")) return;
    try {
      await api.del(`/api/fleet/profiles/${id}`);
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleAssign = async (profileId, host) => {
    try {
      await api.post(`/api/fleet/profiles/${profileId}/assign`, { host_id: host });
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleUnassign = async (profileId, host) => {
    try {
      await api.post(`/api/fleet/profiles/${profileId}/unassign`, { host_id: host });
      load();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Fleet Configuration"
        subtitle="Manage endpoint configuration profiles"
        label="Fleet"
        actions={
          <Button size="sm" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "+ New Profile"}
          </Button>
        }
      />

      {error && <ErrorBanner message={error} onRetry={load} />}
      {message && (
        <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">
          {message}
        </div>
      )}

      {showForm && (
        <Card>
          <CardHeader><CardTitle>Create New Profile</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-3">
              <input
                required
                placeholder="Profile name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className={inputCls}
              />
              <textarea
                placeholder='Settings JSON (e.g. {"log_level": "info", "collect_processes": true})'
                value={form.settings}
                onChange={(e) => setForm({ ...form, settings: e.target.value })}
                className={`${inputCls} h-24 resize-none font-mono text-[12px]`}
              />
              <Button type="submit" size="sm" disabled={submitting}>
                {submitting ? "Creating..." : "Create Profile"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {!profiles && !error && <Loading label="Loading fleet profiles" />}

      {profiles && profiles.length === 0 && (
        <Card className="flex flex-col items-center justify-center py-16 text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-[var(--radius-2xl)] bg-[var(--bg-surface-active)]">
            <span className="text-2xl">&#9881;</span>
          </div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">No profiles configured</h3>
          <p className="mt-1.5 max-w-sm text-sm text-[var(--fg-muted)] leading-relaxed">
            Create configuration profiles to manage endpoint settings across your fleet.
          </p>
        </Card>
      )}

      {profiles && (
        <div className="space-y-2">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              profile={p}
              expanded={expanded === p.id}
              onToggle={() => setExpanded(expanded === p.id ? null : p.id)}
              onDelete={handleDelete}
              onAssign={handleAssign}
              onUnassign={handleUnassign}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default memo(FleetConfig);
