import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

const ACTION_TYPES = [
  { id: "block_ip", label: "Block IP", icon: "\uD83D\uDEAB" },
  { id: "kill_process", label: "Kill Process", icon: "\u2620\uFE0F" },
  { id: "quarantine", label: "Quarantine", icon: "\uD83E\uDDF0" },
  { id: "isolate", label: "Isolate Endpoint", icon: "\uD83D\uDD17" },
  { id: "disable_account", label: "Disable Account", icon: "\uD83D\uDD12" },
  { id: "escalate", label: "Escalate", icon: "\u2B06\uFE0F" },
  { id: "create_incident", label: "Create Incident", icon: "\uD83D\uDCCB" },
  { id: "notify", label: "Notify", icon: "\uD83D\uDD14" },
];

function PlaybookEditor({ playbook, onSave, onCancel }) {
  const [form, setForm] = useState(playbook || { name: "", description: "", triggers: { severity: [], tactics: [] }, actions: [] });
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  const handleSave = async () => {
    setSaving(true);
    try {
      if (playbook?.id) {
        await api.automationUpdatePlaybook(playbook.id, form);
        toast.success("Playbook updated");
      } else {
        await api.automationCreatePlaybook(form);
        toast.success("Playbook created");
      }
      onSave?.();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{playbook?.id ? "Edit Playbook" : "Create Playbook"}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)]">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="mt-1 w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-inset)] px-3 py-2 text-sm text-[var(--fg-primary)]"
              placeholder="Playbook name"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)]">Description</label>
            <textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className="mt-1 w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-inset)] px-3 py-2 text-sm text-[var(--fg-primary)]"
              rows={3}
              placeholder="Playbook description"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)]">Trigger Severity</label>
            <div className="mt-2 flex flex-wrap gap-2">
              {["critical", "high", "medium", "low"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => {
                    const current = form.triggers?.severity || [];
                    const next = current.includes(sev) ? current.filter((s) => s !== sev) : [...current, sev];
                    setForm({ ...form, triggers: { ...form.triggers, severity: next } });
                  }}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all ${
                    form.triggers?.severity?.includes(sev)
                      ? "bg-[var(--accent-cyan)] text-white"
                      : "bg-[var(--bg-inset)] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface)]"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)]">Actions</label>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {ACTION_TYPES.map((action) => (
                <button
                  key={action.id}
                  onClick={() => {
                    const current = form.actions || [];
                    const next = current.includes(action.id) ? current.filter((a) => a !== action.id) : [...current, action.id];
                    setForm({ ...form, actions: next });
                  }}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-all ${
                    form.actions?.includes(action.id)
                      ? "bg-[var(--accent-cyan)] text-white"
                      : "bg-[var(--bg-inset)] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface)]"
                  }`}
                >
                  <span>{action.icon}</span>
                  <span>{action.label}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2 pt-4">
            <Button onClick={handleSave} disabled={saving || !form.name}>
              {saving ? "Saving..." : "Save Playbook"}
            </Button>
            <Button variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function PlaybookList({ playbooks, onEdit, onTest, onRun, onDelete }) {
  return (
    <div className="grid gap-4">
      {playbooks.map((pb) => (
        <Card key={pb.id}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>{pb.name}</CardTitle>
              <Badge severity={pb.enabled ? "info" : "low"} size="sm">
                {pb.enabled ? "Active" : "Disabled"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-[var(--fg-secondary)]">{pb.description || "No description"}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {pb.triggers?.severity?.map((sev) => (
                <Badge key={sev} severity={sev} size="sm">{sev}</Badge>
              ))}
              {pb.actions?.map((action) => (
                <span key={action} className="rounded-md bg-[var(--bg-inset)] px-2 py-1 text-[10px] text-[var(--fg-secondary)]">
                  {action}
                </span>
              ))}
            </div>
            <div className="mt-4 flex gap-2">
              <Button size="sm" onClick={() => onEdit(pb)}>Edit</Button>
              <Button size="sm" variant="secondary" onClick={() => onTest(pb.id)}>Test</Button>
              <Button size="sm" variant="secondary" onClick={() => onRun(pb.id)}>Run</Button>
              <Button size="sm" variant="danger" onClick={() => onDelete(pb.id)}>Delete</Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function PlaybookEditorPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const res = await api.automationPlaybooks();
      setPlaybooks(Array.isArray(res) ? res : res?.playbooks || res?.items || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleTest = async (id) => {
    try {
      await api.automationTestPlaybook(id, 1);
      toast.success("Playbook test started");
    } catch (err) {
      toast.error(err.message);
    }
  };

  const handleRun = async (id) => {
    try {
      await api.automationRunPlaybook(id, 1);
      toast.success("Playbook executed");
    } catch (err) {
      toast.error(err.message);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm("Delete this playbook?")) return;
    try {
      await api.automationDeletePlaybook(id);
      toast.success("Playbook deleted");
      load();
    } catch (err) {
      toast.error(err.message);
    }
  };

  if (loading) return <Loading />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOAR Playbook Editor"
        subtitle={`${playbooks.length} playbooks configured`}
        action={<Button onClick={() => setShowCreate(true)}>+ New Playbook</Button>}
      />

      {(showCreate || editing) && (
        <PlaybookEditor
          playbook={editing}
          onSave={() => { setEditing(null); setShowCreate(false); load(); }}
          onCancel={() => { setEditing(null); setShowCreate(false); }}
        />
      )}

      <PlaybookList
        playbooks={playbooks}
        onEdit={setEditing}
        onTest={handleTest}
        onRun={handleRun}
        onDelete={handleDelete}
      />
    </div>
  );
}

export default memo(PlaybookEditorPage);
