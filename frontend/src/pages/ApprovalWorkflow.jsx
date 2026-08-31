import { memo, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

const inputCls = "w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40";

const STATUS_COLORS = { pending: "medium", approved: "low", rejected: "critical" };

function RequestRow({ req, onAction, busy }) {
  return (
    <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4 transition-all hover:border-[var(--border-strong)]">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{req.action_type}</span>
            <Badge severity={STATUS_COLORS[req.status] || "info"} size="sm" dot>{req.status}</Badge>
          </div>
          {req.params && (
            <p className="mt-1.5 font-mono text-[11px] text-[var(--fg-muted)] truncate">{typeof req.params === "string" ? req.params : JSON.stringify(req.params)}</p>
          )}
          {req.justification && (
            <p className="mt-2 text-[12px] text-[var(--fg-secondary)]">{req.justification}</p>
          )}
          <p className="mt-1.5 text-[11px] text-[var(--fg-muted)]">
            Requested by {req.requested_by || "system"} · {new Date(req.created_at).toLocaleString()}
          </p>
        </div>
        {req.status === "pending" && (
          <div className="flex shrink-0 gap-2">
            <Button size="xs" onClick={() => onAction(req.id, "approved")} disabled={busy}>Approve</Button>
            <Button variant="danger" size="xs" onClick={() => onAction(req.id, "rejected")} disabled={busy}>Reject</Button>
          </div>
        )}
      </div>
    </div>
  );
}

function ApprovalWorkflow() {
  const [requests, setRequests] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ action_type: "", params: "", justification: "" });
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");

  const load = () => {
    setError("");
    api
      .get("/api/approval/pending")
      .then((data) => setRequests(Array.isArray(data) ? data : data.items || []))
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const handleAction = async (id, status) => {
    setBusy(true);
    setError("");
    try {
      if (status === "approved") {
        await api.post(`/api/approval/${id}/approve`, {});
      } else {
        await api.post(`/api/approval/${id}/reject`, {});
      }
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    setMessage("");
    try {
      await api.post("/api/approval/request", {
        action_type: form.action_type.trim(),
        action_params: form.params.trim() ? JSON.parse(form.params) : {},
        justification: form.justification.trim(),
        requested_by: "admin",
      });
      setMessage("Approval request submitted");
      setForm({ action_type: "", params: "", justification: "" });
      setShowForm(false);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const items = requests || [];
  const pending = items.filter((r) => r.status === "pending");
  const resolved = items.filter((r) => r.status !== "pending");

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Approval Workflow"
        subtitle="SOAR action approvals and request management"
        label="Automation"
        actions={
          <Button size="sm" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "+ New Request"}
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
          <CardHeader><CardTitle>New Approval Request</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-3">
              <input
                required
                placeholder="Action type (e.g. isolate_host, block_ip)"
                value={form.action_type}
                onChange={(e) => setForm({ ...form, action_type: e.target.value })}
                className={inputCls}
              />
              <textarea
                placeholder='Params JSON (e.g. {"host": "srv-01"})'
                value={form.params}
                onChange={(e) => setForm({ ...form, params: e.target.value })}
                className={`${inputCls} h-20 resize-none font-mono text-[12px]`}
              />
              <textarea
                required
                placeholder="Justification for this action..."
                value={form.justification}
                onChange={(e) => setForm({ ...form, justification: e.target.value })}
                className={`${inputCls} h-20 resize-none`}
              />
              <Button type="submit" size="sm" disabled={submitting}>
                {submitting ? "Submitting..." : "Submit Request"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {!requests && !error && <Loading label="Loading approval requests" />}

      {requests && (
        <div className="space-y-5">
          {pending.length > 0 && (
            <div>
              <h2 className="mb-3 text-[13px] font-semibold text-[var(--fg-primary)]">
                Pending ({pending.length})
              </h2>
              <div className="space-y-2">
                {pending.map((r) => (
                  <RequestRow key={r.id} req={r} onAction={handleAction} busy={busy} />
                ))}
              </div>
            </div>
          )}

          {resolved.length > 0 && (
            <div>
              <h2 className="mb-3 text-[13px] font-semibold text-[var(--fg-secondary)]">
                Resolved ({resolved.length})
              </h2>
              <div className="space-y-2">
                {resolved.map((r) => (
                  <RequestRow key={r.id} req={r} onAction={handleAction} busy={busy} />
                ))}
              </div>
            </div>
          )}

          {items.length === 0 && (
            <Card className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-[var(--radius-2xl)] bg-[var(--bg-surface-active)]">
                <span className="text-2xl">&#9989;</span>
              </div>
              <h3 className="text-base font-semibold text-[var(--fg-primary)]">No approval requests</h3>
              <p className="mt-1.5 max-w-sm text-sm text-[var(--fg-muted)] leading-relaxed">
                SOAR playbook actions requiring approval will appear here.
              </p>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

export default memo(ApprovalWorkflow);
