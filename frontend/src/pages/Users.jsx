import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button, Tabs, SearchInput } from "../components/ui/index.js";

function Users() {
  const [users, setUsers] = useState([]);
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState("");
  const [tab, setTab] = useState("users");
  const [search, setSearch] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "analyst", full_name: "", org: "" });

  const [mfaState, setMfaState] = useState("idle");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaOtpauth, setMfaOtpauth] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaBusy, setMfaBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [u, a] = await Promise.allSettled([api.users(), api.audit({ limit: 200 })]);
      setUsers(u.status === "fulfilled" ? u.value?.items || [] : []);
      setAudit(a.status === "fulfilled" ? a.value?.items || [] : []);
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [refresh]);

  const startMfa = async () => {
    setError(""); setMessage(""); setMfaBusy(true);
    try {
      const res = await api.mfaSetup();
      setMfaSecret(res.secret); setMfaOtpauth(res.otpauth_url); setMfaState("confirm");
    } catch (err) { setError(err.message); } finally { setMfaBusy(false); }
  };

  const confirmMfa = async () => {
    setError(""); setMessage(""); setMfaBusy(true);
    try {
      await api.mfaConfirm(mfaCode.trim());
      setMessage("Two-factor authentication enabled");
      setMfaState("idle"); setMfaSecret(""); setMfaOtpauth(""); setMfaCode(""); refresh();
    } catch (err) { setError(err.message); } finally { setMfaBusy(false); }
  };

  const disableMfa = async () => {
    const next = window.prompt("Enter your current authenticator code to disable 2FA:");
    if (!next) return;
    setError(""); setMessage(""); setMfaBusy(true);
    try { await api.mfaDisable(next.trim()); setMessage("2FA disabled"); refresh(); }
    catch (err) { setError(err.message); } finally { setMfaBusy(false); }
  };

  const create = async (e) => {
    e.preventDefault(); setBusy("create"); setError(""); setMessage("");
    try {
      const u = await api.createUser(form);
      setMessage(`User "${u.username}" created`); setForm({ username: "", password: "", role: "analyst", full_name: "", org: "" }); refresh();
    } catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const toggleActive = async (u) => {
    setBusy(`active:${u.id}`); setError("");
    try { await api.updateUser(u.id, { is_active: !u.is_active }); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const approve = async (u) => {
    setBusy(`approve:${u.id}`); setError(""); setMessage("");
    try { await api.approveUser(u.id); setMessage(`"${u.username}" verified`); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const reject = async (u) => {
    if (!window.confirm(`Reject "${u.username}"?`)) return;
    setBusy(`reject:${u.id}`); setError("");
    try { await api.rejectUser(u.id); setMessage(`"${u.username}" rejected`); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const resetPassword = async (u) => {
    const next = window.prompt(`New password for "${u.username}":`);
    if (!next) return; setBusy(`pwd:${u.id}`); setError("");
    try { await api.updateUser(u.id, { password: next }); setMessage(`Password reset for "${u.username}"`); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const remove = async (u) => {
    if (!window.confirm(`Delete "${u.username}"? This cannot be undone.`)) return;
    setBusy(`del:${u.id}`); setError("");
    try { await api.deleteUser(u.id); setMessage(`"${u.username}" deleted`); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  const clearAudit = async () => {
    if (!window.confirm("Clear audit trail?")) return;
    setBusy("clearAudit"); setError(""); setMessage("");
    try { await api.clearAudit(); setMessage("Audit trail cleared"); refresh(); }
    catch (err) { setError(err.message); } finally { setBusy(""); }
  };

  if (loading) return <Loading label="Loading users" />;

  const filtered = users.filter((u) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return u.username?.toLowerCase().includes(q) || u.full_name?.toLowerCase().includes(q) || u.org?.toLowerCase().includes(q);
  });

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Users & Audit"
        subtitle="Manage operator accounts and review the audit trail"
        actions={<Button onClick={refresh} variant="secondary" size="sm">Refresh</Button>}
      />

      {message && <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">{message}</div>}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Users</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{users.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Pending</p>
          <p className="mt-1 text-2xl font-bold text-[var(--severity-high)]">{users.filter((u) => u.registration_status === "pending").length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Audit Events</p>
          <p className="mt-1 text-2xl font-bold text-[var(--fg-primary)]">{audit.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">2FA Enabled</p>
          <p className="mt-1 text-2xl font-bold text-[var(--status-healthy)]">{users.filter((u) => u.totp_enabled).length}</p>
        </Card>
      </div>

      <Tabs
        tabs={[{ id: "users", label: "Users" }, { id: "audit", label: "Audit Trail" }, { id: "mfa", label: "2FA Setup" }, { id: "create", label: "Create Account" }]}
        active={tab}
        onChange={setTab}
      />

      {tab === "users" && (
        <>
          <SearchInput value={search} onChange={setSearch} placeholder="Search users..." className="sm:w-80" />
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <Card><div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No users found</div></Card>
            ) : filtered.map((u) => (
              <Card key={u.id} hover>
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-mono text-[13px] font-semibold text-[var(--fg-primary)]">{u.username}</span>
                      <Badge severity={u.role === "admin" ? "low" : "info"} size="sm">{u.role}</Badge>
                      {u.totp_enabled && <Badge severity="info" size="sm">2FA</Badge>}
                      {u.registration_status === "pending" && <Badge severity="medium" size="sm">PENDING</Badge>}
                      {u.registration_status === "rejected" && <Badge severity="critical" size="sm">REJECTED</Badge>}
                      {!u.is_active && u.registration_status !== "pending" && u.registration_status !== "rejected" && <Badge severity="critical" size="sm">DISABLED</Badge>}
                      {u.org && <Badge severity="low" size="sm">{u.org}</Badge>}
                    </div>
                    <p className="mt-1 truncate text-[11px] text-[var(--fg-muted)]">
                      {u.full_name || "—"}
                      {u.last_login_at ? ` · last login ${new Date(u.last_login_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}` : " · never logged in"}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    {u.registration_status === "pending" ? (
                      <>
                        <Button variant="ghost" size="xs" onClick={() => approve(u)} disabled={busy === `approve:${u.id}`}>Approve</Button>
                        <Button variant="danger-ghost" size="xs" onClick={() => reject(u)} disabled={busy === `reject:${u.id}`}>Reject</Button>
                      </>
                    ) : (
                      <>
                        <Button variant="ghost" size="xs" onClick={() => resetPassword(u)} disabled={busy === `pwd:${u.id}`}>Pwd</Button>
                        <Button variant="ghost" size="xs" onClick={() => toggleActive(u)} disabled={busy === `active:${u.id}`}>{u.is_active ? "Disable" : "Enable"}</Button>
                      </>
                    )}
                    <Button variant="danger-ghost" size="xs" onClick={() => remove(u)} disabled={busy === `del:${u.id}`}>Delete</Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </>
      )}

      {tab === "audit" && (
        <Card padding={false}>
          <div className="flex items-center justify-between px-5 pt-4 pb-3">
            <p className="text-[11px] text-[var(--fg-muted)]">{audit.length} event{audit.length === 1 ? "" : "s"}</p>
            <Button variant="danger-ghost" size="xs" onClick={clearAudit} disabled={busy === "clearAudit" || audit.length === 0}>Clear</Button>
          </div>
          {audit.length === 0 ? (
            <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No activity yet</div>
          ) : (
            <div className="max-h-[480px] overflow-y-auto">
              <table className="w-full text-left">
                <thead>
                  <tr><th>When</th><th>Actor</th><th>Action</th><th>Entity</th><th>Detail</th><th>IP</th></tr>
                </thead>
                <tbody>
                  {audit.map((e) => (
                    <tr key={e.id} className="hover:bg-[var(--bg-surface-hover)]">
                      <td className="whitespace-nowrap font-mono text-[11px] text-[var(--fg-muted)]">{new Date(e.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</td>
                      <td className="font-mono text-[11px] text-[var(--accent-cyan)]">{e.actor}</td>
                      <td><Badge severity="info" size="sm">{e.action}</Badge></td>
                      <td className="font-mono text-[11px] text-[var(--fg-secondary)]">{e.entity_type ? `${e.entity_type} ${e.entity_id}` : "—"}</td>
                      <td className="max-w-[320px] truncate text-[11px] text-[var(--fg-muted)]">{e.detail || "—"}</td>
                      <td className="font-mono text-[11px] text-[var(--fg-muted)]">{e.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab === "mfa" && (
        <Card>
          <CardContent>
            {mfaState === "confirm" ? (
              <div className="space-y-3">
                <p className="text-[13px] text-[var(--fg-secondary)]">Scan with your authenticator app</p>
                {mfaOtpauth ? (
                  <div className="mx-auto flex max-w-[200px] justify-center rounded-[var(--radius-lg)] bg-white p-2">
                    <img src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(mfaOtpauth)}`} alt="QR code" className="h-full w-full" />
                  </div>
                ) : (
                  <pre className="overflow-x-auto rounded-[var(--radius-md)] bg-[var(--bg-inset)] p-3 text-center font-mono text-[13px] text-[var(--status-healthy)]">{mfaSecret}</pre>
                )}
                <p className="break-all text-[11px] text-[var(--fg-muted)]">Manual: <span className="font-mono text-[var(--fg-secondary)]">{mfaSecret}</span></p>
                <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value.slice(0, 6))} placeholder="6-digit code" inputMode="numeric" className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-3 text-center font-mono text-[13px] tracking-[0.4em] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
                <div className="flex gap-2">
                  <Button onClick={confirmMfa} disabled={mfaCode.length < 6 || mfaBusy} className="flex-1" size="sm">Activate 2FA</Button>
                  <Button variant="ghost" size="sm" onClick={() => setMfaState("idle")}>Cancel</Button>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-[13px] text-[var(--fg-secondary)]">Add TOTP-based two-factor authentication (RFC 6238)</p>
                <Button onClick={startMfa} disabled={mfaBusy} size="sm">Set Up 2FA</Button>
                <Button variant="danger-ghost" size="sm" onClick={disableMfa} disabled={mfaBusy}>Disable 2FA</Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {tab === "create" && (
        <Card>
          <CardHeader><CardTitle>Create Account</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={create} className="space-y-3">
              <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="username" required pattern="[a-zA-Z0-9_.-]+" className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
              <input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} placeholder="full name (optional)" className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
              <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="password (min 8 chars)" required minLength={8} className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })} className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40">
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
              <input value={form.org} onChange={(e) => setForm({ ...form, org: e.target.value })} placeholder="organization (optional)" maxLength={64} className="w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40" />
              <Button type="submit" disabled={busy === "create"} className="w-full" size="md">{busy === "create" ? "Creating..." : "Create User"}</Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default memo(Users);
