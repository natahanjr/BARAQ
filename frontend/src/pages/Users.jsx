import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const ROLE_STYLES = {
  admin: "rounded-lg border border-violet-500/30 bg-violet-500/[0.1] px-2.5 py-1 text-xs font-bold text-violet-400",
  analyst: "rounded-lg border border-cyan-500/30 bg-cyan-500/[0.1] px-2.5 py-1 text-xs font-bold text-cyan-400",
};

export default function Users() {
  const [users, setUsers] = useState([]);
  const [audit, setAudit] = useState([]);
  const [me, setMe] = useState(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "analyst", full_name: "", org: "" });

  const [mfaState, setMfaState] = useState("idle");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaOtpauth, setMfaOtpauth] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaBusy, setMfaBusy] = useState(false);

  const startMfa = async () => {
    setError("");
    setMessage("");
    setMfaBusy(true);
    try {
      const res = await api.mfaSetup();
      setMfaSecret(res.secret);
      setMfaOtpauth(res.otpauth_url);
      setMfaState("confirm");
    } catch (err) {
      setError(err.message);
    } finally {
      setMfaBusy(false);
    }
  };

  const confirmMfa = async () => {
    setError("");
    setMessage("");
    setMfaBusy(true);
    try {
      await api.mfaConfirm(mfaCode.trim());
      setMessage("Two-factor authentication enabled");
      setMfaState("idle");
      setMfaSecret("");
      setMfaOtpauth("");
      setMfaCode("");
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setMfaBusy(false);
    }
  };

  const disableMfa = async () => {
    const next = window.prompt("Enter your current authenticator code to disable 2FA:");
    if (!next) return;
    setError("");
    setMessage("");
    setMfaBusy(true);
    try {
      await api.mfaDisable(next.trim());
      setMessage("Two-factor authentication disabled");
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setMfaBusy(false);
    }
  };

  const refresh = useCallback(() => {
    api.users().then((r) => setUsers(r.items || [])).catch(() => {});
    api.me().then(setMe).catch(() => {});
    api.audit({ limit: 200 }).then((r) => setAudit(r.items || [])).catch(() => {});
  }, []);

  const clearAudit = async () => {
    const next = window.confirm(
      "Clear the entire audit trail? A report will be generated first as the permanent record of all activity.",
    );
    if (!next) return;
    setError("");
    setMessage("");
    setBusy("clearAudit");
    try {
      const res = await api.clearAudit();
      setMessage(`${res.message} Report: ${res.report?.file_path?.split(/[\\/]/).pop() ?? "none"}`);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [refresh]);

  const create = async (e) => {
    e.preventDefault();
    setBusy("create");
    setError("");
    setMessage("");
    try {
      const u = await api.createUser(form);
      setMessage(`User "${u.username}" created (${u.role})`);
      setForm({ username: "", password: "", role: "analyst", full_name: "", org: "" });
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const toggleActive = async (u) => {
    setBusy(`active:${u.id}`);
    setError("");
    try {
      await api.updateUser(u.id, { is_active: !u.is_active });
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const approve = async (u) => {
    setBusy(`approve:${u.id}`);
    setError("");
    setMessage("");
    try {
      const updated = await api.approveUser(u.id);
      setMessage(`Account "${updated.username}" verified and activated.`);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const reject = async (u) => {
    if (!window.confirm(`Reject the registration of "${u.username}"?`)) return;
    setBusy(`reject:${u.id}`);
    setError("");
    try {
      const updated = await api.rejectUser(u.id);
      setMessage(`Registration of "${updated.username}" rejected.`);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const resetPassword = async (u) => {
    const next = window.prompt(`New password for "${u.username}" (min 8 chars):`);
    if (!next) return;
    setBusy(`pwd:${u.id}`);
    setError("");
    try {
      await api.updateUser(u.id, { password: next });
      setMessage(`Password reset for "${u.username}"`);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  const remove = async (u) => {
    if (!window.confirm(`Delete account "${u.username}"? This cannot be undone.`)) return;
    setBusy(`del:${u.id}`);
    setError("");
    try {
      await api.deleteUser(u.id);
      setMessage(`Account "${u.username}" deleted`);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="space-y-6 pb-12">
      <div className="flex items-center justify-between rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div>
          <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Users & Audit</h1>
          <p className="mt-1 text-[13px] text-slate-400">Manage operator accounts and review the audit trail</p>
        </div>
        <button
          type="button"
          onClick={refresh}
          className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3.5 py-2 text-[12px] font-medium text-slate-300 transition-all hover:bg-white/[0.06]"
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2" />
          </svg>
          Refresh
        </button>
      </div>

      {message && (
        <div className="rounded-xl border p-4" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)" }}>
          <p className="text-sm font-medium" style={{ color: "var(--success-text, #065f46)" }}>{message}</p>
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Operator Accounts <span className="ml-1 text-xs font-normal normal-case tracking-normal text-slate-500">({users.length})</span>
          </h3>
          <div className="space-y-2">
            {users.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-white/[0.06] bg-white/[0.02] px-4 py-10 text-center">
                <svg className="mb-3 h-8 w-8 text-slate-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                  <circle cx="9" cy="7" r="4" />
                  <line x1="19" y1="8" x2="19" y2="14" />
                  <line x1="22" y1="11" x2="16" y2="11" />
                </svg>
                <p className="text-[13px] font-medium text-slate-400">No users yet</p>
                <p className="mt-1 text-xs text-slate-600">Create an account to get started</p>
              </div>
            ) : (
              users.map((u) => (
                <div
                  key={u.id}
                  className="flex items-center justify-between gap-2 rounded-xl border border-white/[0.04] bg-white/[0.02] px-3.5 py-3 transition-all hover:border-white/[0.08]"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate font-mono text-[13px] font-semibold text-slate-100">
                        {u.username}
                      </span>
                      <span className={ROLE_STYLES[u.role] || ROLE_STYLES.analyst}>
                        {u.role}
                      </span>
                      {u.totp_enabled && (
                        <span className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.1] px-2.5 py-1 text-xs font-bold text-emerald-400" title="Two-factor authentication enabled">
                          2FA
                        </span>
                      )}
                      {u.registration_status === "pending" && (
                        <span className="rounded-lg border border-amber-500/30 bg-amber-500/[0.1] px-2.5 py-1 text-xs font-bold text-amber-400" title="Awaiting administrator verification">
                          PENDING VERIFICATION
                        </span>
                      )}
                      {u.registration_status === "rejected" && (
                        <span className="rounded-lg border border-rose-500/30 bg-rose-500/[0.1] px-2.5 py-1 text-xs font-bold text-rose-400" title="Registration was rejected">
                          REJECTED
                        </span>
                      )}
                      {!u.is_active && u.registration_status !== "pending" && u.registration_status !== "rejected" && (
                        <span className="rounded-lg border border-rose-500/30 bg-rose-500/[0.1] px-2.5 py-1 text-xs font-bold text-rose-400">
                          DISABLED
                        </span>
                      )}
                      {u.org && (
                        <span
                          className="max-w-[110px] truncate rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-xs font-bold text-slate-300"
                          title={`Organization: ${u.org}`}
                        >
                          {u.org}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 truncate text-xs text-slate-500">
                      {u.full_name || "—"}
                      {u.last_login_at
                        ? ` · last login ${new Date(u.last_login_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`
                        : " · never logged in"}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    {u.registration_status === "pending" ? (
                      <>
                        <button
                          type="button"
                          onClick={() => approve(u)}
                          disabled={busy === `approve:${u.id}`}
                          className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.08] px-2.5 py-1 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/[0.15] disabled:opacity-40"
                          title="Verify this account and activate it"
                        >
                          {busy === `approve:${u.id}` ? "Verifying…" : "Approve"}
                        </button>
                        <button
                          type="button"
                          onClick={() => reject(u)}
                          disabled={busy === `reject:${u.id}`}
                          className="rounded-lg border border-rose-500/30 bg-rose-500/[0.08] px-2.5 py-1 text-xs font-semibold text-rose-400 hover:bg-rose-500/[0.15] disabled:opacity-40"
                          title="Reject this registration"
                        >
                          {busy === `reject:${u.id}` ? "Rejecting…" : "Reject"}
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={() => resetPassword(u)}
                          disabled={busy === `pwd:${u.id}`}
                          className="rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-xs font-semibold text-slate-300 hover:bg-white/[0.06] disabled:opacity-40"
                          title="Reset password"
                        >
                          Pwd
                        </button>
                        <button
                          type="button"
                          onClick={() => toggleActive(u)}
                          disabled={busy === `active:${u.id}`}
                          className={`rounded-lg border px-2.5 py-1 text-xs font-semibold transition-all disabled:opacity-40 ${
                            u.is_active
                              ? "border-amber-500/30 bg-amber-500/[0.08] text-amber-400 hover:bg-amber-500/[0.15]"
                              : "border-emerald-500/30 bg-emerald-500/[0.08] text-emerald-400 hover:bg-emerald-500/[0.15]"
                          }`}
                        >
                          {u.is_active ? "Disable" : "Enable"}
                        </button>
                      </>
                    )}
                    <button
                      type="button"
                      onClick={() => remove(u)}
                      disabled={busy === `del:${u.id}`}
                      className="rounded-lg border border-rose-500/30 bg-rose-500/[0.08] px-2.5 py-1 text-xs font-semibold text-rose-400 hover:bg-rose-500/[0.15] disabled:opacity-40"
                      title="Delete account permanently"
                    >
                      {busy === `del:${u.id}` ? "Deleting…" : "Delete"}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Two-Factor Authentication
          </h3>

          {mfaState === "confirm" ? (
            <div className="space-y-3">
              <div className="rounded-2xl border border-amber-500/20 bg-gradient-to-br from-amber-500/[0.06] to-transparent p-5">
                <p className="mb-3 text-[12px] font-semibold text-amber-300">
                  Scan with your authenticator app (e.g. Google Authenticator, Authy)
                </p>
                {mfaOtpauth ? (
                  <div className="mx-auto flex max-w-[200px] justify-center rounded-xl border border-white/[0.06] bg-white p-3">
                    <img
                      src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(mfaOtpauth)}`}
                      alt="QR code for TOTP setup"
                      className="h-full w-full"
                    />
                  </div>
                ) : (
                  <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-center font-mono text-[13px] text-emerald-300">{mfaSecret}</pre>
                )}
                <p className="mt-3 break-all text-xs text-slate-500">
                  Manual entry: <span className="font-mono text-slate-300">{mfaSecret}</span>
                </p>
              </div>
              <input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.slice(0, 6))}
                placeholder="6-digit verification code"
                inputMode="numeric"
                autoComplete="one-time-code"
                className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-center font-mono text-[13px] tracking-[0.4em] text-slate-200 outline-none placeholder:text-xs placeholder:tracking-normal placeholder:text-slate-500 focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
              />
              <button
                type="button"
                onClick={confirmMfa}
                disabled={mfaCode.length < 6 || mfaBusy}
                className="w-full rounded-xl border border-emerald-500/25 bg-emerald-500/[0.08] px-4 py-3 text-[13px] font-bold text-emerald-400 transition-all hover:bg-emerald-500/[0.15] disabled:opacity-50"
              >
                {mfaBusy ? "Verifying…" : "Activate 2FA"}
              </button>
              <button
                type="button"
                onClick={() => setMfaState("idle")}
                disabled={mfaBusy}
                className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-2.5 text-[12px] font-medium text-slate-400 transition-all hover:bg-white/[0.06] disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-[12px] leading-relaxed text-slate-500">
                Protect this session&apos;s account with a time-based one-time password
                (RFC&nbsp;6238, compatible with Google Authenticator, Authy, 1Password
                and other standard apps).
              </p>
              {me?.totp_enabled ? (
                <div className="flex flex-col gap-2">
                  <p className="rounded-lg border px-4 py-2.5 text-center text-sm font-semibold" style={{ background: "var(--success-bg, #ecfdf5)", borderColor: "var(--success-border, #a7f3d0)", color: "var(--success-text, #065f46)" }}>
                    Two-factor authentication is ON for this account
                  </p>
                  <button
                    type="button"
                    onClick={disableMfa}
                    disabled={mfaBusy}
                    className="w-full rounded-xl border px-4 py-3 text-sm font-semibold transition-all disabled:opacity-50"
                    style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}
                  >
                    Disable 2FA
                  </button>
                </div>
              ) : (
                <div className="flex flex-col gap-2">
                  <button
                    type="button"
                    onClick={startMfa}
                    disabled={mfaBusy}
                    className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-4 py-3 text-[13px] font-bold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
                  >
                    {mfaBusy ? "Working…" : "Set Up 2FA"}
                  </button>
                  <button
                    type="button"
                    onClick={disableMfa}
                    disabled={mfaBusy}
                    className="w-full rounded-xl border border-rose-500/30 bg-rose-500/[0.08] px-4 py-2.5 text-[12px] font-semibold text-rose-400 transition-all hover:bg-rose-500/[0.15] disabled:opacity-50"
                  >
                    Disable 2FA
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Create Account
          </h3>
          <form onSubmit={create} className="space-y-3">
            <input
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder="username (3+ chars)"
              required
              pattern="[a-zA-Z0-9_.-]+"
              className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            />
            <input
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              placeholder="full name (optional)"
              className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            />
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              placeholder="password (min 8 chars)"
              required
              minLength={8}
              className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            />
            <select
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
              className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            >
              <option value="analyst">Analyst (read + investigate)</option>
              <option value="admin">Admin (full control)</option>
            </select>
            <input
              value={form.org}
              onChange={(e) => setForm({ ...form, org: e.target.value })}
              placeholder="organization (e.g. univ-a; blank = platform-wide)"
              maxLength={64}
              className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
            />
            <button
              type="submit"
              disabled={busy === "create"}
              className="w-full rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-5 py-3 text-[13px] font-bold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
            >
              {busy === "create" ? "Creating…" : "Create User"}
            </button>
          </form>
        </div>

        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6 lg:col-span-3">
          <div className="mb-4 flex items-center justify-between gap-2">
            <h3 className="flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
              <span className="h-1 w-1 rounded-full bg-cyan-400" />
              Audit Trail
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-500">
                {audit.length === 0 ? "No activity recorded yet" : `latest ${audit.length}`}
              </span>
              <button
                onClick={clearAudit}
                disabled={busy === "clearAudit" || audit.length === 0}
                className="rounded-lg border border-rose-500/20 bg-rose-500/[0.06] px-3 py-1.5 text-xs font-semibold text-rose-400 hover:bg-rose-500/[0.12] disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busy === "clearAudit" ? "Clearing…" : "Clear History"}
              </button>
            </div>
          </div>
          {audit.length === 0 ? (
            <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-white/[0.06] bg-white/[0.02] px-4 py-12 text-center">
              <svg className="mb-3 h-8 w-8 text-slate-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 8v4l3 3" />
                <circle cx="12" cy="12" r="10" />
              </svg>
              <p className="text-[13px] font-medium text-slate-400">No activity yet</p>
              <p className="mt-1 text-xs text-slate-600">Sign-ins, alert actions, commands and report generations will appear here</p>
            </div>
          ) : (
            <div className="max-h-[480px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-[#0a0a0f]">
                  <tr className="border-b border-white/[0.06] text-xs uppercase tracking-[0.08em] text-slate-500/70">
                    <th className="pb-2 pr-3 text-left font-medium">When</th>
                    <th className="pb-2 pr-3 text-left font-medium">Actor</th>
                    <th className="pb-2 pr-3 text-left font-medium">Action</th>
                    <th className="pb-2 pr-3 text-left font-medium">Entity</th>
                    <th className="pb-2 pr-3 text-left font-medium">Detail</th>
                    <th className="pb-2 text-left font-medium">IP</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((e) => (
                    <tr key={e.id} className="border-b border-white/[0.04] hover:bg-white/[0.02]">
                      <td className="whitespace-nowrap py-2 pr-3 font-mono text-xs text-slate-500">
                        {new Date(e.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </td>
                      <td className="py-2 pr-3 font-mono text-[12px] text-cyan-300">{e.actor}</td>
                      <td className="py-2 pr-3">
                        <span className="rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-xs font-bold text-slate-300">
                          {e.action}
                        </span>
                      </td>
                      <td className="py-2 pr-3 font-mono text-[12px] text-slate-400">
                        {e.entity_type ? `${e.entity_type} ${e.entity_id}` : "—"}
                      </td>
                      <td className="max-w-[320px] truncate py-2 pr-3 text-[12px] text-slate-500">{e.detail || "—"}</td>
                      <td className="py-2 font-mono text-[12px] text-slate-600">{e.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-xs font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}