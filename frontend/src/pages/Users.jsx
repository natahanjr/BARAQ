import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { RefreshIcon } from "../components/icons.jsx";

const ROLE_STYLES = {
  admin: "bg-violet-500/15 text-violet-400",
  analyst: "bg-cyan-500/15 text-cyan-400",
};

export default function Users() {
  const [users, setUsers] = useState([]);
  const [audit, setAudit] = useState([]);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "analyst", full_name: "", org: "" });

  // --- Two-factor authentication (self-service, active session) ---
  const [mfaState, setMfaState] = useState("idle"); // idle | setup | confirm | disabled
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
      <PageHeader
        title="Users & Audit"
        subtitle="Manage operator accounts and review the audit trail"
        actions={
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-800/60 px-3.5 py-2 text-xs font-medium text-slate-300 transition-colors hover:bg-slate-700/60"
          >
            <RefreshIcon className="h-4 w-4" />
            Refresh
          </button>
        }
      />

      {message && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-300">
          ✓ {message}
        </div>
      )}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Users */}
        <Card>
          <h3 className="mb-4 text-base font-semibold text-white">
            Operator Accounts <span className="ml-1 text-xs font-normal text-slate-500">({users.length})</span>
          </h3>
          <div className="space-y-2">
            {users.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-700/60 bg-slate-900/40 px-4 py-5 text-center text-xs text-slate-500">
                No users yet
              </p>
            ) : (
              users.map((u) => (
                <div
                  key={u.id}
                  className="flex items-center justify-between gap-2 rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-mono text-sm font-semibold text-slate-100">
                        {u.username}
                      </span>
                      <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${ROLE_STYLES[u.role] || ROLE_STYLES.analyst}`}>
                        {u.role}
                      </span>
                      {u.totp_enabled && (
                        <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-400" title="Two-factor authentication enabled">
                          2FA
                        </span>
                      )}
                      {!u.is_active && (
                        <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold text-red-400">
                          DISABLED
                        </span>
                      )}
                      {u.org && (
                        <span
                          className="max-w-[110px] truncate rounded-full bg-violet-500/10 px-2 py-0.5 text-[10px] font-semibold text-violet-300"
                          title={`Organization: ${u.org}`}
                        >
                          {u.org}
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 truncate text-[11px] text-slate-500">
                      {u.full_name || "—"}
                      {u.last_login_at
                        ? ` · last login ${new Date(u.last_login_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`
                        : " · never logged in"}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    <button
                      type="button"
                      onClick={() => resetPassword(u)}
                      disabled={busy === `pwd:${u.id}`}
                      className="rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-[10px] font-medium text-slate-300 transition-colors hover:bg-slate-700 disabled:opacity-40"
                      title="Reset password"
                    >
                      Pwd
                    </button>
                    <button
                      type="button"
                      onClick={() => toggleActive(u)}
                      disabled={busy === `active:${u.id}`}
                      className={`rounded-md border px-2 py-1 text-[10px] font-medium transition-colors disabled:opacity-40 ${
                        u.is_active
                          ? "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20"
                          : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                      }`}
                    >
                      {u.is_active ? "Disable" : "Enable"}
                    </button>
                    <button
                      type="button"
                      onClick={() => remove(u)}
                      disabled={busy === `del:${u.id}`}
                      className="rounded-md border border-red-500/40 bg-red-500/10 px-2 py-1 text-[10px] font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-40"
                      title="Delete account permanently"
                    >
                      {busy === `del:${u.id}` ? "Deleting…" : "Delete"}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Two-factor authentication */}
        <Card>
          <h3 className="mb-4 text-base font-semibold text-white">Two-Factor Authentication</h3>

          {mfaState === "confirm" ? (
            <div className="space-y-3">
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
                <p className="mb-2 text-xs font-semibold text-amber-300">
                  Scan with your authenticator app (e.g. Google Authenticator, Authy)
                </p>
                {mfaOtpauth ? (
                  <div className="mx-auto flex max-w-[220px] justify-center rounded-lg border border-slate-700 bg-white p-2">
                    <img
                      src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(mfaOtpauth)}`}
                      alt="QR code for TOTP setup"
                      className="h-full w-full"
                    />
                  </div>
                ) : (
                  <pre className="overflow-x-auto rounded bg-slate-950 p-3 text-center font-mono text-sm text-emerald-300">{mfaSecret}</pre>
                )}
                <p className="mt-3 break-all text-[11px] text-slate-500">
                  Manual entry: <span className="font-mono text-slate-300">{mfaSecret}</span>
                </p>
              </div>
              <input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.slice(0, 6))}
                placeholder="6-digit verification code"
                inputMode="numeric"
                autoComplete="one-time-code"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-center font-mono text-lg tracking-[0.4em] text-slate-100 outline-none placeholder:text-xs placeholder:tracking-normal placeholder:text-slate-600 focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={confirmMfa}
                disabled={mfaCode.length < 6 || mfaBusy}
                className="w-full rounded-lg bg-gradient-to-r from-emerald-600 to-emerald-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-emerald-500 hover:to-emerald-400 disabled:opacity-50"
              >
                {mfaBusy ? "Verifying…" : "Activate 2FA"}
              </button>
              <button
                type="button"
                onClick={() => setMfaState("idle")}
                disabled={mfaBusy}
                className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200 disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-xs leading-relaxed text-slate-500">
                Protect this session&apos;s account with a time-based one-time password
                (RFC&nbsp;6238, compatible with Google Authenticator, Authy, 1Password
                and other standard apps).
              </p>
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={startMfa}
                  disabled={mfaBusy}
                  className="w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
                >
                  {mfaBusy ? "Working…" : "Set Up 2FA"}
                </button>
                <button
                  type="button"
                  onClick={disableMfa}
                  disabled={mfaBusy}
                  className="w-full rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                >
                  Disable 2FA
                </button>
              </div>
            </div>
          )}
        </Card>

        {/* Create user */}
        <Card>
          <h3 className="mb-4 text-base font-semibold text-white">Create Account</h3>
          <form onSubmit={create} className="space-y-3">
            <input
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder="username (3+ chars)"
              required
              pattern="[a-zA-Z0-9_.-]+"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500"
            />
            <input
              value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              placeholder="full name (optional)"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500"
            />
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              placeholder="password (min 8 chars)"
              required
              minLength={8}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500"
            />
            <select
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500"
            >
              <option value="analyst">Analyst (read + investigate)</option>
              <option value="admin">Admin (full control)</option>
            </select>
            <input
              value={form.org}
              onChange={(e) => setForm({ ...form, org: e.target.value })}
              placeholder="organization (e.g. univ-a; blank = platform-wide)"
              maxLength={64}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={busy === "create"}
              className="w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
            >
              {busy === "create" ? "Creating…" : "Create User"}
            </button>
          </form>
        </Card>

        {/* Audit trail */}
        <Card className="lg:col-span-3">
          <div className="mb-4 flex items-center justify-between gap-2">
            <h3 className="text-base font-semibold text-white">Audit Trail</h3>
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-slate-500">
                {audit.length === 0 ? "No activity recorded yet" : `latest ${audit.length}`}
              </span>
              <button
                onClick={clearAudit}
                disabled={busy === "clearAudit" || audit.length === 0}
                className="rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-1 text-[11px] font-semibold text-red-400 transition-colors hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {busy === "clearAudit" ? "Clearing…" : "Clear History"}
              </button>
            </div>
          </div>
          {audit.length === 0 ? (
            <p className="rounded-lg border border-dashed border-slate-700/60 bg-slate-900/40 px-4 py-6 text-center text-xs text-slate-500">
              Sign-ins, alert actions, commands and report generations will appear here.
            </p>
          ) : (
            <div className="max-h-[480px] overflow-y-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-950">
                  <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                    <th className="pb-2 pr-3 font-medium">When</th>
                    <th className="pb-2 pr-3 font-medium">Actor</th>
                    <th className="pb-2 pr-3 font-medium">Action</th>
                    <th className="pb-2 pr-3 font-medium">Entity</th>
                    <th className="pb-2 pr-3 font-medium">Detail</th>
                    <th className="pb-2 font-medium">IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {audit.map((e) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap py-2 pr-3 font-mono text-[11px] text-slate-500">
                        {new Date(e.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </td>
                      <td className="py-2 pr-3 font-mono text-cyan-300">{e.actor}</td>
                      <td className="py-2 pr-3">
                        <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-semibold text-slate-300">
                          {e.action}
                        </span>
                      </td>
                      <td className="py-2 pr-3 font-mono text-slate-400">
                        {e.entity_type ? `${e.entity_type} ${e.entity_id}` : "—"}
                      </td>
                      <td className="max-w-[320px] truncate py-2 pr-3 text-slate-500">{e.detail || "—"}</td>
                      <td className="py-2 font-mono text-slate-600">{e.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
