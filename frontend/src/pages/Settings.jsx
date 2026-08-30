import { memo, useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button, Tabs } from "../components/ui/index.js";

const inputCls = "w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40";

function formatUptime(totalSeconds) {
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = Math.floor(totalSeconds % 60);
  const pad = (n) => String(n).padStart(2, "0");
  return d > 0 ? `${d}d ${pad(h)}h ${pad(m)}m` : `${pad(h)}:${pad(m)}:${pad(s)}`;
}

function UptimeTimer({ uptimeSeconds }) {
  const ref = useRef(null);
  const bootRef = useRef(null);
  useEffect(() => {
    if (bootRef.current === null) bootRef.current = Date.now() - (uptimeSeconds || 0) * 1000;
    const tick = () => {
      const candidate = Date.now() - (uptimeSeconds || 0) * 1000;
      if (candidate < bootRef.current) bootRef.current = candidate;
      const elapsed = Math.max(0, Math.floor((Date.now() - bootRef.current) / 1000));
      if (ref.current) ref.current.textContent = formatUptime(elapsed);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [uptimeSeconds]);
  return <span ref={ref} className="font-mono tabular-nums" />;
}

function SystemAdminPanel() {
  const [status, setStatus] = useState(null);
  const [dq, setDq] = useState(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = async () => {
    const [st, q] = await Promise.allSettled([api.systemStatus(), api.dataQuality()]);
    if (st.status === "fulfilled") setStatus(st.value);
    if (q.status === "fulfilled") setDq(q.value);
    if (st.status !== "fulfilled") setError(st.reason.message);
  };

  useEffect(() => { refresh(); const t = setInterval(() => { if (!document.hidden) refresh(); }, 10000); return () => clearInterval(t); }, []);

  const run = async (kind, body) => {
    setBusy(kind); setError(""); setMessage("");
    try { const res = await api[kind](body); setMessage(res.message ?? "Done"); refresh(); }
    catch (e) { setError(e.message); } finally { setBusy(""); }
  };

  const repairDQ = async () => {
    if (!window.confirm("Run data-quality repair?")) return;
    setBusy("dataQualityRepair"); setError(""); setMessage("");
    try { const res = await api.dataQualityRepair({ reason: "manual" }); setMessage(res.triggered === false ? "Repair skipped" : "Repair finished"); refresh(); }
    catch (e) { setError(e.message); } finally { setBusy(""); }
  };

  if (!status) return <Loading label="Loading system status" />;
  const summary = status.summary || {};
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          ["Application", status.application, `v${status.version}`, "var(--accent-cyan)"],
          ["Database", status.database?.includes("postgres") ? "PostgreSQL" : "SQLite", "psycopg3", "var(--fg-primary)"],
          ["Collection", status.collecting ? "ACTIVE" : "IDLE", "15s scheduler", status.collecting ? "var(--status-healthy)" : "var(--severity-critical)"],
          ["Uptime", <UptimeTimer uptimeSeconds={status.uptime_seconds || 0} />, "live", "var(--fg-primary)"],
        ].map(([label, value, sub, color]) => (
          <Card key={label} className="p-4">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{label}</p>
            <p className="mt-1 font-mono text-[15px] font-bold" style={{ color }}>{value}</p>
            <p className="mt-0.5 text-[11px] text-[var(--fg-muted)]">{sub}</p>
          </Card>
        ))}
      </div>

      {message && <div className="rounded-[var(--radius-lg)] border border-[var(--status-healthy-border)] bg-[var(--status-healthy)]/[0.06] p-3 text-[12px] text-[var(--status-healthy)]">{message}</div>}
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <div className="grid gap-5 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Live Collection</CardTitle></CardHeader>
          <CardContent>
            <p className="text-[12px] text-[var(--fg-muted)]">Collect real host telemetry and push through detection pipeline.</p>
            <Button onClick={() => run("collect")} disabled={busy === "collect"} size="sm" className="mt-4 w-full">{busy === "collect" ? "Collecting..." : "Collect Live Data"}</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Current KPIs</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {[
              ["Security Score", summary.security_score?.toFixed(1), "var(--accent-cyan)"],
              ["Total Events", summary.total_events?.toLocaleString(), "var(--fg-primary)"],
              ["Active Alerts", summary.active_alerts, "var(--severity-high)"],
              ["Critical Threats", summary.critical_threats, "var(--severity-critical)"],
              ["Anomalies (ML)", summary.anomalies_detected, "var(--accent-violet)"],
              ["Events Last Hour", summary.events_last_hour, "var(--fg-primary)"],
              ["System Status", summary.system_status, "var(--status-healthy)"],
            ].map(([k, v, c]) => (
              <div key={k} className="flex items-center justify-between rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
                <span className="text-[12px] text-[var(--fg-muted)]">{k}</span>
                <span className="text-[12px] font-semibold" style={{ color: c }}>{v ?? "—"}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>Data Quality</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
              <p className="text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Status</p>
              <p className="mt-0.5 text-[13px] font-semibold text-[var(--fg-primary)]">{dq?.current?.status ?? "—"}</p>
            </div>
            <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
              <p className="text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Corruption Rate</p>
              <p className="mt-0.5 text-[13px] font-semibold text-[var(--fg-primary)]">{dq?.current?.corruption_rate != null ? `${(dq.current.corruption_rate * 100).toFixed(1)}%` : "—"}</p>
            </div>
            <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
              <p className="text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Valid / Corrupted</p>
              <p className="mt-0.5 text-[13px] font-semibold text-[var(--fg-primary)]">{dq?.current ? `${dq.current.valid} / ${dq.current.corrupted}` : "—"}</p>
            </div>
          </div>
          {dq?.current?.reasons && Object.keys(dq.current.reasons).length > 0 && (
            <div className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
              <p className="text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-1">Top Reasons</p>
              {Object.entries(dq.current.reasons).slice(0, 3).map(([reason, count]) => (
                <div key={reason} className="flex justify-between text-[12px]"><span className="text-[var(--fg-secondary)]">{reason}</span><span className="font-mono text-[var(--fg-muted)]">{count}</span></div>
              ))}
            </div>
          )}
          <Button variant="secondary" size="sm" onClick={repairDQ} disabled={busy === "dataQualityRepair"}>Run Repair</Button>
        </CardContent>
      </Card>
    </div>
  );
}

function TuningPanel() {
  const [fp, setFp] = useState(null);
  const [groups, setGroups] = useState(null);
  useEffect(() => {
    api.fpAnalysis().then(setFp).catch(() => {});
    api.alertGroups().then(setGroups).catch(() => {});
  }, []);

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>False-Positive Analysis</CardTitle></CardHeader>
        <CardContent>
          {!fp ? <p className="text-[12px] text-[var(--fg-muted)]">Loading...</p> : fp.items.length === 0 ? (
            <p className="text-[12px] text-[var(--fg-muted)]">No alert history yet</p>
          ) : (
            <div className="max-h-80 space-y-2 overflow-y-auto">
              {fp.items.map((item) => (
                <div key={item.rule} className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{item.rule}</span>
                    <span className="font-mono text-[12px] font-bold" style={{ color: item.fp_candidate_score >= 0.6 ? "var(--severity-critical)" : item.fp_candidate_score >= 0.35 ? "var(--severity-high)" : "var(--status-healthy)" }}>
                      {item.fp_candidate_score.toFixed(2)}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-[var(--fg-muted)]">{item.total} alerts · {item.closed} closed · avg triggers {item.avg_trigger_count}</p>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Repeated Detections</CardTitle></CardHeader>
        <CardContent>
          {!groups ? <p className="text-[12px] text-[var(--fg-muted)]">Loading...</p> : groups.items.length === 0 ? (
            <p className="text-[12px] text-[var(--fg-muted)]">No open alerts</p>
          ) : (
            <div className="max-h-80 space-y-2 overflow-y-auto">
              {groups.items.slice(0, 20).map((g) => (
                <div key={`${g.rule}-${g.host}-${g.user}`} className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{g.rule}</span>
                    <Badge severity="info" size="sm">×{g.count}</Badge>
                  </div>
                  <p className="mt-1 text-[11px] text-[var(--fg-muted)]">host {g.host || "?"} · {g.trigger_count} triggers</p>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SuppressionPanel() {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState({ rule: "", host: "*", user: "*", reason: "", expires_hours: 168 });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refresh = () => api.listSuppressions().then((r) => setRules(r.items || [])).catch(() => {});
  useEffect(() => { refresh(); }, []);

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setMessage(""); setError("");
    try {
      await api.createSuppression({ rule: form.rule.trim(), host: form.host.trim() || "*", user: form.user.trim() || "*", reason: form.reason.trim(), expires_hours: Number(form.expires_hours) || 168 });
      setMessage(`Suppression created`); setForm({ rule: "", host: "*", user: "*", reason: "", expires_hours: 168 }); refresh();
    } catch (err) { setError(err.message); } finally { setBusy(false); }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this suppression?")) return;
    try { await api.deleteSuppression(id); refresh(); } catch (err) { setError(err.message); }
  };

  return (
    <Card>
      <CardHeader><CardTitle>Alert Suppression</CardTitle></CardHeader>
      <CardContent>
        <p className="text-[12px] text-[var(--fg-muted)] mb-4">Declare expected behaviour to suppress findings.</p>
        <form onSubmit={submit} className="grid gap-2 sm:grid-cols-2">
          <input required placeholder="Rule id" value={form.rule} onChange={(e) => setForm({ ...form, rule: e.target.value })} className={inputCls} />
          <div className="grid grid-cols-2 gap-2">
            <input placeholder="Host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} className={inputCls} />
            <input placeholder="User" value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} className={inputCls} />
          </div>
          <input placeholder="Reason" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className={`${inputCls} sm:col-span-2`} />
          <div className="sm:col-span-2 flex items-end gap-2">
            <input type="number" min="0" value={form.expires_hours} onChange={(e) => setForm({ ...form, expires_hours: e.target.value })} className={`${inputCls} w-28`} title="Expiry hours" />
            <Button type="submit" disabled={busy} size="sm">{busy ? "Creating..." : "Create"}</Button>
          </div>
        </form>
        {message && <p className="mt-2 text-[12px] text-[var(--status-healthy)]">{message}</p>}
        {error && <p className="mt-2 text-[12px] text-[var(--severity-critical)]">{error}</p>}
        {rules.length > 0 && (
          <div className="mt-3 max-h-48 space-y-1.5 overflow-y-auto">
            {rules.map((r) => (
              <div key={r.id} className="flex items-center gap-2 rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-[12px] font-semibold text-[var(--fg-primary)]">{r.rule} <span className="text-[var(--fg-muted)]">· {r.host}/{r.user}</span></p>
                  <p className="text-[11px] text-[var(--fg-muted)]">{r.reason || "no reason"} · suppressed {r.suppressed_count || 0}×</p>
                </div>
                <Button variant="danger-ghost" size="xs" onClick={() => remove(r.id)}>Remove</Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AccountCard({ me }) {
  if (!me) return null;
  return (
    <Card>
      <CardHeader><CardTitle>Account</CardTitle></CardHeader>
      <CardContent>
        <dl className="space-y-2">
          {[
            ["Username", me.username],
            ["Full Name", me.full_name || "—"],
            ["Role", me.role],
            ["Organization", me.org || "—"],
            ["Created", me.created_at ? new Date(me.created_at).toLocaleDateString() : "—"],
            ["2FA", me.totp_enabled ? "ON" : "OFF"],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center justify-between rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-2">
              <span className="text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{k}</span>
              <span className="text-[13px] font-semibold text-[var(--fg-primary)]">{v}</span>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function RenameCard({ onDone }) {
  const [form, setForm] = useState({ current_password: "", new_username: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setMessage(""); setError("");
    try { const u = await api.renameAccount(form.current_password, form.new_username.trim()); setMessage(`Renamed to "${u.username}"`); setForm({ current_password: "", new_username: "" }); onDone(u); }
    catch (err) { setError(err.message); } finally { setBusy(false); }
  };

  return (
    <Card>
      <CardHeader><CardTitle>Rename Account</CardTitle></CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <input type="password" required placeholder="Current password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} className={inputCls} />
          <input required minLength={3} placeholder="New username" value={form.new_username} onChange={(e) => setForm({ ...form, new_username: e.target.value })} className={inputCls} />
          {message && <p className="text-[12px] text-[var(--status-healthy)]">{message}</p>}
          {error && <p className="text-[12px] text-[var(--severity-critical)]">{error}</p>}
          <Button type="submit" disabled={busy} size="sm" className="w-full">{busy ? "Renaming..." : "Rename"}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

function PasswordCard() {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setMessage(""); setError("");
    try {
      if (form.new_password !== form.confirm) { setError("Passwords don't match"); return; }
      await api.changePassword(form.current_password, form.new_password); setMessage("Password updated"); setForm({ current_password: "", new_password: "", confirm: "" });
    } catch (err) { setError(err.message); } finally { setBusy(false); }
  };

  return (
    <Card>
      <CardHeader><CardTitle>Change Password</CardTitle></CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-3">
          <input type="password" required placeholder="Current password" value={form.current_password} onChange={(e) => setForm({ ...form, current_password: e.target.value })} className={inputCls} />
          <input type="password" required minLength={8} placeholder="New password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} className={inputCls} />
          <input type="password" required minLength={8} placeholder="Confirm new password" value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} className={inputCls} />
          {message && <p className="text-[12px] text-[var(--status-healthy)]">{message}</p>}
          {error && <p className="text-[12px] text-[var(--severity-critical)]">{error}</p>}
          <Button type="submit" disabled={busy} size="sm" className="w-full">{busy ? "Updating..." : "Update Password"}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

function MfaCard({ enabled, onChanged }) {
  const [state, setState] = useState("idle");
  const [secret, setSecret] = useState("");
  const [otpauth, setOtpauth] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const start = async () => { setError(""); try { const res = await api.mfaSetup(); setSecret(res.secret); setOtpauth(res.otpauth_url); setState("confirm"); } catch (err) { setError(err.message); } };
  const confirm = async () => { setBusy(true); setError(""); try { await api.mfaConfirm(code.trim()); setMessage("2FA enabled"); setState("idle"); setCode(""); onChanged(); } catch (err) { setError(err.message); } finally { setBusy(false); } };
  const disable = async () => { const next = window.prompt("Enter authenticator code to disable:"); if (!next) return; setBusy(true); try { await api.mfaDisable(next.trim()); setMessage("2FA disabled"); onChanged(); } catch (err) { setError(err.message); } finally { setBusy(false); } };

  if (state === "confirm") {
    return (
      <Card>
        <CardHeader><CardTitle>Two-Factor Authentication</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-[12px] text-[var(--fg-muted)]">Scan with your authenticator app</p>
          {otpauth ? (
            <div className="mx-auto flex max-w-[180px] justify-center rounded-[var(--radius-lg)] bg-white p-2">
              <img src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauth)}`} alt="QR" className="h-full w-full" />
            </div>
          ) : <pre className="rounded-[var(--radius-md)] bg-[var(--bg-inset)] p-3 text-center font-mono text-[12px] text-[var(--status-healthy)]">{secret}</pre>}
          <p className="break-all text-[11px] text-[var(--fg-muted)]">Manual: <span className="font-mono text-[var(--fg-secondary)]">{secret}</span></p>
          <input value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))} placeholder="6-digit code" inputMode="numeric" className={`${inputCls} text-center font-mono tracking-[0.4em]`} />
          <div className="flex gap-2">
            <Button onClick={confirm} disabled={code.length < 6 || busy} size="sm" className="flex-1">Activate</Button>
            <Button variant="ghost" size="sm" onClick={() => setState("idle")}>Cancel</Button>
          </div>
          {error && <p className="text-[12px] text-[var(--severity-critical)]">{error}</p>}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader><CardTitle>Two-Factor Authentication</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-[12px] text-[var(--fg-muted)]">Add TOTP-based 2FA (RFC 6238)</p>
        {enabled ? (
          <>
            <Badge severity="info" size="sm">2FA is ON</Badge>
            <Button variant="danger-ghost" size="sm" onClick={disable} disabled={busy} className="w-full">Disable 2FA</Button>
          </>
        ) : (
          <Button onClick={start} size="sm" className="w-full">Set Up 2FA</Button>
        )}
        {message && <p className="text-[12px] text-[var(--status-healthy)]">{message}</p>}
        {error && <p className="text-[12px] text-[var(--severity-critical)]">{error}</p>}
      </CardContent>
    </Card>
  );
}

function PreferencesCard() {
  const [theme, setTheme] = useState(() => {
    try { const s = localStorage.getItem("baraq-theme"); if (s === "light" || s === "dark") return s; } catch {}
    return document.documentElement.classList.contains("light") ? "light" : "dark";
  });

  const toggle = (next) => {
    setTheme(next);
    try { localStorage.setItem("baraq-theme", next); } catch {}
    document.documentElement.classList.toggle("light", next === "light");
    window.dispatchEvent(new CustomEvent("baraq:theme-change", { detail: next }));
  };

  return (
    <Card>
      <CardHeader><CardTitle>Preferences</CardTitle></CardHeader>
      <CardContent>
        <div className="flex items-center justify-between rounded-[var(--radius-md)] bg-[var(--bg-inset)] px-3 py-3">
          <div>
            <p className="text-[13px] font-medium text-[var(--fg-primary)]">Theme</p>
            <p className="text-[11px] text-[var(--fg-muted)]">{theme === "light" ? "Light" : "Dark"}</p>
          </div>
          <Button variant="ghost" size="xs" onClick={() => toggle(theme === "light" ? "dark" : "light")}>
            {theme === "light" ? "🌙" : "☀️"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function Settings({ user, onUserChange }) {
  const [me, setMe] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("system");
  const isAdmin = user?.role === "admin";

  const refresh = () => api.me().then((res) => setMe(res.user)).catch((err) => setError(err.message));
  useEffect(() => { refresh(); }, []);

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Settings"
        subtitle={isAdmin ? "System operations, account, security and preferences" : "Account, security and preferences"}
      />

      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <Tabs
        tabs={isAdmin ? [
          { id: "system", label: "System" },
          { id: "tuning", label: "Tuning" },
          { id: "account", label: "Account" },
        ] : [
          { id: "account", label: "Account" },
        ]}
        active={tab}
        onChange={setTab}
      />

      {isAdmin && tab === "system" && <SystemAdminPanel />}
      {isAdmin && tab === "tuning" && (
        <div className="space-y-5">
          <TuningPanel />
          <SuppressionPanel />
        </div>
      )}
      {tab === "account" && (
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-5">
            <AccountCard me={me} />
            <PreferencesCard />
          </div>
          <div className="space-y-5">
            <RenameCard onDone={(u) => { setMe(u); onUserChange?.(u); }} />
            <PasswordCard />
            <MfaCard enabled={me?.totp_enabled ?? false} onChanged={refresh} />
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(Settings);
