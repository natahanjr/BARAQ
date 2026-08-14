import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { Routes, Route, NavLink, Link, useLocation, Navigate } from "react-router";
import { api, authStore } from "./api.js";
import { useRealtime } from "./realtime.js";
import Login from "./pages/Login.jsx";

const Dashboard = lazy(() => import("./pages/Dashboard.jsx"));
const Alerts = lazy(() => import("./pages/Alerts.jsx"));
const AlertDetail = lazy(() => import("./pages/AlertDetail.jsx"));
const Investigation = lazy(() => import("./pages/Investigation.jsx"));
const EntityGraph = lazy(() => import("./pages/EntityGraph.jsx"));
const Telemetry = lazy(() => import("./pages/Telemetry.jsx"));
const Assistant = lazy(() => import("./pages/Assistant.jsx"));
const Reports = lazy(() => import("./pages/Reports.jsx"));
const Evaluation = lazy(() => import("./pages/Evaluation.jsx"));
const Incidents = lazy(() => import("./pages/Incidents.jsx"));
const Endpoints = lazy(() => import("./pages/Endpoints.jsx"));
const AgentSetup = lazy(() => import("./pages/AgentSetup.jsx"));
const Users = lazy(() => import("./pages/Users.jsx"));
const Settings = lazy(() => import("./pages/Settings.jsx"));

import {
  DashboardIcon,
  AlertsIcon,
  NetworkIcon,
  TelemetryIcon,
  AssistantIcon,
  ReportsIcon,
  EvaluationIcon,
  SystemIcon,
  UsersIcon,
  IncidentsIcon,
  LogoutIcon,
  MenuIcon,
  ShieldIcon,
  SunIcon,
  MoonIcon,
  EndpointIcon,
  AgentIcon,
} from "./components/icons.jsx";

const NAV = [
  { section: "Operations" },
  { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
  { to: "/alerts", label: "Alerts", icon: AlertsIcon },
  { to: "/entities", label: "Entity Graph", icon: NetworkIcon },
  { to: "/telemetry", label: "Telemetry", icon: TelemetryIcon },
  { to: "/assistant", label: "AI Assistant", icon: AssistantIcon },
  { to: "/reports", label: "Reports", icon: ReportsIcon },
  { to: "/incidents", label: "Incidents", icon: IncidentsIcon },
  { to: "/evaluation", label: "Evaluation", icon: EvaluationIcon, adminOnly: true },
  { to: "/endpoints", label: "Endpoints", icon: EndpointIcon, adminOnly: true },
  { to: "/agent-setup", label: "Agent Setup", icon: AgentIcon },
  { section: "System" },
  { to: "/settings", label: "Settings", icon: SystemIcon },
  { to: "/users", label: "Users & Audit", icon: UsersIcon, adminOnly: true },
];

function useBackendStatus() {
  const [status, setStatus] = useState(null);
  const [online, setOnline] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const check = () =>
      api
        .systemStatus()
        .then((s) => {
          if (cancelled) return;
          setStatus(s);
          setOnline(true);
        })
        .catch(() => {
          if (!cancelled) setOnline(false);
        });
    check();
    const timer = setInterval(check, 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const realtimeConnected = useRealtime((msg) => {
    if (msg.type === "status" && msg.payload?.summary) {
      setStatus((prev) => ({ ...(prev || {}), summary: msg.payload.summary }));
      setOnline(true);
    } else if (msg.type === "alert") {
      setOnline(true);
      window.dispatchEvent(new CustomEvent("baraq:realtime-alert", { detail: msg.payload }));
    }
  });

  return { status, online, realtimeConnected };
}

function useTheme() {
  const [theme, setTheme] = useState(() =>
    typeof document !== "undefined" && document.documentElement.classList.contains("light")
      ? "light"
      : "dark"
  );

  // Keep the latest theme visible to the event listener below (Settings page
  // can toggle the theme too and must stay in sync with this component).
  const themeRef = useRef(theme);
  useEffect(() => {
    themeRef.current = theme;
  }, [theme]);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("light", theme === "light");
    try {
      localStorage.setItem("baraq-theme", theme);
    } catch {
      /* private mode etc. */
    }
  }, [theme]);

  useEffect(() => {
    const onThemeChange = (e) => {
      const next = e.detail;
      if (next && next !== themeRef.current) setTheme(next);
    };
    window.addEventListener("baraq:theme-change", onThemeChange);
    return () => window.removeEventListener("baraq:theme-change", onThemeChange);
  }, []);

  return [theme, setTheme];
}

function AdminGate({ user, children }) {
  if (user?.role === "admin") return children;
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-3 text-center">
      <ShieldIcon className="h-10 w-10 text-slate-600" />
      <p className="text-base font-semibold text-slate-300">Access denied</p>
      <p className="max-w-sm text-sm text-slate-500">
        This area requires administrator privileges. Contact your administrator if you need access.
      </p>
    </div>
  );
}

function SetupBanner({ setup, user, setNavOpen }) {
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem("baraq-setup-dismissed") === "1";
    } catch {
      return false;
    }
  });

  if (!setup || dismissed || user?.role !== "admin") return null;

  const items = [];
  if (!setup.credentials_configured) {
    items.push({
      key: "credentials",
      text: "Default admin password and API keys are still in use",
      link: "/users",
      label: "Change credentials",
    });
  }
  if (!setup.ml_trained) {
    items.push({
      key: "ml",
      text: "The ML detection model has not been trained yet",
      link: "/settings",
      label: "Train model",
    });
  }
  if (!items.length) return null;

  return (
    <div className="border-b border-amber-500/30 bg-gradient-to-r from-amber-500/15 via-amber-500/10 to-amber-500/15 px-4 py-3 sm:px-6 lg:px-8">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-amber-200">
          <span className="font-semibold uppercase tracking-wider text-amber-400">
            Setup checklist
          </span>
          {items.map((item, idx) => (
            <Link
              key={item.key}
              to={item.link}
              onClick={() => setNavOpen(false)}
              className={`inline-flex items-center gap-1.5 ${idx > 0 ? "sm:border-l sm:border-amber-500/25 sm:pl-4" : ""}`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              {item.text} · {item.label} →
            </Link>
          ))}
        </div>
        <button
          type="button"
          onClick={() => {
            try {
              localStorage.setItem("baraq-setup-dismissed", "1");
            } catch {
              /* ignore */
            }
            setDismissed(true);
          }}
          className="rounded-md px-2 py-1 text-xs text-amber-300 transition-colors hover:bg-amber-500/20"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

function BARAQLogo() {
  return (
    <svg className="h-10 w-10" viewBox="0 0 64 64">
      <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#06b6d4" />
          <stop offset="100%" stopColor="#0e7490" />
        </linearGradient>
        <linearGradient id="centerGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#34d399" />
          <stop offset="100%" stopColor="#059669" />
        </linearGradient>
      </defs>
      <path
        d="M32 6 L52 12 L52 28 Q52 42 32 52 Q12 42 12 28 L12 12 Z"
        fill="url(#shieldGradient)"
        opacity="0.9"
      />
      <path
        d="M32 10 L48 15 L48 28 Q48 38 32 46 Q16 38 16 28 L16 15 Z"
        fill="none"
        stroke="#22d3ee"
        strokeWidth="1.2"
        opacity="0.6"
      />
      <circle cx="32" cy="28" r="6" fill="url(#centerGradient)" opacity="0.85" />
      <circle cx="32" cy="28" r="3.5" fill="#34d399" />
      <path
        d="M28.5 28 L31 30.5 L35.5 25.5"
        stroke="white"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Sidebar({ open, onClose, online, activeAlerts, realtimeConnected, user, onLogout, org, onOrg, orgOptions }) {
  const location = useLocation();

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-slate-800/60 bg-gradient-to-b from-slate-950 via-slate-950 to-slate-900/80 transition-transform duration-200 lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        {/* Brand */}
        <div className="flex items-center gap-3 px-5 pb-5 pt-6">
          <BARAQLogo />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-wide text-white">BARAQ</p>
            <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">
              Threat Detection
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
          {NAV.filter(
            (item) => !item.to || (item.adminOnly ? user?.role === "admin" : true),
          ).map((item) => {
            if (!item.to) {
              return (
                <p
                  key={item.section}
                  className="pb-1 pl-3.5 pt-4 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600 first:pt-0"
                >
                  {item.section}
                </p>
              );
            }
            const isActive =
              item.end
                ? location.pathname === item.to
                : location.pathname.startsWith(item.to);
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onClose}
                className={`group relative flex items-center gap-3 rounded-lg px-3.5 py-2 text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "border border-cyan-500/25 bg-gradient-to-r from-cyan-500/20 to-cyan-500/5 text-cyan-200 shadow-[0_0_18px_-6px_rgba(34,211,238,0.45)]"
                    : "border border-transparent text-slate-500 hover:bg-white/[0.03] hover:text-slate-300"
                }`}
              >
                <Icon className={`h-[18px] w-[18px] shrink-0 ${isActive ? "text-cyan-400" : "text-slate-600 group-hover:text-slate-400"}`} />
                <span className="truncate">{item.label}</span>
                {item.to === "/alerts" && activeAlerts > 0 && (
                  <span className="ml-auto rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold text-red-400">
                    {activeAlerts}
                  </span>
                )}
                {isActive && (
                  <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-cyan-400" />
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Footer status */}
        <div className="space-y-3 border-t border-white/5 px-5 py-4">
          {user && (
            <>
              {user.role === "admin" && orgOptions.length > 0 && (
                <label className="block">
                  <span className="mb-1 block text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Organization
                  </span>
                  <select
                    value={org}
                    onChange={(e) => onOrg(e.target.value)}
                    className="w-full rounded-lg border border-slate-700/70 bg-slate-900/80 px-2.5 py-1.5 text-xs font-medium text-slate-200 outline-none transition-colors focus:border-cyan-500/60"
                    title="Narrow the whole console to one organization (admins)"
                  >
                    <option value="">All organizations</option>
                    {orgOptions.map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <div className="flex items-center gap-2.5">
                <span
                  className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                    user.role === "admin" ? "bg-violet-400" : "bg-cyan-400"
                  }`}
                />
                <span className="min-w-0 flex-1 truncate text-xs font-medium text-slate-200">
                  {user.username}
                </span>
                <span className="rounded-full bg-white/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-slate-400">
                  {user.role}
                </span>
                {user.role !== "admin" && user.org ? (
                  <span
                    className="max-w-[90px] truncate rounded-full bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-semibold text-cyan-300"
                    title={`Organization: ${user.org}`}
                  >
                    {user.org}
                  </span>
                ) : null}
                <button
                  type="button"
                  onClick={onLogout}
                  aria-label="Log out"
                  title="Log out"
                  className="rounded-md border border-white/10 bg-white/[0.04] p-1.5 text-slate-300 transition-colors hover:border-red-500/40 hover:text-red-400"
                >
                  <LogoutIcon className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="h-px bg-white/5" />
            </>
          )}
        </div>
      </aside>
    </>
  );
}

function Topbar({ onMenuClick, online, summary, theme, onToggleTheme }) {
  const location = useLocation();
  const page = NAV.find(
    (n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to))
  )?.label ?? "BARAQ";

  const score = summary?.security_score ?? 0;
  const scoreClass =
    score >= 70 ? "text-emerald-400" : score >= 40 ? "text-amber-400" : "text-red-400";

  return (
    <header className="sticky top-0 z-20 border-b border-slate-800/50 bg-gradient-to-r from-slate-950/90 via-slate-950/80 to-slate-900/85 px-4 py-3.5 shadow-lg shadow-black/20 backdrop-blur-xl sm:px-6 lg:px-8">
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation"
            className="rounded-lg border border-white/10 bg-white/[0.04] p-2 text-slate-300 transition-colors hover:bg-white/[0.08] lg:hidden"
          >
            <MenuIcon className="h-5 w-5" />
          </button>
          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold tracking-tight text-white sm:text-xl">
              {page}
            </h1>
            <p className="mt-0.5 hidden text-xs text-slate-500 sm:block">
              Real-time endpoint security monitoring
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {summary && (
            <div className="hidden items-center overflow-hidden rounded-md border border-white/5 bg-white/[0.02] md:flex">
              {[
                { label: "Score", value: Math.round(score), cls: scoreClass },
                {
                  label: "Events",
                  value: (summary.total_events ?? 0).toLocaleString(),
                  cls: "text-slate-200",
                },
                { label: "Alerts", value: summary.active_alerts ?? 0, cls: "text-cyan-400" },
              ].map((s, i) => (
                <div
                  key={s.label}
                  className={`flex items-center gap-1.5 px-3 py-1 ${
                    i > 0 ? "border-l border-white/5" : ""
                  }`}
                >
                  <span className={`text-xs font-semibold tabular-nums ${s.cls}`}>{s.value}</span>
                  <span className="text-[9px] font-medium uppercase tracking-wider text-slate-500">
                    {s.label}
                  </span>
                </div>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
            title={theme === "light" ? "Dark mode" : "Light mode"}
            className="rounded-lg border border-white/10 bg-white/[0.04] p-2 text-slate-300 transition-colors hover:bg-white/[0.08]"
          >
            {theme === "light" ? (
              <MoonIcon className="h-5 w-5" />
            ) : (
              <SunIcon className="h-5 w-5" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}

function ForcePasswordChange({ user, onDone, onLogout }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setNotice("");
    if (next !== confirm) {
      setError("New passwords do not match");
      return;
    }
    if (next.length < 8) {
      setError("New password must be at least 8 characters");
      return;
    }
    if (next === current) {
      setError("New password must be different from the current one");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setNotice("Password updated - welcome to BARAQ.");
      setTimeout(onDone, 1200);
    } catch (err) {
      setError(err.message.replace(/^\d+: /, ""));
    } finally {
      setBusy(false);
    }
  };

  const inputCls =
    "w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500";

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <BARAQLogo />
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-wide text-white">BARAQ</h1>
            <p className="mt-1 text-xs font-semibold uppercase tracking-[0.25em] text-amber-400">
              Security · Password change required
            </p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="space-y-4 rounded-2xl border border-amber-500/25 bg-slate-900/60 p-6 shadow-2xl backdrop-blur"
        >
          <p className="rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
            You are signed in with the default bootstrap password for{" "}
            <span className="font-mono text-amber-200">{user.username}</span>.
            Choose a strong new password to continue — you cannot use the
            console until this is done.
          </p>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="pwd-current">
              Current password
            </label>
            <input
              id="pwd-current"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
              autoFocus
              className={inputCls}
              placeholder="Default bootstrap password"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="pwd-new">
              New password <span className="text-slate-600">(min 8 characters)</span>
            </label>
            <input
              id="pwd-new"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              required
              minLength={8}
              className={inputCls}
              placeholder="••••••••"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="pwd-confirm">
              Confirm new password
            </label>
            <input
              id="pwd-confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
              minLength={8}
              className={inputCls}
              placeholder="••••••••"
            />
          </div>

          {error && (
            <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {error}
            </p>
          )}
          {notice && (
            <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-400">
              {notice}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
          >
            {busy ? "Updating password…" : "Change Password & Continue"}
          </button>

          <button
            type="button"
            onClick={onLogout}
            className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200"
          >
            Sign out
          </button>
        </form>
      </div>
    </div>
  );
}

export default function App() {
  const [navOpen, setNavOpen] = useState(false);
  const { status, online, realtimeConnected } = useBackendStatus();
  const [theme, setTheme] = useTheme();
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [org, setOrg] = useState(() => authStore.org || "");
  const [orgOptions, setOrgOptions] = useState([]);

  useEffect(() => {
    // Session may be restored from the httpOnly cookie on reload; an
    // anonymous/expired session simply falls back to the login screen.
    api
      .me()
      .then((res) => setUser(res.user))
      .catch(() => {})
      .finally(() => setAuthReady(true));
  }, []);

  // Admins: build the organization list from operator accounts so the
  // sidebar switcher can narrow the whole console to one tenant.
  useEffect(() => {
    if (user?.role !== "admin") return;
    api
      .users()
      .then((res) => {
        const orgs = [
          ...new Set(
            (res.items || []).map((u) => String(u.org || "").trim()).filter(Boolean),
          ),
        ].sort((a, b) => a.localeCompare(b));
        setOrgOptions(orgs);
        if (org && !orgs.includes(org)) setOrg("");
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const changeOrg = (value) => {
    setOrg(value);
    authStore.org = value;
  };

  useEffect(() => {
    authStore.user = user;
  }, [user]);

  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("baraq:logout", onLogout);
    return () => window.removeEventListener("baraq:logout", onLogout);
  }, []);

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* token already invalid */
    }
    authStore.set(null);
    setUser(null);
  };

  if (!authReady) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950">
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-cyan-400" />
          Checking session…
        </div>
      </div>
    );
  }

  if (!user) {
    return <Login onAuthenticated={setUser} />;
  }

  if (user.must_change_password) {
    return (
      <ForcePasswordChange
        user={user}
        onDone={() => setUser({ ...user, must_change_password: false })}
        onLogout={logout}
      />
    );
  }

  return (
    <div className="min-h-screen bg-[var(--app-bg)] text-slate-200">
        <Sidebar
          open={navOpen}
          onClose={() => setNavOpen(false)}
          online={online}
          realtimeConnected={realtimeConnected}
          activeAlerts={status?.summary?.active_alerts ?? 0}
          user={user}
          onLogout={logout}
          org={org}
          onOrg={changeOrg}
          orgOptions={user?.role === "admin" ? orgOptions : []}
        />
        <div className="flex min-h-screen flex-col lg:pl-64">
          <Topbar
            onMenuClick={() => setNavOpen(true)}
            online={online}
            summary={status?.summary}
            theme={theme}
            onToggleTheme={() => setTheme(theme === "light" ? "dark" : "light")}
          />
          <SetupBanner setup={status?.setup} user={user} setNavOpen={setNavOpen} />
        <main className="fade-in mx-auto w-full max-w-[1400px] flex-1 px-4 py-7 sm:px-6 lg:px-8">
          <Suspense
            fallback={
              <div className="flex min-h-[40vh] items-center justify-center">
                <div className="flex items-center gap-3 text-sm text-slate-400">
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-cyan-400" />
                  Loading page…
                </div>
              </div>
            }
          >
            <Routes key={`${user.role}:${org}`}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/investigation" element={<Investigation />} />
              <Route path="/entities" element={<EntityGraph />} />
              <Route path="/telemetry" element={<Telemetry />} />
              <Route path="/assistant" element={<Assistant />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/evaluation" element={<AdminGate user={user}><Evaluation /></AdminGate>} />
              <Route path="/endpoints" element={<AdminGate user={user}><Endpoints /></AdminGate>} />
              <Route path="/agent-setup" element={<AgentSetup />} />
              <Route path="/users" element={<AdminGate user={user}><Users /></AdminGate>} />
              <Route path="/settings" element={<Settings user={user} onUserChange={setUser} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
        <footer className="border-t border-white/5 px-6 py-5 text-center text-xs text-slate-600">
          <span className="inline-flex items-center gap-1.5">
            <ShieldIcon className="h-3.5 w-3.5" />
            BARAQ · Real-Time Endpoint Security Operations
          </span>
        </footer>
      </div>
    </div>
  );
}
