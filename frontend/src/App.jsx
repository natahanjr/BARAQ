import { lazy, Suspense, useEffect, useState } from "react";
import { Routes, Route, NavLink, Link, useLocation, Navigate } from "react-router";
import { api, authStore } from "./api.js";
import { useRealtime } from "./realtime.js";
import Login from "./pages/Login.jsx";

const Dashboard = lazy(() => import("./pages/Dashboard.jsx"));
const CommandCenter = lazy(() => import("./pages/CommandCenter.jsx"));
const Alerts = lazy(() => import("./pages/Alerts.jsx"));
const AlertDetail = lazy(() => import("./pages/AlertDetail.jsx"));
const Investigation = lazy(() => import("./pages/Investigation.jsx"));
const EntityGraph = lazy(() => import("./pages/EntityGraph.jsx"));
const Events = lazy(() => import("./pages/Events.jsx"));
const Telemetry = lazy(() => import("./pages/Telemetry.jsx"));
const Assistant = lazy(() => import("./pages/Assistant.jsx"));
const Reports = lazy(() => import("./pages/Reports.jsx"));
const Evaluation = lazy(() => import("./pages/Evaluation.jsx"));
const Incidents = lazy(() => import("./pages/Incidents.jsx"));
const System = lazy(() => import("./pages/System.jsx"));
const Users = lazy(() => import("./pages/Users.jsx"));

import {
  DashboardIcon,
  CommandIcon,
  AlertsIcon,
  InvestigationIcon,
  NetworkIcon,
  EventsIcon,
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
} from "./components/icons.jsx";

const NAV = [
  { to: "/command-center", label: "Command Center", icon: CommandIcon, adminOnly: true },
  { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
  { to: "/alerts", label: "Alerts", icon: AlertsIcon },
  { to: "/investigation", label: "Investigation", icon: InvestigationIcon },
  { to: "/entities", label: "Entity Graph", icon: NetworkIcon },
  { to: "/events", label: "Events", icon: EventsIcon },
  { to: "/telemetry", label: "Processes & Network", icon: TelemetryIcon },
  { to: "/assistant", label: "AI Assistant", icon: AssistantIcon },
  { to: "/reports", label: "Reports", icon: ReportsIcon },
  { to: "/incidents", label: "Incidents", icon: IncidentsIcon },
  { to: "/evaluation", label: "Evaluation", icon: EvaluationIcon, adminOnly: true },
  { to: "/system", label: "System", icon: SystemIcon, adminOnly: true },
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
      window.dispatchEvent(new CustomEvent("sentinel:realtime-alert", { detail: msg.payload }));
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

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("light", theme === "light");
    try {
      localStorage.setItem("sentinel-theme", theme);
    } catch {
      /* private mode etc. */
    }
  }, [theme]);

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
      return localStorage.getItem("sentinel-setup-dismissed") === "1";
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
      link: "/system",
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
              localStorage.setItem("sentinel-setup-dismissed", "1");
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

function SentinelLogo() {
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

function Sidebar({ open, onClose, online, activeAlerts, realtimeConnected, user, onLogout }) {
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
          <SentinelLogo />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold tracking-wide text-white">SentinelSOC</p>
            <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500">
              Threat Detection
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
          {NAV.filter((item) => (item.adminOnly ? user?.role === "admin" : true)).map((item) => {
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
          <div className="flex items-center gap-2.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                online ? "bg-emerald-400" : "bg-red-400"
              }`}
            />
            <span className="text-xs font-medium text-slate-500">
              {online ? "System Online" : "Backend Offline"}
            </span>
            <span
              className={`ml-auto rounded-full px-1.5 py-0.5 text-[9px] ${
                online ? "bg-cyan-500/15 text-cyan-400" : "bg-slate-700 text-slate-500"
              }`}
              title={realtimeConnected ? "Live push connected - realtime stream" : "Live push on 15s polling (auto-detects realtime)"}
            >
              {realtimeConnected ? "LIVE" : "15s poll"}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
}

function Topbar({ onMenuClick, online, summary, theme, onToggleTheme }) {
  const location = useLocation();
  const page = NAV.find(
    (n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to))
  )?.label ?? "SentinelSOC";

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

export default function App() {
  const [navOpen, setNavOpen] = useState(false);
  const { status, online, realtimeConnected } = useBackendStatus();
  const [theme, setTheme] = useTheme();
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);

  useEffect(() => {
    // Session may be restored from the httpOnly cookie on reload; an
    // anonymous/expired session simply falls back to the login screen.
    api
      .me()
      .then((res) => setUser(res.user))
      .catch(() => {})
      .finally(() => setAuthReady(true));
  }, []);

  useEffect(() => {
    authStore.user = user;
  }, [user]);

  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("sentinel:logout", onLogout);
    return () => window.removeEventListener("sentinel:logout", onLogout);
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
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/command-center" element={<AdminGate user={user}><CommandCenter /></AdminGate>} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/investigation" element={<Investigation />} />
              <Route path="/entities" element={<EntityGraph />} />
              <Route path="/events" element={<Events />} />
              <Route path="/telemetry" element={<Telemetry />} />
              <Route path="/assistant" element={<Assistant />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/evaluation" element={<AdminGate user={user}><Evaluation /></AdminGate>} />
              <Route path="/system" element={<AdminGate user={user}><System /></AdminGate>} />
              <Route path="/users" element={<AdminGate user={user}><Users /></AdminGate>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
        <footer className="border-t border-white/5 px-6 py-5 text-center text-xs text-slate-600">
          <span className="inline-flex items-center gap-1.5">
            <ShieldIcon className="h-3.5 w-3.5" />
            SentinelSOC · Real-Time Endpoint Security Operations
          </span>
        </footer>
      </div>
    </div>
  );
}
