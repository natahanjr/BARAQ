import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { Routes, Route, NavLink, Link, useLocation, useNavigate, Navigate } from "react-router";
import { api, authStore } from "./api.js";
import { useRealtime } from "./realtime.js";
import BARAQLogo from "./components/BARAQLogo.jsx";
import AssistantPanel from "./components/AssistantPanel.jsx";
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
const RBACenter = lazy(() => import("./pages/RBACenter.jsx"));
const Search = lazy(() => import("./pages/Search.jsx"));
const Automation = lazy(() => import("./pages/Automation.jsx"));
const Dashboards = lazy(() => import("./pages/Dashboards.jsx"));
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
  RiskShieldIcon,
  RulesIcon,
  BoltIcon,
  ActivityIcon,
  SearchIcon,
  BellIcon,
} from "./components/icons.jsx";

const PODS = [
  {
    id: "INTEL",
    title: "INTEL",
    tagline: "The Eyes",
    items: [
      { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
      { to: "/alerts", label: "Alerts", icon: AlertsIcon, badge: "alerts" },
      { to: "/search", label: "Search", icon: ShieldIcon },
      { to: "/telemetry", label: "Telemetry", icon: TelemetryIcon },
      { to: "/dashboards", label: "Dashboards", icon: ActivityIcon },
    ],
  },
  {
    id: "ENGAGE",
    title: "ENGAGE",
    tagline: "The Hands",
    items: [
      { to: "/incidents", label: "Incidents", icon: IncidentsIcon, badge: "incidents" },
      { to: "/entities", label: "Entity Graph", icon: NetworkIcon },
      { to: "/automation", label: "Automation", icon: BoltIcon },
      { to: "/evaluation", label: "Evaluation", icon: EvaluationIcon, adminOnly: true },
      { to: "/rba", label: "Entity Risk", icon: RiskShieldIcon },
    ],
  },
  {
    id: "ADMIN",
    title: "ADMIN",
    tagline: "The Backbone",
    items: [
      { to: "/endpoints", label: "Endpoints", icon: EndpointIcon, adminOnly: true },
      { to: "/agent-setup", label: "Agent Setup", icon: AgentIcon },
      { to: "/users", label: "Users & Audit", icon: UsersIcon, adminOnly: true },
      { to: "/settings", label: "Settings", icon: SystemIcon },
    ],
  },
  {
    id: "AUGMENT",
    title: "AUGMENT",
    tagline: "The Brain",
    items: [
      { to: "/assistant", label: "AI Assistant", icon: AssistantIcon },
      { to: "/reports", label: "Reports", icon: ReportsIcon },
    ],
  },
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
  // Theme preference: "dark" | "light" | "system" (follows the OS). The
  // effective appearance is derived from system only when chosen; analysts
  // can always override per-session from the topbar.
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("baraq-theme") || "system";
    } catch {
      return "system";
    }
  });

  const [systemDark, setSystemDark] = useState(() =>
    typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches,
  );

  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mq) return;
    const onChange = (e) => setSystemDark(e.matches);
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, [theme]);

  const effective = theme === "system" ? (systemDark ? "dark" : "light") : theme;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("light", effective === "light");
    try {
      localStorage.setItem("baraq-theme", theme);
    } catch {
      /* private mode etc. */
    }
  }, [theme, effective]);

  useEffect(() => {
    const onThemeChange = (e) => {
      const next = e.detail;
      if (next === "dark" || next === "light" || next === "system") setTheme(next);
    };
    window.addEventListener("baraq:theme-change", onThemeChange);
    return () => window.removeEventListener("baraq:theme-change", onThemeChange);
  }, []);

  return [theme, setTheme, effective];
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

function Sidebar({
  open,
  onClose,
  online,
  collapsed,
  onToggleCollapsed,
  activeAlerts,
  criticalAlerts,
  openIncidents,
  criticalIncidents,
  user,
  onLogout,
  org,
  onOrg,
  orgOptions,
}) {
  const location = useLocation();

  const navItems = (pod) =>
    pod.items.filter((item) => (item.adminOnly ? user?.role === "admin" : true));

  const badgeFor = (item) => {
    if (item.badge === "alerts") {
      if (!activeAlerts) return null;
      return { count: activeAlerts, critical: criticalAlerts > 0 };
    }
    if (item.badge === "incidents") {
      if (!openIncidents) return null;
      return { count: openIncidents, critical: criticalIncidents > 0 };
    }
    return null;
  };

  const link = (item, mobile) => {
    const isActive =
      item.end ? location.pathname === item.to : location.pathname.startsWith(item.to);
    const Icon = item.icon;
    const badge = badgeFor(item);
    return (
      <NavLink
        key={item.to}
        to={item.to}
        end={item.end}
        onClick={onClose}
        title={collapsed && !mobile ? item.label : undefined}
        className={`group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all duration-150 ${
          isActive
            ? "border border-cyan-400/20 bg-gradient-to-r from-cyan-500/15 via-violet-500/5 to-transparent text-white"
            : "border border-transparent text-slate-400 hover:bg-white/[0.04] hover:text-slate-200"
        } ${collapsed && !mobile ? "justify-center px-0" : ""}`}
      >
        <Icon
          className={`h-[18px] w-[18px] shrink-0 transition-all ${
            isActive
              ? "text-cyan-400 drop-shadow-[0_0_6px_rgba(0,240,255,0.6)]"
              : "text-slate-500 group-hover:text-cyan-300"
          }`}
        />
        {!(collapsed && !mobile) && <span className="truncate">{item.label}</span>}
        {isActive && (
          <span className="absolute left-0 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r-full bg-violet-500 shadow-[0_0_10px_rgba(123,97,255,0.8)]" />
        )}
        {badge && (
          <span
            className={`ml-auto shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold tabular-nums ${
              badge.critical
                ? "badge-critical bg-red-500/20 text-red-400"
                : "bg-slate-600/40 text-slate-400"
            } ${collapsed && !mobile ? "absolute right-1 top-1" : ""}`}
          >
            {badge.count}
          </span>
        )}
      </NavLink>
    );
  };

  const podDivider = (pod) => (
    <div key={pod.id} className="mx-3 mt-5 flex items-center gap-2 first:mt-2">
      <span className="h-px flex-1 bg-gradient-to-r from-cyan-500/40 via-violet-500/25 to-transparent" />
      {!collapsed && (
        <span className="text-[9px] font-bold tracking-[0.22em] text-slate-500">{pod.title}</span>
      )}
    </div>
  );

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}
      <aside
        className={`glass-line fixed inset-y-0 left-0 z-40 flex flex-col transition-all duration-200 lg:translate-x-0 ${
          collapsed ? "w-[60px]" : "w-60"
        } ${open ? "translate-x-0" : "-translate-x-full"}`}
      >
        {/* Brand */}
        <div className={`flex items-center gap-3 px-4 pb-4 pt-5 ${collapsed ? "justify-center px-0" : ""}`}>
          <BARAQLogo className="h-9 w-9 shrink-0" />
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-base font-bold tracking-wide text-white">BARAQ</p>
              <p className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                <span className={`h-1.5 w-1.5 rounded-full ${online ? "pulse-dot bg-emerald-400 shadow-[0_0_6px_rgba(0,230,118,0.9)]" : "bg-red-500"}`} />
                {online ? "System Operational" : "Offline"}
              </p>
            </div>
          )}
        </div>

        {/* Collapse toggle */}
        <button
          type="button"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="mx-3 mb-1 hidden items-center justify-center gap-2 rounded-xl border border-white/5 bg-white/[0.03] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 transition-colors hover:border-cyan-400/30 hover:text-cyan-300 lg:flex"
        >
          {collapsed ? "▸" : "◂ Expand / Collapse"}
        </button>

        {/* Pods */}
        <nav className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-2">
          {PODS.map((pod) => (
            <div key={pod.id}>
              {podDivider(pod)}
              <div className="mt-1.5 space-y-0.5">
                {navItems(pod).map((item) => link(item, false))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer status */}
        <div className="space-y-3 border-t border-white/5 px-3 py-3">
          {user && (
            <>
              {user.role === "admin" && orgOptions.length > 0 && !collapsed && (
                <label className="block">
                  <span className="mb-1 block text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Organization
                  </span>
                  <select
                    value={org}
                    onChange={(e) => onOrg(e.target.value)}
                    className="w-full rounded-lg border border-slate-700/70 bg-slate-900/80 px-2.5 py-1.5 text-xs font-medium text-slate-200 outline-none transition-colors focus:border-cyan-400/60"
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
              <div
                className={`flex items-center gap-2.5 rounded-xl border border-white/5 bg-white/[0.03] px-3 py-2.5 ${collapsed ? "justify-center px-0" : ""}`}
              >
                <span className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-xs font-bold uppercase text-white shadow-[0_0_14px_-2px_rgba(0,240,255,0.5)]">
                  {(user.username || "?").slice(0, 2)}
                  {user.mfa_enabled && (
                    <span
                      className="absolute -bottom-0.5 -right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full border border-white/20 bg-emerald-500 text-[7px] text-white"
                      title="MFA enabled"
                    >
                      ✓
                    </span>
                  )}
                </span>
                {!collapsed && (
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-semibold text-slate-200">{user.username}</p>
                    <p className="truncate text-[10px] uppercase tracking-wider text-slate-500">
                      {user.role}
                      {user.role !== "admin" && user.org ? ` · ${user.org}` : ""}
                    </p>
                  </div>
                )}
                <button
                  type="button"
                  onClick={onLogout}
                  aria-label="Log out"
                  title="Log out"
                  className="shrink-0 rounded-lg border border-white/10 bg-white/[0.04] p-1.5 text-slate-300 transition-colors hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400"
                >
                  <LogoutIcon className="h-3.5 w-3.5" />
                </button>
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
}

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  const fmt = (d, tz) =>
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: tz });
  const day = (d, tz) =>
    d.toLocaleDateString([], { month: "short", day: "numeric", timeZone: tz }).toUpperCase();
  return { local: fmt(now), utc: fmt(now, "UTC"), localDay: day(now), utcDay: day(now, "UTC") };
}

/* Notification center — only actionable items, never spam. */
function NotificationBell({ summary, setup, user }) {
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState(false);

  const items = [];
  if ((summary?.critical_threats ?? 0) > 0) {
    items.push({
      level: "critical",
      text: `${summary.critical_threats} critical alert${summary.critical_threats > 1 ? "s" : ""} require response`,
      to: "/alerts",
    });
  }
  if ((summary?.anomalies_detected ?? 0) > 0) {
    items.push({
      level: "medium",
      text: `${summary.anomalies_detected} ML anomaly${summary.anomalies_detected > 1 ? "ies" : "y"} flagged`,
      to: "/alerts",
    });
  }
  if (user?.role === "admin" && setup && !setup.credentials_configured) {
    items.push({ level: "high", text: "Default admin credentials still in use", to: "/users" });
  }
  if (setup && !setup.ml_trained) {
    items.push({ level: "medium", text: "ML detection model not trained yet", to: "/settings" });
  }

  const unread = items.length > 0 && !seen ? items.length : 0;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => {
          setOpen((o) => !o);
          setSeen(true);
        }}
        aria-label={`Notifications (${unread} unread)`}
        title="Notification center"
        className="relative rounded-xl border border-white/10 bg-white/[0.04] p-2 text-slate-300 transition-colors hover:bg-white/[0.08]"
      >
        <BellIcon className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 font-mono text-[9px] font-bold text-white">
            {unread}
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="drawer-in absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-2xl border border-white/10 bg-[#101827]/95 shadow-2xl backdrop-blur-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-4 py-3">
              <p className="text-xs font-semibold text-slate-100">Notifications</p>
              <span className="rounded-full border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[9px] text-slate-400">
                {items.length} actionable
              </span>
            </div>
            {items.length > 0 ? (
              <ul className="max-h-80 overflow-auto p-2">
                {items.map((item, idx) => (
                  <li key={idx}>
                    <Link
                      to={item.to}
                      onClick={() => setOpen(false)}
                      className="flex items-start gap-2.5 rounded-xl px-2.5 py-2.5 transition-colors hover:bg-white/[0.04]"
                    >
                      <span
                        className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                          item.level === "critical"
                            ? "pulse-dot bg-red-500"
                            : item.level === "high"
                              ? "bg-orange-400"
                              : "bg-amber-400"
                        }`}
                      />
                      <span className="text-xs leading-snug text-slate-300">{item.text}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="px-4 py-8 text-center">
                <p className="text-xs text-slate-400">All systems nominal</p>
                <p className="mt-1 text-[10px] text-slate-600">
                  You will only be interrupted for actionable events
                </p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function Topbar({ onMenuClick, online, summary, theme, onToggleTheme, warRoom, onToggleWarRoom, setup, user }) {
  const location = useLocation();
  const navigate = useNavigate();
  const page =
    PODS.flatMap((p) => p.items).find(
      (n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to))
    )?.label ?? "BARAQ";

  const [q, setQ] = useState("");
  const clock = useClock();

  const score = summary?.security_score ?? 0;
  const scoreClass =
    score >= 70 ? "text-emerald-400" : score >= 40 ? "text-amber-400" : "text-red-400";

  // Demo/test mode: seeded telemetry is excluded from every production view.

  const submitSearch = (e) => {
    e.preventDefault();
    const query = q.trim();
    navigate(query ? `/search?q=${encodeURIComponent(query)}` : "/search");
  };

  return (
    <header className="glass-line sticky top-0 z-20">
      <div className="flex items-center gap-3 px-4 py-2.5 sm:px-5 lg:px-6">
        <button
          type="button"
          onClick={onMenuClick}
          aria-label="Open navigation"
          className="rounded-xl border border-white/10 bg-white/[0.04] p-2 text-slate-300 transition-colors hover:bg-white/[0.08] lg:hidden"
        >
          <MenuIcon className="h-4 w-4" />
        </button>

        {/* Brand + page context */}
        <div className="hidden min-w-0 items-center gap-2.5 lg:flex">
          <BARAQLogo className="h-7 w-7 shrink-0" />
          <div className="min-w-0">
            <h1 className="truncate text-sm font-bold tracking-wide text-white">{page}</h1>
            <p className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-500">
              <span
                className={`h-1.5 w-1.5 rounded-full ${online ? "pulse-dot bg-emerald-400 shadow-[0_0_6px_rgba(0,230,118,0.9)]" : "bg-red-500"}`}
              />
              {online ? "System Operational" : "Backend Offline"}
            </p>
          </div>
        </div>

        {/* Universal search */}
        <form onSubmit={submitSearch} className="ml-1 hidden max-w-xl flex-1 md:block">
          <div className="group flex items-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2 transition-all focus-within:border-cyan-400/50 focus-within:bg-white/[0.06] focus-within:shadow-[0_0_24px_-6px_rgba(0,240,255,0.4)]">
            <SearchIcon className="h-4 w-4 shrink-0 text-slate-500 transition-colors group-focus-within:text-cyan-300" />
            <input
              id="global-search"
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search…"
              className="w-full bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-500"
            />
            <kbd className="hidden shrink-0 rounded border border-white/10 bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-slate-500 lg:inline-block">
              /
            </kbd>
          </div>
        </form>
        <div className="flex-1 md:hidden" />

        <div className="ml-auto flex items-center gap-2">
          {/* Live clock — local time */}
          <div
            className="hidden items-center rounded-xl border border-white/5 bg-white/[0.03] px-3 py-1.5 xl:flex"
            title={`Local ${clock.localDay}`}
          >
            <div className="text-right leading-tight">
              <p className="font-mono text-[11px] font-semibold text-cyan-300">{clock.local}</p>
            </div>
          </div>

          {summary && (
            <div className="hidden items-center overflow-hidden rounded-xl border border-white/5 bg-white/[0.03] lg:flex">
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
                  className={`flex items-center gap-1.5 px-3 py-1.5 ${
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

          {/* War Room toggle */}
          <button
            type="button"
            onClick={onToggleWarRoom}
            aria-pressed={warRoom}
            title={warRoom ? "Exit War Room mode" : "War Room mode — distraction-free monitoring"}
            className={`hidden items-center gap-1.5 rounded-xl border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors md:inline-flex ${
              warRoom
                ? "border-violet-500/50 bg-violet-500/15 text-violet-300 shadow-[0_0_18px_-4px_rgba(123,97,255,0.6)]"
                : "border-white/10 bg-white/[0.04] text-slate-400 hover:bg-white/[0.08] hover:text-slate-200"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${warRoom ? "pulse-dot bg-violet-400" : "bg-slate-600"}`} />
            War Room
          </button>

          {/* Notification center */}
          <NotificationBell summary={summary} setup={setup} user={user} />

          {/* Theme: dark → light → system (follow OS) */}
          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={`Theme: ${theme} — click to switch`}
            title={
              theme === "dark"
                ? "Theme: Dark — click for Light"
                : theme === "light"
                  ? "Theme: Light — click for System (follow OS)"
                  : "Theme: System — click for Dark"
            }
            className="rounded-xl border border-white/10 bg-white/[0.04] p-2 text-slate-300 transition-colors hover:bg-white/[0.08]"
          >
            {theme === "light" ? (
              <SunIcon className="h-4 w-4" />
            ) : theme === "system" ? (
              <SystemIcon className="h-4 w-4" />
            ) : (
              <MoonIcon className="h-4 w-4" />
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

function BoltTransition() {
  const location = useLocation();
  const [bolt, setBolt] = useState(null);
  const prevPath = useRef(location.pathname);

  useEffect(() => {
    if (prevPath.current !== location.pathname) {
      prevPath.current = location.pathname;
      setBolt(Date.now());
      const t = setTimeout(() => setBolt(null), 750);
      return () => clearTimeout(t);
    }
  }, [location.pathname]);

  if (!bolt) return null;
  return (
    <div
      key={bolt}
      className="pointer-events-none fixed inset-0 z-[60]"
      aria-hidden="true"
    >
      <div className="bolt-streak absolute left-0 top-0 h-full w-2 bg-gradient-to-b from-cyan-400 via-violet-500 to-cyan-400" />
    </div>
  );
}

function CommandPalette({ open, onClose }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const actions = PODS.flatMap((pod) =>
    pod.items.map((item) => ({ ...item, pod: pod.title })),
  );
  const query = q.trim().toLowerCase();
  const filtered = actions.filter(
    (a) =>
      !query ||
      a.label.toLowerCase().includes(query) ||
      a.pod.toLowerCase().includes(query),
  );

  const go = (to) => {
    onClose();
    navigate(to);
  };

  return (
    <div
      className="fixed inset-0 z-[75] flex items-start justify-center bg-black/60 px-4 pt-[12vh] backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="palette-in w-full max-w-lg overflow-hidden rounded-2xl border border-cyan-400/25 bg-[#0b1320]/95 shadow-[0_0_60px_-12px_rgba(0,240,255,0.4)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 border-b border-white/10 px-4 py-3">
          <span className="text-cyan-400">⚡</span>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && filtered.length > 0) go(filtered[0].to);
            }}
            placeholder="Type a page or search…"
            className="w-full bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-500"
          />
          <kbd className="shrink-0 rounded border border-white/10 bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-slate-500">
            ESC
          </kbd>
        </div>
        <div className="max-h-[46vh] overflow-y-auto p-2">
          {query && (
            <button
              type="button"
              onClick={() => {
                onClose();
                navigate(`/search?q=${encodeURIComponent(q.trim())}`);
              }}
              className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-xs text-slate-300 transition-colors hover:bg-cyan-500/10"
            >
              <SearchIcon className="h-4 w-4 text-cyan-400" />
              <span>
                Search <strong className="text-cyan-300">"{q.trim()}"</strong> across events,
                alerts and entities
              </span>
            </button>
          )}
          {filtered.map((a) => {
            const Icon = a.icon;
            return (
              <button
                key={a.to}
                type="button"
                onClick={() => go(a.to)}
                className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors hover:bg-white/[0.06]"
              >
                <Icon className="h-4 w-4 text-slate-400" />
                <span className="flex-1 text-xs font-medium text-slate-200">{a.label}</span>
                <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-600">
                  {a.pod}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* Keyboard shortcut reference (press ?) */
function ShortcutsHelp({ open, onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const groups = [
    {
      title: "Navigate",
      rows: [
        ["g d", "Dashboard"],
        ["g a", "Alerts"],
        ["g i", "Incidents"],
        ["g e", "Entity Graph"],
        ["g m", "MITRE / Risk Center"],
        ["g s", "Search"],
        ["g u", "Automation"],
      ],
    },
    {
      title: "Act",
      rows: [
        ["/", "Focus global search"],
        ["n", "Incident center"],
        ["Ctrl / ⌘ K", "Command palette"],
        ["?", "Keyboard shortcuts"],
        ["Esc", "Close panel"],
      ],
    },
  ];

  return (
    <div
      className="fixed inset-0 z-[75] flex items-start justify-center bg-black/60 px-4 pt-[10vh] backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
    >
      <div
        className="palette-in w-full max-w-md overflow-hidden rounded-2xl border border-white/10 bg-[#0b1320]/95 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <p className="text-sm font-bold text-white">Keyboard Shortcuts</p>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-400 transition-colors hover:border-red-500/40 hover:text-red-400"
          >
            ✕
          </button>
        </div>
        <div className="grid grid-cols-2 gap-x-6 p-4">
          {groups.map((g) => (
            <div key={g.title}>
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                {g.title}
              </p>
              <ul className="space-y-2">
                {g.rows.map(([key, desc]) => (
                  <li key={key} className="flex items-center justify-between gap-3">
                    <kbd className="shrink-0 rounded border border-cyan-400/25 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-cyan-300">
                      {key}
                    </kbd>
                    <span className="text-right text-[11px] text-slate-400">{desc}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AssistantDrawer({ open, onClose }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[70] bg-black/40 backdrop-blur-[2px]" onClick={onClose}>
      <div
        className="drawer-in glass-line absolute bottom-0 right-0 flex h-[72vh] w-full max-w-[420px] flex-col rounded-t-2xl sm:bottom-4 sm:right-4 sm:max-h-[600px] sm:rounded-2xl"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="AI Assistant"
      >
        <div className="flex items-center gap-2.5 border-b border-white/10 px-4 py-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-violet-400/40 bg-violet-500/15 shadow-[0_0_14px_-4px_rgba(123,97,255,0.7)]">
            <AssistantIcon className="h-4 w-4 text-violet-300" />
          </span>
          <div className="min-w-0">
            <p className="text-sm font-bold text-white">AI Assistant</p>
            <p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-500">
              Local threat intelligence
            </p>
          </div>
          <span className="pulse-dot ml-1 h-1.5 w-1.5 rounded-full bg-emerald-400" />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close assistant"
            className="ml-auto rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-slate-400 transition-colors hover:border-red-500/40 hover:text-red-400"
          >
            ✕
          </button>
        </div>
        <div className="flex min-h-0 flex-1 flex-col p-4">
          <AssistantPanel compact />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [navOpen, setNavOpen] = useState(false);
  const [warRoom, setWarRoom] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("baraq:sidebar:collapsed") === "1",
  );
  const navigate = useNavigate();
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;

  // Global shortcuts: Ctrl/Cmd+K → command palette, "/" → universal search,
  // g <key> → page jump, n → incidents, "?" → shortcut help.
  const gPending = useRef(false);
  useEffect(() => {
    const onKey = (e) => {
      const target = e.target;
      const typing =
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable);
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        document.getElementById("global-search")?.focus();
        return;
      }
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;

      const key = e.key.toLowerCase();
      if (key === "g") {
        e.preventDefault();
        gPending.current = true;
        setTimeout(() => {
          gPending.current = false;
        }, 1500);
        return;
      }
      if (gPending.current) {
        const JUMP = {
          d: "/",
          a: "/alerts",
          i: "/incidents",
          e: "/entities",
          m: "/rba",
          s: "/search",
          u: "/automation",
          r: "/reports",
        };
        if (JUMP[key]) {
          e.preventDefault();
          gPending.current = false;
          navigateRef.current(JUMP[key]);
          return;
        }
        gPending.current = false;
        return;
      }
      if (key === "?") {
        e.preventDefault();
        setShortcutsOpen((o) => !o);
        return;
      }
      if (key === "n") {
        e.preventDefault();
        navigateRef.current("/incidents");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const [badges, setBadges] = useState({ openIncidents: 0, criticalIncidents: 0 });
  const { status, online } = useBackendStatus();
  const [theme, setTheme] = useTheme();
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [org, setOrg] = useState(() => authStore.org || "");
  const [orgOptions, setOrgOptions] = useState([]);

  const toggleCollapsed = () => {
    setCollapsed((c) => {
      localStorage.setItem("baraq:sidebar:collapsed", c ? "0" : "1");
      return !c;
    });
  };

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

  // Sidebar badges: open incidents and open critical incidents, refreshed
  // alongside the backend status poll.
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    const refresh = () => {
      api
        .incidents({ status: "open", limit: 100 })
        .then((res) => {
          if (cancelled) return;
          const items = res.items || [];
          setBadges({
            openIncidents: items.length,
            criticalIncidents: items.filter((i) => i.severity === "critical").length,
          });
        })
        .catch(() => {});
    };
    refresh();
    const t = setInterval(refresh, 30000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [user]);

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

  const shell =
    user && !user.must_change_password ? (
      <div
        className={`min-h-screen bg-[var(--app-bg)] text-slate-200 ${warRoom ? "war-room" : ""}`}
      >
        {!warRoom && (
          <Sidebar
            open={navOpen}
            onClose={() => setNavOpen(false)}
            online={online}
            collapsed={collapsed}
            onToggleCollapsed={toggleCollapsed}
            activeAlerts={status?.summary?.active_alerts ?? 0}
            criticalAlerts={status?.summary?.critical_threats ?? 0}
            openIncidents={badges.openIncidents}
            criticalIncidents={badges.criticalIncidents}
            user={user}
            onLogout={logout}
            org={org}
            onOrg={changeOrg}
            orgOptions={user?.role === "admin" ? orgOptions : []}
          />
        )}
        <div
          className={`flex min-h-screen flex-col ${!warRoom && (collapsed ? "lg:pl-[60px]" : "lg:pl-60")}`}
        >
          {!warRoom && (
            <Topbar
              onMenuClick={() => setNavOpen(true)}
              online={online}
              summary={status?.summary}
              theme={theme}
              onToggleTheme={() =>
                setTheme(theme === "dark" ? "light" : theme === "light" ? "system" : "dark")
              }
              warRoom={warRoom}
              onToggleWarRoom={() => setWarRoom((w) => !w)}
              setup={status?.setup}
              user={user}
            />
          )}
          {warRoom && (
            <div className="sticky top-0 z-20 flex items-center gap-3 px-5 py-2">
              <BARAQLogo className="h-6 w-6 shrink-0" />
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
                War Room · Live Monitoring
              </p>
              <button
                type="button"
                onClick={() => setWarRoom(false)}
                className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300 transition-colors hover:border-red-500/40 hover:text-red-400"
              >
                Exit War Room
              </button>
            </div>
          )}
          {!warRoom && <SetupBanner setup={status?.setup} user={user} setNavOpen={setNavOpen} />}
          <main
            className={`fade-in mx-auto w-full flex-1 px-4 py-5 sm:px-6 lg:px-7 ${
              warRoom ? "max-w-[1900px]" : "max-w-[1440px]"
            }`}
          >
            <Suspense
              fallback={
                <div className="space-y-4 py-2">
                  <div className="skeleton h-9 w-64 rounded-xl" />
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
                    {Array.from({ length: 5 }).map((_, i) => (
                      <div key={i} className="skeleton h-28 rounded-2xl" />
                    ))}
                  </div>
                  <div className="skeleton h-80 rounded-2xl" />
                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                    <div className="skeleton h-64 rounded-2xl" />
                    <div className="skeleton h-64 rounded-2xl" />
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
                <Route path="/rba" element={<RBACenter />} />
                <Route path="/search" element={<Search />} />
                <Route path="/dashboards" element={<Dashboards />} />
                <Route path="/automation" element={<Automation />} />
                <Route path="/evaluation" element={<AdminGate user={user}><Evaluation /></AdminGate>} />
                <Route path="/endpoints" element={<AdminGate user={user}><Endpoints /></AdminGate>} />
                <Route path="/agent-setup" element={<AgentSetup />} />
                <Route path="/users" element={<AdminGate user={user}><Users /></AdminGate>} />
                <Route path="/settings" element={<Settings user={user} onUserChange={setUser} />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </main>
          {!warRoom && (
            <footer className="border-t border-white/5 px-6 py-4 text-center text-xs text-slate-600">
              <span className="inline-flex items-center gap-1.5">
                <ShieldIcon className="h-3.5 w-3.5 text-cyan-500/60" />
                BARAQ · Real-Time Endpoint Security Operations
              </span>
            </footer>
          )}
        </div>
        <BoltTransition />
        {!warRoom && (
          <>
            <button
              type="button"
              onClick={() => setAssistantOpen(true)}
              title="Open AI Assistant"
              aria-label="Open AI Assistant"
              className="launcher-pulse fixed bottom-5 right-5 z-[65] flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/40 bg-[#0e1a2b]/90 text-cyan-300 backdrop-blur-xl transition-all hover:scale-110 hover:border-cyan-300/70 hover:text-cyan-200"
            >
              <AssistantIcon className="h-5 w-5" />
            </button>
            <AssistantDrawer open={assistantOpen} onClose={() => setAssistantOpen(false)} />
          </>
        )}
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
        <ShortcutsHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
      </div>
    ) : null;

  return (
    <div className="min-h-screen bg-[var(--app-bg)] text-slate-200">{shell}</div>
  );
}
