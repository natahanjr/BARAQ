import { lazy, Suspense, useEffect, useState } from "react";
import { Routes, Route, NavLink, useLocation, Navigate } from "react-router-dom";
import { api } from "./api.js";

const Dashboard = lazy(() => import("./pages/Dashboard.jsx"));
const Alerts = lazy(() => import("./pages/Alerts.jsx"));
const AlertDetail = lazy(() => import("./pages/AlertDetail.jsx"));
const Investigation = lazy(() => import("./pages/Investigation.jsx"));
const Events = lazy(() => import("./pages/Events.jsx"));
const Telemetry = lazy(() => import("./pages/Telemetry.jsx"));
const Assistant = lazy(() => import("./pages/Assistant.jsx"));
const Reports = lazy(() => import("./pages/Reports.jsx"));
const Evaluation = lazy(() => import("./pages/Evaluation.jsx"));
const System = lazy(() => import("./pages/System.jsx"));

import {
  DashboardIcon,
  AlertsIcon,
  InvestigationIcon,
  EventsIcon,
  TelemetryIcon,
  AssistantIcon,
  ReportsIcon,
  EvaluationIcon,
  SystemIcon,
  MenuIcon,
  ShieldIcon,
} from "./components/icons.jsx";

const NAV = [
  { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
  { to: "/alerts", label: "Alerts", icon: AlertsIcon },
  { to: "/investigation", label: "Investigation", icon: InvestigationIcon },
  { to: "/events", label: "Events", icon: EventsIcon },
  { to: "/telemetry", label: "Processes & Network", icon: TelemetryIcon },
  { to: "/assistant", label: "AI Assistant", icon: AssistantIcon },
  { to: "/reports", label: "Reports", icon: ReportsIcon },
  { to: "/evaluation", label: "Evaluation", icon: EvaluationIcon },
  { to: "/system", label: "System", icon: SystemIcon },
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
    const timer = setInterval(check, 15000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return { status, online };
}

function SentinelLogo() {
  return (
    <svg className="h-10 w-10" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
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

function Sidebar({ open, onClose, online, activeAlerts }) {
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
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-slate-800/60 bg-gradient-to-b from-slate-950 via-slate-950 to-slate-900 shadow-2xl transition-transform duration-200 lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        {/* Brand */}
        <div className="flex items-center gap-3 border-b border-slate-800/40 px-5 py-5">
          <SentinelLogo />
          <div className="min-w-0">
            <p className="truncate text-sm font-bold tracking-wide text-white">SentinelSOC</p>
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-400">
              Live Threat Detection
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5">
          {NAV.map((item) => {
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
                className={`group flex items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? "border border-cyan-500/30 bg-gradient-to-r from-cyan-500/20 to-cyan-500/10 text-cyan-300 shadow-lg shadow-cyan-500/10"
                    : "border border-transparent text-slate-400 hover:bg-slate-800/40 hover:text-slate-200"
                }`}
              >
                <Icon className={`h-5 w-5 shrink-0 ${isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"}`} />
                <span className="truncate">{item.label}</span>
                {item.to === "/alerts" && activeAlerts > 0 && (
                  <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500/20 px-1.5 text-[10px] font-bold text-red-400">
                    {activeAlerts}
                  </span>
                )}
                {isActive && item.to !== "/alerts" && (
                  <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/50" />
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Footer status */}
        <div className="border-t border-slate-800/40 px-5 py-4">
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                online ? "animate-pulse bg-emerald-500" : "bg-red-500"
              }`}
            />
            <span className={`text-xs font-medium ${online ? "text-emerald-400" : "text-red-400"}`}>
              {online ? "System Online" : "Backend Offline"}
            </span>
          </div>
          <p className="mt-2 font-mono text-[11px] text-slate-500">v1.0.0 · Real-time · Win32</p>
        </div>
      </aside>
    </>
  );
}

function Topbar({ onMenuClick, online, summary }) {
  const location = useLocation();
  const page = NAV.find(
    (n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to))
  )?.label ?? "SentinelSOC";

  const score = summary?.security_score ?? 0;
  const scoreClass =
    score >= 70 ? "text-emerald-400" : score >= 40 ? "text-amber-400" : "text-red-400";

  return (
    <header className="sticky top-0 z-20 border-b border-slate-800/50 bg-gradient-to-r from-slate-950/95 via-slate-950/90 to-slate-950/95 px-4 py-4 shadow-lg backdrop-blur-md sm:px-6 lg:px-8">
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation"
            className="rounded-lg border border-slate-700/60 bg-slate-800/60 p-2 text-slate-300 transition-colors hover:bg-slate-700 lg:hidden"
          >
            <MenuIcon className="h-5 w-5" />
          </button>
          <div className="min-w-0">
            <h1 className="truncate text-xl font-bold tracking-tight text-white sm:text-2xl">
              {page}
            </h1>
            <p className="mt-0.5 hidden text-xs text-slate-400 sm:block">
              Real-time endpoint security monitoring
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {summary && (
            <div className="hidden items-center gap-5 rounded-lg border border-slate-800/60 bg-slate-900/50 px-4 py-2 md:flex">
              <div className="text-center">
                <p className={`text-xl font-bold leading-none ${scoreClass}`}>
                  {Math.round(score)}
                </p>
                <p className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">
                  Security Score
                </p>
              </div>
              <div className="h-7 w-px bg-slate-700/50" />
              <div className="text-center">
                <p className="text-base font-semibold leading-none text-slate-200">
                  {(summary.total_events ?? 0).toLocaleString()}
                </p>
                <p className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">Events</p>
              </div>
              <div className="h-7 w-px bg-slate-700/50" />
              <div className="text-center">
                <p className="text-base font-semibold leading-none text-cyan-400">
                  {summary.active_alerts ?? 0}
                </p>
                <p className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">Alerts</p>
              </div>
            </div>
          )}

          <div
            className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${
              online
                ? "border-emerald-500/30 bg-emerald-500/10"
                : "border-red-500/30 bg-red-500/10"
            }`}
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                online ? "animate-pulse bg-emerald-500" : "bg-red-500"
              }`}
            />
            <span className={`text-xs font-medium ${online ? "text-emerald-400" : "text-red-400"}`}>
              <span className="hidden sm:inline">{online ? "Backend Online" : "Backend Offline"}</span>
              <span className="sm:hidden">{online ? "Online" : "Offline"}</span>
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

export default function App() {
  const [navOpen, setNavOpen] = useState(false);
  const { status, online } = useBackendStatus();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-200">
      <Sidebar
        open={navOpen}
        onClose={() => setNavOpen(false)}
        online={online}
        activeAlerts={status?.summary?.active_alerts ?? 0}
      />
      <div className="flex min-h-screen flex-col lg:pl-64">
        <Topbar
          onMenuClick={() => setNavOpen(true)}
          online={online}
          summary={status?.summary}
        />
        <main className="fade-in flex-1 px-4 py-6 sm:px-6 lg:px-8">
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
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/investigation" element={<Investigation />} />
              <Route path="/events" element={<Events />} />
              <Route path="/telemetry" element={<Telemetry />} />
              <Route path="/assistant" element={<Assistant />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/evaluation" element={<Evaluation />} />
              <Route path="/system" element={<System />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
        <footer className="border-t border-slate-800/40 px-6 py-4 text-center text-xs text-slate-600">
          <span className="inline-flex items-center gap-1.5">
            <ShieldIcon className="h-3.5 w-3.5" />
            SentinelSOC · Real-Time Endpoint Security Operations
          </span>
        </footer>
      </div>
    </div>
  );
}
