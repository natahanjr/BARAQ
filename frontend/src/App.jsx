import { useEffect, useState } from "react";
import { Routes, Route, NavLink, useLocation, Navigate } from "react-router-dom";
import { api } from "./api.js";

import Dashboard from "./pages/Dashboard.jsx";
import Alerts from "./pages/Alerts.jsx";
import AlertDetail from "./pages/AlertDetail.jsx";
import Investigation from "./pages/Investigation.jsx";
import Events from "./pages/Events.jsx";
import Telemetry from "./pages/Telemetry.jsx";
import Assistant from "./pages/Assistant.jsx";
import Reports from "./pages/Reports.jsx";
import Evaluation from "./pages/Evaluation.jsx";
import System from "./pages/System.jsx";

const NAV = [
  { to: "/", label: "Dashboard", icon: "▤" },
  { to: "/alerts", label: "Alerts", icon: "⚠" },
  { to: "/investigation", label: "Investigation", icon: "⌖" },
  { to: "/events", label: "Events", icon: "≡" },
  { to: "/telemetry", label: "Processes & Network", icon: "⇄" },
  { to: "/assistant", label: "AI Assistant", icon: "✦" },
  { to: "/reports", label: "Reports", icon: "▦" },
  { to: "/evaluation", label: "Evaluation", icon: "◬" },
  { to: "/system", label: "System", icon: "⚙" },
];

function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 z-20 flex w-56 flex-col border-r border-slate-800 bg-slate-950/90">
      <div className="flex items-center gap-2.5 border-b border-slate-800 px-4 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded bg-cyan-500/15 text-cyan-400 ring-1 ring-cyan-500/30">
          <span className="text-lg font-bold">S</span>
        </div>
        <div>
          <p className="text-sm font-bold tracking-wide text-slate-100">SentinelSOC</p>
          <p className="text-[10px] uppercase tracking-widest text-slate-500">Security Operations Center</p>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-2 py-4">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/30"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              }`
            }
          >
            <span className="w-4 text-center text-base">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-slate-800 px-4 py-3">
        <p className="text-[10px] uppercase tracking-widest text-slate-600">
          MSc Cybersecurity Prototype
        </p>
        <p className="mt-0.5 text-[10px] text-slate-700">v1.0.0 · localhost:8000</p>
      </div>
    </aside>
  );
}

function Topbar() {
  const [status, setStatus] = useState(null);
  const [online, setOnline] = useState(false);
  const location = useLocation();

  useEffect(() => {
    api
      .systemStatus()
      .then((s) => {
        setStatus(s);
        setOnline(true);
      })
      .catch(() => setOnline(false));
  }, [location.pathname]);

  const page = NAV.find((n) => n.to === location.pathname)?.label ?? "SentinelSOC";

  return (
    <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/80 px-6 py-3 backdrop-blur">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">{page}</h1>
        <div className="flex items-center gap-4 text-xs text-slate-500">
          {status && (
            <span className="hidden font-mono md:inline">
              score {status.summary.security_score} · {status.summary.total_events} events
            </span>
          )}
          <span className="flex items-center gap-1.5">
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                online ? "bg-emerald-400 pulse-dot" : "bg-red-500"
              }`}
            />
            {online ? "Backend online" : "Backend offline"}
          </span>
        </div>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-[#0a0f1a]">
      <Sidebar />
      <div className="pl-56">
        <Topbar />
        <main className="px-6 py-6">
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
        </main>
      </div>
    </div>
  );
}
