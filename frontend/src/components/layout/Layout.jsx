import { memo, useState, useCallback, useEffect, useRef } from "react";
import { Outlet, useLocation, useNavigate, Link } from "react-router";
import { useBackendStatus } from "../../hooks/useBackendStatus.js";
import { useAuth } from "../../context/AuthContext.jsx";
import Sidebar from "./Sidebar.jsx";
import Topbar from "./Topbar.jsx";
import CommandPalette from "./CommandPalette.jsx";
import ShortcutHelp from "./ShortcutHelp.jsx";
import { MenuIcon } from "../icons.jsx";

/* ── Route breadcrumb map ──────────────────────────────────────────────── */
const BREADCRUMB_MAP = {
  "/": ["Dashboard"],
  "/alerts": ["Alerts"],
  "/incidents": ["Incidents"],
  "/investigation": ["Investigation"],
  "/detection-rules": ["Detection Rules"],
  "/mitre": ["MITRE ATT\u2019CK"],
  "/ml-detection": ["ML Detection"],
  "/evaluation": ["Evaluation"],
  "/network": ["Network Analyzer"],
  "/threat-intel": ["Threat Intelligence"],
  "/assistant": ["BARAQ Intelligence"],
  "/automation": ["Automation"],
  "/dashboards": ["Dashboards"],
  "/reports": ["Reports"],
  "/endpoints": ["Endpoints"],
  "/telemetry": ["Telemetry"],
  "/users": ["Users & Audit"],
  "/settings": ["Settings"],
  "/agent-setup": ["Agent Setup"],
};

function getBreadcrumbs(pathname) {
  if (BREADCRUMB_MAP[pathname]) {
    return [{ label: "Home", to: "/" }, { label: BREADCRUMB_MAP[pathname][0] }];
  }
  // Handle detail pages like /alerts/123
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length >= 2) {
    const basePath = "/" + parts[0];
    const baseLabel = BREADCRUMB_MAP[basePath]?.[0] || parts[0];
    const detailLabel = parts.slice(1).join(" / ");
    return [
      { label: "Home", to: "/" },
      { label: baseLabel, to: basePath },
      { label: detailLabel },
    ];
  }
  return [{ label: "Home", to: "/" }];
}

function Breadcrumbs({ pathname }) {
  const crumbs = getBreadcrumbs(pathname);
  if (crumbs.length <= 1) return null;
  return (
    <nav aria-label="Breadcrumb" className="mb-4 flex items-center gap-1.5 text-[12px] text-[var(--fg-muted)]">
      {crumbs.map((crumb, i) => {
        const isLast = i === crumbs.length - 1;
        return (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && <span className="text-[var(--fg-faint)]">›</span>}
            {crumb.to && !isLast ? (
              <Link to={crumb.to} className="transition-colors hover:text-[var(--fg-secondary)]">
                {crumb.label}
              </Link>
            ) : (
              <span className={isLast ? "font-medium text-[var(--fg-secondary)]" : ""}>{crumb.label}</span>
            )}
          </span>
        );
      })}
    </nav>
  );
}

/* ── Route loading progress bar ────────────────────────────────────────── */
function RouteProgress() {
  const location = useLocation();
  const [progress, setProgress] = useState(0);
  const [visible, setVisible] = useState(false);
  const timerRef = useRef(null);
  const prevPath = useRef(location.pathname);

  useEffect(() => {
    if (location.pathname === prevPath.current) return;
    prevPath.current = location.pathname;

    // Start progress
    setVisible(true);
    setProgress(0);

    // Simulate progress steps
    clearTimeout(timerRef.current);
    const step1 = setTimeout(() => setProgress(30), 50);
    const step2 = setTimeout(() => setProgress(60), 150);
    const step3 = setTimeout(() => setProgress(85), 300);
    const done = setTimeout(() => {
      setProgress(100);
      setTimeout(() => {
        setVisible(false);
        setProgress(0);
      }, 200);
    }, 450);

    timerRef.current = setTimeout(() => {
      clearTimeout(step1);
      clearTimeout(step2);
      clearTimeout(step3);
      clearTimeout(done);
    }, 5000);

    return () => {
      clearTimeout(step1);
      clearTimeout(step2);
      clearTimeout(step3);
      clearTimeout(done);
      clearTimeout(timerRef.current);
    };
  }, [location.pathname]);

  if (!visible) return null;

  return (
    <div className="fixed left-0 right-0 top-0 z-[var(--z-toast)] h-[2px]">
      <div
        className="h-full rounded-full transition-all duration-200 ease-out"
        style={{
          width: `${progress}%`,
          background: "linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))",
          boxShadow: "0 0 8px var(--accent-cyan-muted)",
        }}
      />
    </div>
  );
}

function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try { return localStorage.getItem("baraq-sidebar-collapsed") === "true"; } catch { return false; }
  });
  const [cmdOpen, setCmdOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const { user, logout, org, setOrg } = useAuth();
  const { online, activeAlerts, criticalAlerts, openIncidents, criticalIncidents, orgOptions } = useBackendStatus();
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef(null);

  const toggleSidebarCollapsed = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try { localStorage.setItem("baraq-sidebar-collapsed", String(next)); } catch {}
      return next;
    });
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      // Skip if typing in input/textarea/select
      const tag = document.activeElement?.tagName;
      const isInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";

      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key === ",") {
        e.preventDefault();
        navigate("/settings");
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === "N") {
        e.preventDefault();
        navigate("/incidents");
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === "I") {
        e.preventDefault();
        navigate("/investigation");
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && (e.key === "D" || e.key === "d")) {
        e.preventDefault();
        // Import useTheme lazily to avoid circular dependency
        const evt = new CustomEvent("baraq:cycle-theme");
        window.dispatchEvent(evt);
        return;
      }
      // ? key for shortcut help
      if (e.key === "?" && !e.ctrlKey && !e.metaKey && !e.altKey && !isInput) {
        e.preventDefault();
        setShortcutsOpen((prev) => !prev);
        return;
      }
      // Number keys 1-9 for sidebar navigation
      if (!e.ctrlKey && !e.metaKey && !e.altKey && !isInput) {
        const navPaths = ["/", "/alerts", "/incidents", "/investigation", "/network", "/threat-intel", "/assistant", "/automation", "/reports"];
        const num = parseInt(e.key, 10);
        if (num >= 1 && num <= 9 && navPaths[num - 1]) {
          e.preventDefault();
          navigate(navPaths[num - 1]);
          return;
        }
      }
      if (e.key === "Escape") {
        if (shortcutsOpen) { setShortcutsOpen(false); return; }
        if (cmdOpen) setCmdOpen(false);
        if (sidebarOpen) setSidebarOpen(false);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [cmdOpen, sidebarOpen, shortcutsOpen, navigate]);

  // Focus main content on route change for accessibility
  useEffect(() => {
    mainRef.current?.focus({ preventScroll: true });
  }, [location.pathname]);

  return (
    <div
      className="flex min-h-screen"
      style={{
        paddingTop: "env(safe-area-inset-top)",
        paddingBottom: "env(safe-area-inset-bottom)",
        paddingLeft: "env(safe-area-inset-left)",
        paddingRight: "env(safe-area-inset-right)",
      }}
    >
      {/* Skip to content */}
      <a href="#main-content" className="skip-link">Skip to content</a>

      {/* Route loading progress */}
      <RouteProgress />

      <Sidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        online={online}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={toggleSidebarCollapsed}
        activeAlerts={activeAlerts}
        criticalAlerts={criticalAlerts}
        openIncidents={openIncidents}
        criticalIncidents={criticalIncidents}
        user={user}
        onLogout={logout}
        org={org}
        onOrg={setOrg}
        orgOptions={orgOptions}
      />

      <div className={`flex min-h-screen flex-1 flex-col transition-all duration-200 ${
        sidebarCollapsed ? "lg:pl-[var(--sidebar-collapsed-width)]" : "lg:pl-[var(--sidebar-width)]"
      }`}>
        <Topbar
          activeAlerts={activeAlerts}
          criticalAlerts={criticalAlerts}
          openIncidents={openIncidents}
          onOpenCommandPalette={() => setCmdOpen(true)}
        />

        {/* Mobile menu button */}
        <button
        onClick={() => setSidebarOpen(true)}
        className="fixed left-3 top-3 z-[var(--z-sidebar)] rounded-xl border border-[var(--border-default)] bg-[var(--bg-surface)] p-1.5 text-[var(--fg-muted)] shadow-[var(--shadow-md)] lg:hidden"
        style={{
          top: "calc(env(safe-area-inset-top) + 0.75rem)",
          left: "calc(env(safe-area-inset-left) + 0.75rem)",
        }}
        aria-label="Open navigation menu"
      >
          <MenuIcon className="h-4 w-4" />
        </button>

        <main
          ref={mainRef}
          id="main-content"
          tabIndex={-1}
          className="flex-1 px-4 py-5 sm:px-6 lg:px-8 focus:outline-none"
        >
          <div className="mx-auto max-w-[1440px]">
            <Breadcrumbs pathname={location.pathname} />
            <div key={location.pathname} className="fade-in">
              <Outlet />
            </div>
          </div>
        </main>

        <footer className="border-t border-[var(--border-subtle)] px-6 py-3 text-center text-[11px] text-[var(--fg-faint)]">
          BARAQ Security Operations Center &middot; {new Date().getFullYear()}
        </footer>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
      <ShortcutHelp open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

export default memo(Layout);
