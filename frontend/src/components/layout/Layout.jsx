import { memo, useState, useCallback, useEffect, useRef } from "react";
import { Outlet } from "react-router";
import { useBackendStatus } from "../../hooks/useBackendStatus.js";
import { useAuth } from "../../context/AuthContext.jsx";
import Sidebar from "./Sidebar.jsx";
import Topbar from "./Topbar.jsx";
import CommandPalette from "./CommandPalette.jsx";
import { MenuIcon } from "../icons.jsx";

function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try { return localStorage.getItem("baraq-sidebar-collapsed") === "true"; } catch { return false; }
  });
  const [cmdOpen, setCmdOpen] = useState(false);
  const { user, logout, org, setOrg } = useAuth();
  const { online, activeAlerts, criticalAlerts, openIncidents, criticalIncidents, orgOptions } = useBackendStatus();

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
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      }
      if (e.key === "Escape") {
        if (cmdOpen) setCmdOpen(false);
        if (sidebarOpen) setSidebarOpen(false);
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [cmdOpen, sidebarOpen]);

  return (
    <div className="flex min-h-screen">
      {/* Skip to content */}
      <a href="#main-content" className="skip-link">Skip to content</a>

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
          className="fixed left-3 top-3 z-[var(--z-sidebar)] rounded-lg border border-[var(--border-default)] bg-[var(--bg-surface)] p-1.5 text-[var(--fg-muted)] shadow-[var(--shadow-md)] lg:hidden"
          aria-label="Open navigation menu"
        >
          <MenuIcon className="h-4 w-4" />
        </button>

        <main id="main-content" tabIndex={-1} className="flex-1 px-4 py-5 sm:px-6 lg:px-8 focus:outline-none">
          <div className="mx-auto max-w-[1440px]">
            <Outlet />
          </div>
        </main>

        <footer className="border-t border-[var(--border-subtle)] px-6 py-3 text-center text-[10px] text-[var(--fg-faint)]">
          BARAQ Security Operations Center &middot; {new Date().getFullYear()}
        </footer>
      </div>

      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}

export default memo(Layout);
