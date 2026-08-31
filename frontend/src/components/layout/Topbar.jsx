import { memo, useCallback, useMemo, useRef, useEffect } from "react";
import { useLocation, Link } from "react-router";
import { useTheme } from "../../context/ThemeContext.jsx";
import { useAuth } from "../../context/AuthContext.jsx";
import { BellIcon, SunIcon, MoonIcon } from "../icons.jsx";
import { StatusDot, CountBadge } from "../ui/index.js";
import { api } from "../../api.js";

const PAGE_TITLES = {
  "/": "Dashboard",
  "/alerts": "Alerts",
  "/incidents": "Incidents",
  "/investigation": "Investigation",
  "/detection-rules": "Detection Rules",
  "/mitre": "MITRE ATT\u2019CK",
  "/ml-detection": "ML Detection",
  "/evaluation": "Evaluation",
  "/network": "Network Analyzer",
  "/threat-intel": "Threat Intelligence",
  "/assistant": "BARAQ Intelligence",
  "/automation": "Automation",
  "/dashboards": "Dashboards",
  "/reports": "Reports",
  "/endpoints": "Endpoints",
  "/telemetry": "Telemetry",
  "/export": "Data Export",
  "/users": "Users & Audit",
  "/settings": "Settings",
  "/agent-setup": "Agent Setup",
  "/rba": "Entity Risk",
};

function Topbar({ activeAlerts, criticalAlerts, openIncidents, onOpenShortcuts, onOpenCommandPalette }) {
  const location = useLocation();
  const { resolvedTheme, cycleTheme } = useTheme();
  const { user } = useAuth();
  const clockRef = useRef(null);

  // DOM-based clock (no re-renders)
  useEffect(() => {
    const el = clockRef.current;
    if (!el) return;
    const tick = () => {
      el.textContent = new Date().toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const pageTitle = useMemo(() => {
    const path = location.pathname;
    if (PAGE_TITLES[path]) return PAGE_TITLES[path];
    for (const [key, val] of Object.entries(PAGE_TITLES)) {
      if (key !== "/" && path.startsWith(key)) return val;
    }
    return "BARAQ";
  }, [location.pathname]);

  return (
    <header role="banner" className="sticky top-0 z-[var(--z-sticky)] border-b border-[var(--border-subtle)] bg-[var(--bg-app)]/80 backdrop-blur-xl">
      <div className="flex h-[var(--topbar-height)] items-center justify-between px-4">
        {/* Left: Title */}
        <div className="flex items-center gap-3 pl-8 lg:pl-0">
          <h1 className="text-[15px] font-semibold text-[var(--fg-primary)]">{pageTitle}</h1>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-1.5" role="toolbar" aria-label="Quick actions">
          {/* Clock */}
          <span ref={clockRef} className="mr-2 font-mono text-[12px] text-[var(--fg-muted)] tabular-nums" aria-label="Current time" />

          {/* Connection indicator */}
          <div className="flex items-center gap-1.5 rounded-lg px-2 py-1" aria-label="Connection status: live">
            <StatusDot status="online" size="xs" />
            <span className="text-[11px] font-medium text-[var(--fg-muted)]">LIVE</span>
          </div>

          {/* Command palette trigger */}
          <button
            onClick={onOpenCommandPalette}
            className="hidden items-center gap-1.5 rounded-lg border border-[var(--border-default)] bg-[var(--bg-surface)] px-2 py-1 text-[11px] text-[var(--fg-muted)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--fg-secondary)] sm:flex"
            title="Command palette (Ctrl+K)"
            aria-label="Open command palette"
          >
            <span aria-hidden="true">⌘K</span>
          </button>

          {/* Notifications */}
          <button className="relative rounded-lg p-1.5 text-[var(--fg-muted)] transition-colors hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-secondary)]" aria-label={`Notifications${activeAlerts > 0 ? ` (${activeAlerts} active)` : ""}`}>
            <BellIcon className="h-4 w-4" />
            {(activeAlerts > 0 || criticalAlerts > 0) && (
              <span className="absolute -right-0.5 -top-0.5" aria-hidden="true">
                <CountBadge count={activeAlerts || criticalAlerts} critical={criticalAlerts > 0} />
              </span>
            )}
          </button>

          {/* Theme toggle */}
          <button
            onClick={cycleTheme}
            className="rounded-lg p-1.5 text-[var(--fg-muted)] transition-colors hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-secondary)]"
            aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
            title={`Theme: ${resolvedTheme}`}
          >
            {resolvedTheme === "dark" ? (
              <MoonIcon className="h-4 w-4" />
            ) : (
              <SunIcon className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}

export default memo(Topbar);
