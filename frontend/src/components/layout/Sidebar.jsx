import { memo, useCallback, useMemo, useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router";
import { useAuth } from "../../context/AuthContext.jsx";
import { useTheme } from "../../context/ThemeContext.jsx";
import {
  DashboardIcon,
  AlertsIcon,
  IncidentsIcon,
  NetworkIcon,
  TelemetryIcon,
  ActivityIcon,
  BoltIcon,
  EvaluationIcon,
  ShieldIcon,
  ReportsIcon,
  AssistantIcon,
  EndpointIcon,
  UsersIcon,
  SystemIcon,
  AgentIcon,
  RiskShieldIcon,
  BellIcon,
  SunIcon,
  MoonIcon,
  LogoutIcon,
} from "../icons.jsx";
import { CountBadge, StatusDot } from "../ui/index.js";
import BARAQLogo from "../BARAQLogo.jsx";

const FAVORITES_KEY = "baraq-favorites";
const ALL_NAV_ITEMS = [
  { to: "/", label: "Dashboard" },
  { to: "/alerts", label: "Alerts" },
  { to: "/incidents", label: "Incidents" },
  { to: "/investigation", label: "Investigation" },
  { to: "/detection-rules", label: "Detection Rules" },
  { to: "/mitre", label: "MITRE ATT&CK" },
  { to: "/ml-detection", label: "ML Detection" },
  { to: "/evaluation", label: "Evaluation" },
  { to: "/network", label: "Network Analyzer" },
  { to: "/threat-intel", label: "Threat Intelligence" },
  { to: "/assistant", label: "BARAQ Intelligence" },
  { to: "/automation", label: "Automation" },
  { to: "/dashboards", label: "Dashboards" },
  { to: "/reports", label: "Reports" },
  { to: "/endpoints", label: "Endpoints" },
  { to: "/telemetry", label: "Telemetry" },
  { to: "/users", label: "Users & Audit" },
  { to: "/settings", label: "Settings" },
];

function getFavorites() {
  try { return JSON.parse(localStorage.getItem(FAVORITES_KEY) || "[]"); } catch { return []; }
}

function setFavoritesStorage(favs) {
  try { localStorage.setItem(FAVORITES_KEY, JSON.stringify(favs)); } catch {}
}

const NAV_SECTIONS = [
  {
    id: "command-center",
    label: "COMMAND CENTER",
    items: [
      { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
      { to: "/alerts", label: "Alerts", icon: AlertsIcon, badge: "alerts" },
      { to: "/incidents", label: "Incidents", icon: IncidentsIcon, badge: "incidents" },
      { to: "/investigation", label: "Investigation", icon: ShieldIcon },
    ],
  },
  {
    id: "detection",
    label: "DETECTION",
    items: [
      { to: "/detection-rules", label: "Detection Rules", icon: ShieldIcon, adminOnly: true },
      { to: "/mitre", label: "MITRE ATT&CK", icon: ActivityIcon },
      { to: "/ml-detection", label: "ML Detection", icon: ActivityIcon },
      { to: "/evaluation", label: "Evaluation", icon: EvaluationIcon, adminOnly: true },
    ],
  },
  {
    id: "network",
    label: "NETWORK",
    items: [
      { to: "/network", label: "Network Analyzer", icon: NetworkIcon },
    ],
  },
  {
    id: "intelligence",
    label: "INTELLIGENCE",
    items: [
      { to: "/threat-intel", label: "Threat Intelligence", icon: ShieldIcon },
      { to: "/assistant", label: "BARAQ Intelligence", icon: AssistantIcon },
    ],
  },
  {
    id: "operations",
    label: "OPERATIONS",
    items: [
      { to: "/automation", label: "Automation", icon: BoltIcon },
      { to: "/dashboards", label: "Dashboards", icon: ActivityIcon },
      { to: "/reports", label: "Reports", icon: ReportsIcon },
    ],
  },
  {
    id: "fleet",
    label: "FLEET",
    items: [
      { to: "/endpoints", label: "Endpoints", icon: EndpointIcon, adminOnly: true },
      { to: "/telemetry", label: "Telemetry", icon: TelemetryIcon },
    ],
  },
  {
    id: "administration",
    label: "ADMINISTRATION",
    items: [
      { to: "/users", label: "Users & Audit", icon: UsersIcon, adminOnly: true },
      { to: "/settings", label: "Settings", icon: SystemIcon },
    ],
  },
];

/* ── SVG Star Icon (consistent across platforms) ──────────────────────── */
function StarIcon({ filled, className = "" }) {
  return (
    <svg className={className} width="10" height="10" viewBox="0 0 16 16" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1.5l1.85 3.75L14 5.9l-3 2.92.71 4.13L8 10.92l-3.71 1.95L5 8.75 2 5.83l4.15-.58L8 1.5z" />
    </svg>
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
  const { isAdmin } = useAuth();
  const { resolvedTheme, cycleTheme } = useTheme();

  const [favorites, setFavs] = useState(getFavorites);

  useEffect(() => {
    const handler = () => setFavs(getFavorites());
    window.addEventListener("baraq:favorites-changed", handler);
    return () => window.removeEventListener("baraq:favorites-changed", handler);
  }, []);

  const toggleFavorite = useCallback((path) => {
    setFavs((prev) => {
      const next = prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path];
      setFavoritesStorage(next);
      window.dispatchEvent(new CustomEvent("baraq:favorites-changed"));
      return next;
    });
  }, []);

  const navItems = useCallback((section) =>
    section.items.filter((item) => (item.adminOnly ? isAdmin : true)),
    [isAdmin]
  );

  const badgeFor = useCallback((item) => {
    if (item.badge === "alerts") {
      if (!activeAlerts) return null;
      return { count: activeAlerts, critical: criticalAlerts > 0 };
    }
    if (item.badge === "incidents") {
      if (!openIncidents) return null;
      return { count: openIncidents, critical: criticalIncidents > 0 };
    }
    return null;
  }, [activeAlerts, criticalAlerts, openIncidents, criticalIncidents]);

  const link = useCallback((item, mobile) => {
    const isActive =
      item.end ? location.pathname === item.to : location.pathname.startsWith(item.to);
    const Icon = item.icon;
    const badge = badgeFor(item);
    const isFav = favorites.includes(item.to);
    return (
      <NavLink
        key={item.to}
        to={item.to}
        end={item.end}
        onClick={onClose}
        title={collapsed && !mobile ? item.label : undefined}
        className={[
          "group relative flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-[13px] font-medium transition-all duration-150",
          isActive
            ? "bg-[var(--accent-cyan)]/10 text-[var(--fg-primary)] shadow-[0_0_16px_-4px_var(--accent-cyan-muted)]"
            : "text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-secondary)]",
          collapsed && !mobile && "justify-center px-0",
        ].join(" ")}
      >
        {isActive && (
          <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-[var(--accent-cyan)]" />
        )}
        <Icon
          className={[
            "h-4 w-4 shrink-0 transition-colors",
            isActive ? "text-[var(--accent-cyan)]" : "text-[var(--fg-muted)] group-hover:text-[var(--fg-secondary)]",
          ].join(" ")}
        />
        {!(collapsed && !mobile) && <span className="truncate">{item.label}</span>}
        {/* Favorite star — visible on hover or when favorited */}
        {!collapsed && !mobile && (
          <button
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              toggleFavorite(item.to);
              // Scale bounce animation
              const el = e.currentTarget;
              el.style.transform = "scale(1.5)";
              el.style.transition = "transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1)";
              setTimeout(() => { el.style.transform = ""; }, 250);
            }}
            className={`ml-auto shrink-0 rounded p-0.5 transition-all duration-150 ${
              isFav
                ? "text-[var(--accent-violet)] opacity-100"
                : "text-[var(--fg-faint)] opacity-0 group-hover:opacity-100 hover:text-[var(--accent-violet)]"
            }`}
            title={isFav ? "Remove from favorites" : "Add to favorites"}
          >
            <StarIcon filled={isFav} />
          </button>
        )}
        {badge && (
          <CountBadge
            count={badge.count}
            critical={badge.critical}
            className={collapsed && !mobile ? "absolute right-1 top-1" : "ml-auto"}
          />
        )}
      </NavLink>
    );
  }, [location.pathname, collapsed, badgeFor, onClose, favorites, toggleFavorite]);

  const sectionDivider = useCallback((section) => (
    <div key={section.id} className="mt-5 first:mt-1 px-2.5">
      {!collapsed && (
        <span className="text-label text-[var(--fg-faint)]">
          {section.label}
        </span>
      )}
    </div>
  ), [collapsed]);

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-[var(--z-sidebar)] bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}
      <aside
        role="navigation"
        aria-label="Main navigation"
        className={[
          "fixed inset-y-0 left-0 z-[var(--z-sidebar)] flex flex-col border-r border-[var(--border-subtle)] bg-[var(--bg-app)] transition-all duration-200 lg:translate-x-0",
          collapsed ? "w-[var(--sidebar-collapsed-width)]" : "w-[var(--sidebar-width)]",
          open ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
      >
        {/* Brand */}
        <div className={`flex items-center gap-2.5 px-4 pb-4 pt-5 ${collapsed ? "justify-center px-0" : ""}`}>
          <BARAQLogo className="h-8 w-8 shrink-0" />
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-[15px] font-bold tracking-tight text-[var(--fg-primary)]">BARAQ</p>
              <div className="flex items-center gap-1.5">
                <StatusDot status={online ? "online" : "offline"} size="xs" pulse={online === null} />
                <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">
                  {online === null ? "Connecting" : online ? "Operational" : "Offline"}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Collapse toggle */}
        <button
          type="button"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="mx-2.5 mb-1 hidden items-center justify-center rounded-xl border border-[var(--border-subtle)] py-1.5 text-[11px] text-[var(--fg-muted)] transition-all hover:border-[var(--border-default)] hover:text-[var(--fg-secondary)] lg:flex"
        >
          {collapsed ? "▸" : "◂"}
        </button>

        {/* Favorites */}
        {!collapsed && favorites.length > 0 && (
          <div className="mt-2 px-2">
            <div className="mb-1 flex items-center gap-1 px-2.5">
              <span className="text-label text-[var(--fg-faint)]">
                Favorites
              </span>
            </div>
            <div className="space-y-0.5">
              {favorites.map((path) => {
                const navItem = ALL_NAV_ITEMS.find((n) => n.to === path);
                if (!navItem) return null;
                const isActive = location.pathname === path || (path !== "/" && location.pathname.startsWith(path));
                return (
                  <NavLink
                    key={path}
                    to={path}
                    onClick={onClose}
                    className={[
                      "group relative flex items-center gap-2.5 rounded-xl px-2.5 py-1.5 text-[12px] font-medium transition-all duration-150",
                      isActive
                        ? "bg-[var(--accent-cyan)]/10 text-[var(--fg-primary)]"
                        : "text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-secondary)]",
                    ].join(" ")}
                  >
                    <StarIcon filled className="text-[var(--accent-violet)]" />
                    <span className="truncate">{navItem.label}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        )}

        {/* Navigation */}
        <nav aria-label="Sidebar" className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-1">
          {NAV_SECTIONS.map((section) => {
            const items = navItems(section);
            if (!items.length) return null;
            return (
              <div key={section.id}>
                {sectionDivider(section)}
                <div className="mt-1 space-y-0.5">
                  {items.map((item) => link(item, false))}
                </div>
              </div>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="space-y-2 border-t border-[var(--border-subtle)] px-2.5 py-3">
          {/* Theme toggle */}
          <button
            onClick={cycleTheme}
            aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
            className={`flex w-full items-center gap-2 rounded-xl px-2.5 py-2 text-[13px] font-medium text-[var(--fg-muted)] transition-all hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-secondary)] ${collapsed ? "justify-center px-0" : ""}`}
            title={`Theme: ${resolvedTheme}`}
          >
            {resolvedTheme === "dark" ? (
              <MoonIcon className="h-4 w-4 shrink-0" />
            ) : resolvedTheme === "light" ? (
              <SunIcon className="h-4 w-4 shrink-0" />
            ) : (
              <span className="h-4 w-4 shrink-0 text-center text-xs">Auto</span>
            )}
            {!collapsed && <span>Theme</span>}
          </button>

          {/* Org switcher */}
          {user?.role === "admin" && orgOptions.length > 0 && !collapsed && (
            <select
              value={org}
              onChange={(e) => onOrg(e.target.value)}
              className="form-select w-full rounded-xl border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1.5 text-[12px] font-medium text-[var(--fg-secondary)] outline-none transition-all duration-[var(--duration-normal)] focus:ring-2 focus:ring-[var(--accent-cyan)]/30 focus:border-[var(--border-focus)]"
              title="Narrow the whole console to one organization (admins)"
            >
              <option value="">All organizations</option>
              {orgOptions.map((o) => (
                <option key={o} value={o}>{o}</option>
              ))}
            </select>
          )}

          {/* User profile */}
          {user && (
            <div className={`flex items-center gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2.5 py-2 ${collapsed ? "justify-center px-0" : ""}`}>
              <span className="relative flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500 to-violet-600 text-[11px] font-bold uppercase text-white">
                {(user.username || "?").slice(0, 2)}
                {user.mfa_enabled && (
                  <span className="absolute -bottom-0.5 -right-0.5 flex h-3 w-3 items-center justify-center rounded-full border border-[var(--bg-app)] bg-[var(--status-healthy)] text-[6px] text-white" title="MFA enabled">
                    ✓
                  </span>
                )}
              </span>
              {!collapsed && (
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[12px] font-semibold text-[var(--fg-primary)]">{user.username}</p>
                  <p className="truncate text-[11px] uppercase tracking-wider text-[var(--fg-muted)]">
                    {user.role}{user.role !== "admin" && user.org ? ` · ${user.org}` : ""}
                  </p>
                </div>
              )}
              <button
                type="button"
                onClick={onLogout}
                aria-label="Log out"
                title="Log out"
                className="shrink-0 rounded-xl border border-[var(--border-subtle)] p-1.5 text-[var(--fg-muted)] transition-all hover:border-[var(--severity-critical-muted)] hover:text-[var(--severity-critical)]"
              >
                <LogoutIcon className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

export default memo(Sidebar);
