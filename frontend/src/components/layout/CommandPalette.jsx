import { memo, useState, useCallback, useEffect, useRef, useMemo } from "react";
import { useNavigate, useLocation } from "react-router";
import { useTheme } from "../../context/ThemeContext.jsx";
import { useFocusTrap } from "../../hooks/useFocusTrap.js";

const NAV_ITEMS = [
  { label: "Dashboard", path: "/", icon: "◉", shortcut: "1" },
  { label: "Alerts", path: "/alerts", icon: "△", shortcut: "2" },
  { label: "Incidents", path: "/incidents", icon: "□", shortcut: "3" },
  { label: "Investigation", path: "/investigation", icon: "◎", shortcut: "4" },
  { label: "Detection Rules", path: "/detection-rules", icon: "◇" },
  { label: "MITRE ATT\u2019CK", path: "/mitre", icon: "⬡" },
  { label: "ML Detection", path: "/ml-detection", icon: "◈" },
  { label: "Evaluation", path: "/evaluation", icon: "◆" },
  { label: "Network Analyzer", path: "/network", icon: "⬢", shortcut: "5" },
  { label: "Threat Intelligence", path: "/threat-intel", icon: "◉", shortcut: "6" },
  { label: "BARAQ Intelligence", path: "/assistant", icon: "◎", shortcut: "7" },
  { label: "Automation", path: "/automation", icon: "⚙", shortcut: "8" },
  { label: "Dashboards", path: "/dashboards", icon: "▤" },
  { label: "Reports", path: "/reports", icon: "▥", shortcut: "9" },
  { label: "Endpoints", path: "/endpoints", icon: "⊞" },
  { label: "Telemetry", path: "/telemetry", icon: "⊟" },
  { label: "Users & Audit", path: "/users", icon: "⊙" },
  { label: "Settings", path: "/settings", icon: "⚙", shortcut: "Ctrl+," },
];

const ACTIONS = [
  { label: "Create Incident", path: "/incidents", icon: "+" },
  { label: "Start Investigation", path: "/investigation", icon: "+" },
];

const RECENT_KEY = "baraq-recent-pages";
const MAX_RECENT = 5;

function getRecentPages() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch {
    return [];
  }
}

function addRecentPage(path) {
  try {
    const recent = getRecentPages().filter((r) => r.path !== path);
    const navItem = NAV_ITEMS.find((n) => n.path === path);
    const label = navItem?.label || path.split("/").filter(Boolean).join(" / ") || "Home";
    const icon = navItem?.icon || "›";
    recent.unshift({ path, label, icon, ts: Date.now() });
    localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, MAX_RECENT)));
  } catch {}
}

function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const navigate = useNavigate();
  const location = useLocation();
  const { cycleTheme } = useTheme();
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const panelRef = useRef(null);
  useFocusTrap(panelRef, open);
  const [recentPages, setRecentPages] = useState([]);

  // Track recent pages on route change
  useEffect(() => {
    if (location.pathname && location.pathname !== "/") {
      addRecentPage(location.pathname);
    }
  }, [location.pathname]);

  // Load recent pages when palette opens
  useEffect(() => {
    if (open) {
      setRecentPages(getRecentPages());
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    if (!q) {
      // Show recent pages first, then all nav items
      const recentPaths = new Set(recentPages.map((r) => r.path));
      const otherItems = NAV_ITEMS.filter((n) => !recentPaths.has(n.path));
      return [...recentPages, ...otherItems, ...ACTIONS];
    }
    const nav = NAV_ITEMS.filter((item) => item.label.toLowerCase().includes(q));
    const acts = ACTIONS.filter((item) => item.label.toLowerCase().includes(q));
    return [...nav, ...acts];
  }, [query, recentPages]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (e.key === "Escape") { onClose(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1)); }
      if (e.key === "ArrowUp") { e.preventDefault(); setSelectedIdx((i) => Math.max(i - 1, 0)); }
      if (e.key === "Enter" && filtered[selectedIdx]) {
        navigate(filtered[selectedIdx].path);
        onClose();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, filtered, selectedIdx, navigate, onClose]);

  useEffect(() => { setSelectedIdx(0); }, [query]);

  // Scroll selected item into view
  useEffect(() => {
    const el = listRef.current?.children[selectedIdx];
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [selectedIdx]);

  if (!open) return null;

  const showRecent = !query && recentPages.length > 0;
  const recentPaths = new Set(recentPages.map((r) => r.path));

  return (
    <div className="fixed inset-0 z-[var(--z-overlay)] flex items-start justify-center pt-[15vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div ref={panelRef} className="relative w-full max-w-lg rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-2xl)] animate-in overflow-hidden">
        <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] px-4 py-3">
          <svg className="h-4 w-4 text-[var(--fg-muted)]" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <circle cx="6.5" cy="6.5" r="4.5" />
            <path d="M10 10l4 4" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search pages and actions..."
            aria-label="Search pages and actions"
            aria-controls="command-list"
            aria-activedescendant={filtered[selectedIdx] ? `cmd-${selectedIdx}` : undefined}
            className="flex-1 bg-transparent text-[14px] text-[var(--fg-primary)] placeholder-[var(--input-placeholder)] outline-none"
          />
          <kbd className="rounded-[var(--radius-sm)] border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--fg-muted)]" aria-hidden="true">ESC</kbd>
        </div>
        <div id="command-list" ref={listRef} role="listbox" aria-label="Navigation results" className="max-h-[300px] overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-[13px] text-[var(--fg-muted)]" role="status">No results found</div>
          ) : (
            <>
              {/* Recent section header */}
              {showRecent && (
                <div className="px-4 py-1.5">
                  <span className="text-label text-[var(--fg-faint)]">
                    Recent
                  </span>
                </div>
              )}
              {filtered.map((item, i) => {
                const isRecentItem = showRecent && recentPaths.has(item.path);
                const isLastRecent = showRecent && i === recentPages.length - 1;
                return (
                  <span key={item.path + item.label + i}>
                    <button
                      id={`cmd-${i}`}
                      role="option"
                      aria-selected={i === selectedIdx}
                      onClick={() => { navigate(item.path); onClose(); }}
                      className={`flex w-full items-center gap-3 px-4 py-2 text-left text-[13px] transition-colors ${
                        i === selectedIdx
                          ? "bg-[var(--bg-surface-active)] text-[var(--fg-primary)]"
                          : "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)]"
                      }`}
                    >
                      <span className="h-5 w-5 shrink-0 text-center text-[12px] text-[var(--fg-muted)]" aria-hidden="true">{item.icon}</span>
                      <span className="truncate">{item.label}</span>
                      {isRecentItem && (
                        <span className="ml-auto rounded bg-[var(--accent-cyan-subtle)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--accent-cyan)]">recent</span>
                      )}
                      {!isRecentItem && item.shortcut && (
                        <kbd className="ml-auto rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1.5 py-0.5 font-mono text-[10px] font-medium text-[var(--fg-faint)]" aria-hidden="true">{item.shortcut}</kbd>
                      )}
                      {!isRecentItem && !item.shortcut && (
                        <span className="ml-auto font-mono text-[11px] text-[var(--fg-faint)]" aria-hidden="true">{item.path}</span>
                      )}
                    </button>
                    {/* Section divider after recent items */}
                    {isLastRecent && !query && (
                      <div className="my-1 border-t border-[var(--border-subtle)]" />
                    )}
                  </span>
                );
              })}
            </>
          )}
        </div>
        <div className="border-t border-[var(--border-subtle)] px-4 py-2 text-[11px] text-[var(--fg-muted)]" aria-hidden="true">
          <span className="font-medium">↑↓</span> Navigate
          <span className="mx-1.5">·</span>
          <span className="font-medium">↵</span> Open
          <span className="mx-1.5">·</span>
          <span className="font-medium">esc</span> Close
        </div>
      </div>
    </div>
  );
}

export default memo(CommandPalette);
