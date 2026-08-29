import { memo, useState, useCallback, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router";
import { useTheme } from "../../context/ThemeContext.jsx";
import { SearchInput } from "../ui/index.js";

const NAV_ITEMS = [
  { label: "Dashboard", path: "/", icon: "◉" },
  { label: "Alerts", path: "/alerts", icon: "△" },
  { label: "Incidents", path: "/incidents", icon: "□" },
  { label: "Investigation", path: "/investigation", icon: "◎" },
  { label: "Detection Rules", path: "/detection-rules", icon: "◇" },
  { label: "MITRE ATT\u2019CK", path: "/mitre", icon: "⬡" },
  { label: "ML Detection", path: "/ml-detection", icon: "◈" },
  { label: "Evaluation", path: "/evaluation", icon: "◆" },
  { label: "Network Analyzer", path: "/network", icon: "⬢" },
  { label: "Threat Intelligence", path: "/threat-intel", icon: "◉" },
  { label: "BARAQ Intelligence", path: "/assistant", icon: "◎" },
  { label: "Automation", path: "/automation", icon: "⚙" },
  { label: "Dashboards", path: "/dashboards", icon: "▤" },
  { label: "Reports", path: "/reports", icon: "▥" },
  { label: "Endpoints", path: "/endpoints", icon: "⊞" },
  { label: "Telemetry", path: "/telemetry", icon: "⊟" },
  { label: "Users & Audit", path: "/users", icon: "⊙" },
  { label: "Settings", path: "/settings", icon: "⚙" },
];

const ACTIONS = [
  { label: "Create Incident", path: "/incidents", icon: "+" },
  { label: "Start Investigation", path: "/investigation", icon: "+" },
];

function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const navigate = useNavigate();
  const { cycleTheme } = useTheme();
  const inputRef = useRef(null);
  const listRef = useRef(null);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    const nav = NAV_ITEMS.filter((item) => item.label.toLowerCase().includes(q));
    const acts = ACTIONS.filter((item) => item.label.toLowerCase().includes(q));
    return [...nav, ...acts];
  }, [query]);

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

  return (
    <div className="fixed inset-0 z-[var(--z-overlay)] flex items-start justify-center pt-[15vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-2xl)] animate-in overflow-hidden">
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
          <kbd className="rounded-[var(--radius-sm)] border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--fg-muted)]" aria-hidden="true">ESC</kbd>
        </div>
        <div id="command-list" ref={listRef} role="listbox" aria-label="Navigation results" className="max-h-[300px] overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-[13px] text-[var(--fg-muted)]" role="status">No results found</div>
          ) : (
            filtered.map((item, i) => (
              <button
                key={item.path + item.label}
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
                <span className="ml-auto font-mono text-[10px] text-[var(--fg-faint)]" aria-hidden="true">{item.path}</span>
              </button>
            ))
          )}
        </div>
        <div className="border-t border-[var(--border-subtle)] px-4 py-2 text-[10px] text-[var(--fg-muted)]" aria-hidden="true">
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
