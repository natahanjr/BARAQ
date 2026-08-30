import { memo, useEffect, useRef } from "react";
import { createPortal } from "react-dom";

const SHORTCUTS = [
  { section: "Navigation", items: [
    { keys: ["Ctrl", "K"], label: "Open command palette" },
    { keys: ["?"], label: "Toggle this help panel" },
    { keys: ["Esc"], label: "Close modals / palette" },
  ]},
  { section: "Sidebar (number keys)", items: [
    { keys: ["1"], label: "Dashboard" },
    { keys: ["2"], label: "Alerts" },
    { keys: ["3"], label: "Incidents" },
    { keys: ["4"], label: "Investigation" },
    { keys: ["5"], label: "Network Analyzer" },
    { keys: ["6"], label: "Threat Intelligence" },
    { keys: ["7"], label: "BARAQ Intelligence" },
    { keys: ["8"], label: "Automation" },
    { keys: ["9"], label: "Reports" },
  ]},
  { section: "Actions", items: [
    { keys: ["Ctrl", "Shift", "N"], label: "New incident" },
    { keys: ["Ctrl", "Shift", "I"], label: "Start investigation" },
    { keys: ["Ctrl", ","], label: "Open settings" },
    { keys: ["Ctrl", "Shift", "D"], label: "Toggle dark/light theme" },
  ]},
  { section: "Alerts", items: [
    { keys: ["A"], label: "Select all visible alerts" },
    { keys: ["D"], label: "Deselect all" },
  ]},
];

function ShortcutHelp({ open, onClose }) {
  const overlayRef = useRef(null);
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement;
    panelRef.current?.focus();
    return () => prev?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);

  const handleBackdrop = (e) => {
    if (e.target === overlayRef.current) onClose();
  };

  if (!open) return null;

  return createPortal(
    <div
      ref={overlayRef}
      onClick={handleBackdrop}
      className="fixed inset-0 z-[var(--z-modal)] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in"
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className="w-full max-w-lg rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-xl)] outline-none animate-in overflow-hidden"
      >
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
          <div className="flex items-center gap-2.5">
            <svg className="h-5 w-5 text-[var(--accent-cyan)]" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
            </svg>
            <h2 className="text-base font-semibold text-[var(--fg-primary)]">Keyboard Shortcuts</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded-[var(--radius-md)] p-1 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)] transition-colors"
            aria-label="Close"
          >
            <svg className="h-4 w-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto px-5 py-4">
          {SHORTCUTS.map((group) => (
            <div key={group.section} className="mb-5 last:mb-0">
              <h3 className="mb-2.5 text-label text-[var(--fg-faint)]">
                {group.section}
              </h3>
              <div className="space-y-1.5">
                {group.items.map((shortcut) => (
                  <div key={shortcut.label} className="flex items-center justify-between rounded-[var(--radius-lg)] px-3 py-2 transition-colors hover:bg-[var(--bg-surface-hover)]">
                    <span className="text-[13px] text-[var(--fg-secondary)]">{shortcut.label}</span>
                    <div className="flex items-center gap-1">
                      {shortcut.keys.map((key, i) => (
                        <span key={i} className="flex items-center">
                          {i > 0 && <span className="mx-0.5 text-[var(--fg-faint)]">+</span>}
                          <kbd className="inline-flex min-w-[24px] items-center justify-center rounded-[var(--radius-sm)] border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1.5 py-0.5 font-mono text-[11px] font-medium text-[var(--fg-muted)]">
                            {key}
                          </kbd>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="border-t border-[var(--border-subtle)] px-5 py-3 text-center text-[11px] text-[var(--fg-faint)]">
          Press <kbd className="rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1 py-0.5 font-mono text-[10px]">?</kbd> or <kbd className="rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1 py-0.5 font-mono text-[10px]">Esc</kbd> to close
        </div>
      </div>
    </div>,
    document.body
  );
}

export default memo(ShortcutHelp);
