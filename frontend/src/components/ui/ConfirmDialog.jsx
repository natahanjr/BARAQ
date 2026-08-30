import { memo, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import { useFocusTrap } from "../../hooks/useFocusTrap.js";

/**
 * Custom confirmation dialog that replaces window.confirm().
 * Uses the existing design token system for consistent theming.
 *
 * Usage:
 *   <ConfirmDialog
 *     open={showConfirm}
 *     onClose={() => setShowConfirm(false)}
 *     onConfirm={handleDelete}
 *     title="Delete alert?"
 *     message="This action cannot be undone."
 *     confirmLabel="Delete"
 *     variant="danger"
 *   />
 */
function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title = "Confirm action",
  message = "Are you sure you want to proceed?",
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "danger", // "danger" | "warning" | "primary"
  loading = false,
}) {
  const overlayRef = useRef(null);
  const panelRef = useRef(null);
  const confirmBtnRef = useRef(null);
  useFocusTrap(panelRef, open);

  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement;
    // Focus is moved to the first focusable control by useFocusTrap.
    return () => prev?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  const handleBackdrop = useCallback(
    (e) => {
      if (e.target === overlayRef.current) onClose();
    },
    [onClose]
  );

  const handleConfirm = useCallback(() => {
    if (!loading) onConfirm();
  }, [loading, onConfirm]);

  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === "Enter" && e.shiftKey) {
        e.preventDefault();
        handleConfirm();
      }
    },
    [handleConfirm]
  );

  if (!open) return null;

  const variantStyles = {
    danger: {
      icon: (
        <svg className="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v4" />
          <circle cx="12" cy="16" r="0.5" fill="currentColor" />
        </svg>
      ),
      iconBg: "var(--severity-critical-subtle)",
      iconColor: "var(--severity-critical)",
      confirmBg: "var(--severity-critical)",
      confirmHover: "brightness(1.1)",
    },
    warning: {
      icon: (
        <svg className="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
          <path d="M12 9v4" />
          <circle cx="12" cy="17" r="0.5" fill="currentColor" />
        </svg>
      ),
      iconBg: "var(--severity-medium-subtle)",
      iconColor: "var(--severity-medium)",
      confirmBg: "var(--severity-medium)",
      confirmHover: "brightness(1.1)",
    },
    primary: {
      icon: (
        <svg className="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 16v-4" />
          <path d="M12 8h.01" />
        </svg>
      ),
      iconBg: "var(--accent-cyan-subtle)",
      iconColor: "var(--accent-cyan)",
      confirmBg: "var(--accent-cyan)",
      confirmHover: "brightness(1.1)",
    },
  };

  const v = variantStyles[variant] || variantStyles.danger;

  return createPortal(
    <div
      ref={overlayRef}
      onClick={handleBackdrop}
      onKeyDown={handleKeyDown}
      className="fixed inset-0 z-[var(--z-modal)] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className="w-full max-w-md rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-xl)] outline-none animate-in"
      >
        <div className="flex items-start gap-4 p-6 pb-0">
          <div
            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
            style={{ background: v.iconBg, color: v.iconColor }}
          >
            {v.icon}
          </div>
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-semibold text-[var(--fg-primary)]">{title}</h2>
            <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--fg-secondary)]">{message}</p>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4">
          <button
            onClick={onClose}
            className="rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface-raised)] px-4 py-2 text-[13px] font-medium text-[var(--fg-secondary)] transition-all duration-[var(--duration-fast)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]"
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmBtnRef}
            onClick={handleConfirm}
            disabled={loading}
            className="rounded-[var(--radius-lg)] px-4 py-2 text-[13px] font-semibold text-white transition-all duration-[var(--duration-fast)] disabled:opacity-50 shadow-[var(--shadow-sm)]"
            style={{ background: v.confirmBg }}
            onMouseEnter={(e) => (e.currentTarget.style.filter = v.confirmHover)}
            onMouseLeave={(e) => (e.currentTarget.style.filter = "")}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Processing…
              </span>
            ) : (
              confirmLabel
            )}
          </button>
        </div>
        <div className="border-t border-[var(--border-subtle)] px-6 py-2 text-center text-[11px] text-[var(--fg-faint)]">
          Press <kbd className="rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1 py-0.5 font-mono text-[10px]">Shift</kbd> + <kbd className="rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1 py-0.5 font-mono text-[10px]">Enter</kbd> to confirm
        </div>
      </div>
    </div>,
    document.body
  );
}

export default memo(ConfirmDialog);
