import { memo, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";

function Drawer({ open, onClose, title, children, side = "right", width = 420, className = "" }) {
  const panelRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  useEffect(() => {
    if (open) panelRef.current?.focus();
  }, [open]);

  if (!open) return null;

  const isRight = side === "right";

  return createPortal(
    <div className="fixed inset-0 z-[var(--z-modal)]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm animate-in"
        onClick={onClose}
      />
      {/* Panel */}
      <div
        ref={panelRef}
        tabIndex={-1}
        className={[
          "absolute inset-y-0 flex flex-col border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-xl)] outline-none",
          "animate-drawer-in",
          isRight ? "right-0 border-l" : "left-0 border-r",
          className,
        ].join(" ")}
        style={{ width: Math.min(width, typeof window !== "undefined" ? window.innerWidth * 0.9 : width) }}
      >
        {title && (
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4 shrink-0">
            <h2 className="text-base font-semibold text-[var(--fg-primary)]">{title}</h2>
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
        )}
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>,
    document.body
  );
}

export default memo(Drawer);
