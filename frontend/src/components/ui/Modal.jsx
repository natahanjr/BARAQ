import { memo, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";

function Modal({ open, onClose, title, children, size = "md", className = "" }) {
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
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  const handleBackdrop = useCallback((e) => {
    if (e.target === overlayRef.current) onClose();
  }, [onClose]);

  if (!open) return null;

  const sizes = {
    sm: "max-w-md",
    md: "max-w-lg",
    lg: "max-w-2xl",
    xl: "max-w-4xl",
    full: "max-w-[90vw]",
  };

  return createPortal(
    <div
      ref={overlayRef}
      onClick={handleBackdrop}
      className="fixed inset-0 z-[var(--z-modal)] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className={[
          "w-full rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-xl)] outline-none",
          "animate-in",
          sizes[size],
          className,
        ].join(" ")}
      >
        {title && (
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
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
        <div className="px-5 py-4 max-h-[70vh] overflow-y-auto">{children}</div>
      </div>
    </div>,
    document.body
  );
}

export default memo(Modal);
