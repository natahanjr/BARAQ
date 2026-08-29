import { memo, useEffect, useState, useCallback, createContext, useContext, useRef } from "react";
import { createPortal } from "react-dom";

const ToastContext = createContext(null);

let toastId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const remove = useCallback((id) => {
    clearTimeout(timers.current[id]);
    delete timers.current[id];
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const add = useCallback(({ title, message, type = "info", duration = 4000, action }) => {
    const id = ++toastId;
    setToasts((prev) => [...prev, { id, title, message, type, action }]);
    if (duration > 0) {
      timers.current[id] = setTimeout(() => remove(id), duration);
    }
    return id;
  }, [remove]);

  const toast = useCallback((message, opts = {}) => {
    if (typeof message === "string") return add({ message, ...opts });
    return add(message);
  }, [add]);

  toast.success = (msg, opts) => add({ message: msg, type: "success", ...opts });
  toast.error = (msg, opts) => add({ message: msg, type: "error", ...opts });
  toast.warning = (msg, opts) => add({ message: msg, type: "warning", ...opts });

  return (
    <ToastContext.Provider value={{ toast, remove }}>
      {children}
      {createPortal(
        <div className="fixed top-4 right-4 z-[var(--z-toast)] flex flex-col gap-2 pointer-events-none">
          {toasts.map((t) => (
            <ToastItem key={t.id} toast={t} onDismiss={() => remove(t.id)} />
          ))}
        </div>,
        document.body
      )}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

const typeStyles = {
  info: "border-[var(--border-default)] bg-[var(--bg-surface)]",
  success: "border-[var(--success-border)] bg-[var(--success-bg)]",
  error: "border-[var(--error-border)] bg-[var(--error-bg)]",
  warning: "border-[var(--warning-border)] bg-[var(--warning-bg)]",
};

const typeIcons = {
  success: "✓",
  error: "✕",
  warning: "⚠",
  info: "i",
};

function ToastItem({ toast, onDismiss }) {
  const [exiting, setExiting] = useState(false);

  const handleDismiss = () => {
    setExiting(true);
    setTimeout(onDismiss, 200);
  };

  return (
    <div
      className={[
        "pointer-events-auto w-80 rounded-[var(--radius-xl)] border px-4 py-3 shadow-[var(--shadow-lg)]",
        "transition-all duration-200",
        exiting ? "opacity-0 translate-x-4" : "animate-toast-in",
        typeStyles[toast.type] || typeStyles.info,
      ].join(" ")}
      role="alert"
    >
      <div className="flex items-start gap-3">
        {typeIcons[toast.type] && (
          <span className="text-sm mt-0.5 shrink-0">{typeIcons[toast.type]}</span>
        )}
        <div className="flex-1 min-w-0">
          {toast.title && <p className="text-sm font-semibold text-[var(--fg-primary)]">{toast.title}</p>}
          <p className="text-[13px] text-[var(--fg-secondary)]">{toast.message}</p>
        </div>
        <button
          onClick={handleDismiss}
          className="shrink-0 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors"
          aria-label="Dismiss"
        >
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M4 4l8 8M12 4l-8 8" />
          </svg>
        </button>
      </div>
      {toast.action && (
        <div className="mt-2 flex gap-2">
          <button
            onClick={() => { toast.action.onClick?.(); handleDismiss(); }}
            className="text-xs font-medium text-[var(--accent-cyan)] hover:underline"
          >
            {toast.action.label}
          </button>
        </div>
      )}
    </div>
  );
}

export default memo(ToastProvider);
