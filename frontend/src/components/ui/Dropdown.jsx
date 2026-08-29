import { memo, useState, useRef, useEffect, useCallback } from "react";

function Dropdown({ trigger, children, align = "left", className = "" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open]);

  const close = useCallback(() => setOpen(false), []);

  return (
    <div ref={ref} className={["relative inline-flex", className].join(" ")}>
      <div onClick={() => setOpen(!open)} className="cursor-pointer">
        {trigger}
      </div>
      {open && (
        <div
          className={[
            "absolute top-full z-20 mt-1 min-w-[180px] rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] shadow-[var(--shadow-lg)] py-1 animate-in",
            align === "right" ? "right-0" : "left-0",
          ].join(" ")}
        >
          {typeof children === "function" ? children({ close }) : children}
        </div>
      )}
    </div>
  );
}

export function DropdownItem({ onClick, children, danger = false, className = "" }) {
  return (
    <button
      onClick={onClick}
      className={[
        "flex w-full items-center gap-2 px-3 py-1.5 text-[12px] transition-colors",
        danger
          ? "text-[var(--severity-critical)] hover:bg-[var(--severity-critical-subtle)]"
          : "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]",
        className,
      ].join(" ")}
    >
      {children}
    </button>
  );
}

export function DropdownSeparator() {
  return <div className="my-1 border-t border-[var(--border-subtle)]" />;
}

export default memo(Dropdown);
