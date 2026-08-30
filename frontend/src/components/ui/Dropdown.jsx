import { memo, useState, useRef, useEffect, useCallback } from "react";
import { useFocusTrap } from "../../hooks/useFocusTrap.js";

const FOCUSABLE = "button:not([disabled]), a[href], [tabindex]:not([tabindex='-1'])";

function Dropdown({ trigger, children, align = "left", className = "" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const prevOpen = useRef(false);

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

  useEffect(() => {
    if (open) {
      menuRef.current?.querySelector(FOCUSABLE)?.focus();
    } else if (prevOpen.current) {
      triggerRef.current?.focus();
    }
    prevOpen.current = open;
  }, [open]);

  const close = useCallback(() => setOpen(false), []);
  const toggle = useCallback(() => setOpen((o) => !o), []);

  return (
    <div ref={ref} className={["relative inline-flex", className].join(" ")}>
      <div
        ref={triggerRef}
        role="button"
        tabIndex={0}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={toggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggle();
          }
        }}
        className="inline-flex cursor-pointer rounded-[var(--radius-md)] outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent-cyan)]"
      >
        {trigger}
      </div>
      {open && (
        <div
          ref={menuRef}
          role="menu"
          aria-label="Menu"
          className={[
            "absolute top-full z-20 mt-1 min-w-[180px] rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 shadow-[var(--shadow-lg)] py-1 animate-in",
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
      role="menuitem"
      onClick={onClick}
      className={[
        "flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12px] transition-colors outline-none focus-visible:bg-[var(--bg-surface-hover)]",
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
