import { memo, useState, useRef, useEffect } from "react";

function Tooltip({ children, content, side = "top", delay = 300, className = "" }) {
  const [open, setOpen] = useState(false);
  const timer = useRef(null);
  const triggerRef = useRef(null);

  const show = () => { timer.current = setTimeout(() => setOpen(true), delay); };
  const hide = () => { clearTimeout(timer.current); setOpen(false); };

  useEffect(() => () => clearTimeout(timer.current), []);

  if (!content) return children;

  const positions = {
    top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
    bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
    left: "right-full top-1/2 -translate-y-1/2 mr-2",
    right: "left-full top-1/2 -translate-y-1/2 ml-2",
  };

  return (
    <div
      ref={triggerRef}
      className={["relative inline-flex", className].join(" ")}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {children}
      {open && (
        <div
          className={[
            "absolute z-[var(--z-tooltip)] pointer-events-none",
            "rounded-[var(--radius-md)] bg-[var(--bg-surface-overlay)] border border-[var(--border-default)]",
            "px-2.5 py-1.5 text-[11px] text-[var(--fg-primary)] shadow-[var(--shadow-md)]",
            "whitespace-nowrap animate-in",
            positions[side],
          ].join(" ")}
          role="tooltip"
        >
          {content}
        </div>
      )}
    </div>
  );
}

export default memo(Tooltip);
