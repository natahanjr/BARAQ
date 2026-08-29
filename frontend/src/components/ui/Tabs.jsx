import { memo, useState, useCallback, useEffect, useRef } from "react";

export function Tabs({ tabs, active, onChange, className = "" }) {
  const tabRefs = useRef({});
  const [indicator, setIndicator] = useState({ left: 0, width: 0 });

  useEffect(() => {
    const el = tabRefs.current[active];
    if (!el) return;
    setIndicator({ left: el.offsetLeft, width: el.offsetWidth });
  }, [active]);

  return (
    <div className={["relative flex gap-0.5 border-b border-[var(--border-subtle)]", className].join(" ")}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          ref={(el) => { tabRefs.current[tab.id] = el; }}
          onClick={() => onChange(tab.id)}
          className={[
            "relative px-3.5 py-2 text-[13px] font-medium transition-colors duration-[var(--duration-fast)]",
            active === tab.id
              ? "text-[var(--fg-primary)]"
              : "text-[var(--fg-muted)] hover:text-[var(--fg-secondary)]",
          ].join(" ")}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span className="ml-1.5 text-[10px] text-[var(--fg-muted)]">({tab.count})</span>
          )}
        </button>
      ))}
      <span
        className="absolute bottom-0 h-0.5 rounded-full bg-[var(--accent-cyan)] transition-all duration-[var(--duration-normal)]"
        style={{ left: indicator.left, width: indicator.width }}
      />
    </div>
  );
}

export default memo(Tabs);
