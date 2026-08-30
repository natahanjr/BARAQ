import { memo, useState, useCallback } from "react";

export function FilterBar({ filters = [], activeFilters = {}, onChange, onClear, className = "" }) {
  const [openDropdown, setOpenDropdown] = useState(null);

  const toggleFilter = useCallback((key, value) => {
    const current = activeFilters[key] || [];
    const next = current.includes(value)
      ? current.filter((v) => v !== value)
      : [...current, value];
    onChange({ ...activeFilters, [key]: next.length ? next : undefined });
  }, [activeFilters, onChange]);

  const activeCount = Object.values(activeFilters).filter(Boolean).flat().length;

  return (
    <div className={["flex items-center gap-2 flex-wrap", className].join(" ")}>
      {filters.map((filter) => (
        <div key={filter.key} className="relative">
          <button
            onClick={() => setOpenDropdown(openDropdown === filter.key ? null : filter.key)}
            className={[
              "inline-flex items-center gap-1.5 rounded-[var(--radius-lg)] border px-2.5 py-1.5 text-[12px] font-medium transition-colors",
              (activeFilters[filter.key]?.length)
                ? "border-[var(--accent-cyan-muted)] bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]"
                : "border-[var(--border-default)] bg-[var(--bg-surface)] text-[var(--fg-secondary)] hover:border-[var(--border-strong)]",
            ].join(" ")}
          >
            {filter.label}
            {(activeFilters[filter.key]?.length) && (
              <span className="text-[11px] opacity-70">({activeFilters[filter.key].length})</span>
            )}
            <svg className="h-3 w-3 opacity-50" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 6l4 4 4-4" />
            </svg>
          </button>
          {openDropdown === filter.key && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setOpenDropdown(null)} />
              <div className="absolute top-full left-0 z-20 mt-1 min-w-[160px] rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 shadow-[var(--shadow-lg)] py-1 animate-in">
                {filter.options.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => toggleFilter(filter.key, opt.value)}
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-[12px] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)] transition-colors"
                  >
                    <span className={[
                      "h-3.5 w-3.5 rounded-[var(--radius-sm)] border flex items-center justify-center shrink-0 transition-colors",
                      (activeFilters[filter.key] || []).includes(opt.value)
                        ? "border-[var(--accent-cyan)] bg-[var(--accent-cyan)]"
                        : "border-[var(--border-strong)]",
                    ].join(" ")}>
                      {(activeFilters[filter.key] || []).includes(opt.value) && (
                        <svg className="h-2.5 w-2.5 text-[var(--bg-app)]" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="3">
                          <path d="M3 8l3 3 7-7" />
                        </svg>
                      )}
                    </span>
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      ))}
      {activeCount > 0 && onClear && (
        <button
          onClick={() => { onClear(); setOpenDropdown(null); }}
          className="text-[11px] font-medium text-[var(--fg-muted)] hover:text-[var(--severity-critical)] transition-colors"
        >
          Clear all ({activeCount})
        </button>
      )}
    </div>
  );
}

export default memo(FilterBar);
