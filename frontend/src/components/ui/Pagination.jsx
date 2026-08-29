import { memo, useMemo } from "react";

function Pagination({ page, total, perPage, onChange, className = "" }) {
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  const pages = useMemo(() => {
    const result = [];
    const delta = 2;
    const left = Math.max(2, page - delta);
    const right = Math.min(totalPages - 1, page + delta);
    result.push(1);
    if (left > 2) result.push("...");
    for (let i = left; i <= right; i++) result.push(i);
    if (right < totalPages - 1) result.push("...");
    if (totalPages > 1) result.push(totalPages);
    return result;
  }, [page, totalPages]);

  if (totalPages <= 1) return null;

  const btn = (p, label, disabled = false) => (
    <button
      key={label}
      onClick={() => onChange(p)}
      disabled={disabled}
      className={[
        "h-8 min-w-[32px] px-2 rounded-[var(--radius-md)] text-[12px] font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-cyan)]",
        "disabled:opacity-40 disabled:pointer-events-none",
        p === page
          ? "bg-[var(--accent-cyan)] text-[var(--bg-app)]"
          : "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]",
      ].join(" ")}
    >
      {label}
    </button>
  );

  return (
    <div className={["flex items-center gap-1", className].join(" ")}>
      {btn(page - 1, "‹", page <= 1)}
      {pages.map((p, i) =>
        p === "..." ? (
          <span key={`e${i}`} className="px-1 text-[var(--fg-muted)]">…</span>
        ) : (
          btn(p, p)
        )
      )}
      {btn(page + 1, "›", page >= totalPages)}
    </div>
  );
}

export default memo(Pagination);
