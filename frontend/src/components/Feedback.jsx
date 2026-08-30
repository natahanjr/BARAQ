export function Loading({ label = "Loading" }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border py-20"
      style={{ background: "var(--notice-bg, #fff)", borderColor: "var(--notice-border, #e2e8f0)" }}>
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 animate-spin rounded-full border-2 border-slate-300 border-t-cyan-500" />
        <div className="absolute inset-0 animate-pulse rounded-full border border-cyan-500/20" />
      </div>
      <p className="mt-4 text-sm" style={{ color: "var(--notice-text, #64748b)" }}>{label}...</p>
    </div>
  );
}

export function EmptyState({ title = "No data", subtitle, icon = "◌" }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed py-16 text-center"
      style={{ background: "var(--notice-bg, #fff)", borderColor: "var(--notice-border, #e2e8f0)" }}>
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border text-2xl"
        style={{ background: "var(--notice-bg, #f8fafc)", borderColor: "var(--notice-border, #e2e8f0)", color: "var(--notice-text, #64748b)" }}>
        {icon}
      </div>
      <p className="mt-4 text-sm font-semibold" style={{ color: "var(--notice-text, #1e293b)" }}>{title}</p>
      {subtitle && <p className="mt-1 max-w-sm text-sm" style={{ color: "var(--notice-text, #64748b)" }}>{subtitle}</p>}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border px-5 py-4 text-sm"
      style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
      <span className="flex items-center gap-2">
        <span aria-hidden>⚠</span>
        <span>{message}</span>
      </span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded-xl border px-4 py-2 text-sm font-medium transition-colors"
          style={{ borderColor: "var(--error-border, #fecaca)", background: "white", color: "var(--error-text, #991b1b)" }}
        >
          Retry
        </button>
      )}
    </div>
  );
}
