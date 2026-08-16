export function Loading({ label = "Loading" }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border border-white/5 bg-white/[0.02] py-20">
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
        <div className="absolute inset-0 animate-pulse rounded-full border border-cyan-500/20" />
      </div>
      <p className="mt-4 text-sm text-slate-400">{label}...</p>
    </div>
  );
}

export function EmptyState({ title = "No data", subtitle, icon = "◌" }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-700/60 bg-white/[0.02] py-16 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700/60 bg-white/[0.04] text-2xl text-slate-500">
        {icon}
      </div>
      <p className="mt-4 text-sm font-semibold text-slate-300">{title}</p>
      {subtitle && <p className="mt-1 max-w-sm text-xs text-slate-500">{subtitle}</p>}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
      <span className="flex items-center gap-2">
        <span aria-hidden>⚠</span>
        <span>{message}</span>
      </span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20"
        >
          Retry
        </button>
      )}
    </div>
  );
}