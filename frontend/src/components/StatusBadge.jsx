const STATUS_STYLES = {
  open: { chip: "border-rose-500/40 bg-rose-500/15 text-rose-400", dot: "bg-rose-500" },
  in_progress: { chip: "border-amber-500/40 bg-amber-500/15 text-amber-400", dot: "bg-amber-400" },
  investigating: { chip: "border-amber-500/40 bg-amber-500/15 text-amber-400", dot: "bg-amber-400" },
  contained: { chip: "border-violet-500/40 bg-violet-500/15 text-violet-400", dot: "bg-violet-400" },
  closed: { chip: "border-emerald-500/40 bg-emerald-500/15 text-emerald-400", dot: "bg-emerald-400" },
  resolved: { chip: "border-emerald-500/40 bg-emerald-500/15 text-emerald-400", dot: "bg-emerald-400" },
  dismissed: { chip: "border-slate-500/40 bg-slate-500/15 text-slate-400", dot: "bg-slate-400" },
};

export default function StatusBadge({ status = "open", className = "" }) {
  const s = String(status).toLowerCase();
  const style = STATUS_STYLES[s] || STATUS_STYLES.open;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${style.chip} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {s}
    </span>
  );
}