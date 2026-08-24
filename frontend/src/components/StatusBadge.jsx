const STATUS_STYLES = {
  open: {
    chip: "border-rose-500/25 bg-rose-500/[0.08] text-rose-300",
    dot: "bg-rose-400 shadow-[0_0_5px_rgba(251,113,133,0.5)]",
  },
  in_progress: {
    chip: "border-amber-500/25 bg-amber-500/[0.08] text-amber-300",
    dot: "bg-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.5)]",
  },
  investigating: {
    chip: "border-amber-500/25 bg-amber-500/[0.08] text-amber-300",
    dot: "bg-amber-400 shadow-[0_0_5px_rgba(251,191,36,0.5)]",
  },
  contained: {
    chip: "border-violet-500/25 bg-violet-500/[0.08] text-violet-300",
    dot: "bg-violet-400 shadow-[0_0_5px_rgba(167,139,250,0.5)]",
  },
  closed: {
    chip: "border-emerald-500/25 bg-emerald-500/[0.08] text-emerald-300",
    dot: "bg-emerald-400",
  },
  resolved: {
    chip: "border-emerald-500/25 bg-emerald-500/[0.08] text-emerald-300",
    dot: "bg-emerald-400",
  },
  dismissed: {
    chip: "border-slate-500/20 bg-slate-500/[0.06] text-slate-400",
    dot: "bg-slate-400",
  },
};

export default function StatusBadge({ status = "open", className = "" }) {
  const s = String(status).toLowerCase();
  const style = STATUS_STYLES[s] || STATUS_STYLES.open;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[10px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
    >
      <span className={`h-[5px] w-[5px] rounded-full ${style.dot}`} />
      {s}
    </span>
  );
}
