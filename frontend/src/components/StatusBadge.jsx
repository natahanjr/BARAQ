const STATUS_STYLES = {
  open: "bg-rose-500/15 text-rose-400 border-rose-500/40",
  investigating: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  resolved: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  dismissed: "bg-slate-500/15 text-slate-400 border-slate-500/40",
};

export default function StatusBadge({ status = "open" }) {
  const s = String(status).toLowerCase();
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${
        STATUS_STYLES[s] || STATUS_STYLES.open
      }`}
    >
      {s}
    </span>
  );
}
