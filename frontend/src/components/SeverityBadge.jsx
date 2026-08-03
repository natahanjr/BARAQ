const SEVERITY_STYLES = {
  critical: "bg-red-500/15 text-red-400 border-red-500/40",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  low: "bg-sky-500/15 text-sky-400 border-sky-500/40",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/40",
};

export default function SeverityBadge({ severity = "info" }) {
  const s = String(severity).toLowerCase();
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${
        SEVERITY_STYLES[s] || SEVERITY_STYLES.info
      }`}
    >
      {s}
    </span>
  );
}
