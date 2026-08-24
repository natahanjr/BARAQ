const SEVERITY_STYLES = {
  critical: {
    chip: "border-red-500/25 bg-red-500/[0.08] text-red-300",
    dot: "bg-red-400 shadow-[0_0_6px_rgba(255,107,147,0.6)]",
  },
  high: {
    chip: "border-orange-500/25 bg-orange-500/[0.08] text-orange-300",
    dot: "bg-orange-400 shadow-[0_0_5px_rgba(251,146,60,0.5)]",
  },
  medium: {
    chip: "border-blue-400/20 bg-blue-400/[0.06] text-blue-300",
    dot: "bg-blue-400",
  },
  low: {
    chip: "border-slate-400/15 bg-slate-400/[0.05] text-slate-300",
    dot: "bg-slate-400",
  },
  info: {
    chip: "border-slate-400/15 bg-slate-400/[0.04] text-slate-400",
    dot: "bg-slate-500",
  },
};

export default function SeverityBadge({ severity = "info", className = "" }) {
  const s = String(severity).toLowerCase();
  const style = SEVERITY_STYLES[s] || SEVERITY_STYLES.info;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[10px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
      title={s.toUpperCase()}
    >
      <span
        className={`h-[5px] w-[5px] rounded-full ${style.dot} ${
          s === "critical" ? "badge-critical" : ""
        }`}
      />
      {s}
    </span>
  );
}
