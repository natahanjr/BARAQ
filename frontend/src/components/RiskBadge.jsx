const LEVEL_STYLES = {
  CRITICAL: {
    chip: "border-red-500/25 bg-red-500/[0.08] text-red-300",
    dot: "bg-red-400 shadow-[0_0_6px_rgba(255,107,147,0.6)]",
  },
  HIGH: {
    chip: "border-orange-500/25 bg-orange-500/[0.08] text-orange-300",
    dot: "bg-orange-400 shadow-[0_0_5px_rgba(251,146,60,0.5)]",
  },
  MEDIUM: {
    chip: "border-amber-500/20 bg-amber-500/[0.06] text-amber-300",
    dot: "bg-amber-400",
  },
  LOW: {
    chip: "border-emerald-500/20 bg-emerald-500/[0.06] text-emerald-300",
    dot: "bg-emerald-400",
  },
};

export default function RiskBadge({ level = "LOW", score, className = "" }) {
  const l = String(level).toUpperCase();
  const style = LEVEL_STYLES[l] || LEVEL_STYLES.LOW;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[10px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
    >
      <span className={`h-[5px] w-[5px] rounded-full ${style.dot}`} />
      {l}
      {score !== undefined && score !== null && (
        <span className="font-mono text-[9px] opacity-70">{Number(score).toFixed(0)}</span>
      )}
    </span>
  );
}
