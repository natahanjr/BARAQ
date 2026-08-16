const LEVEL_STYLES = {
  CRITICAL: { chip: "border-red-500/40 bg-red-500/15 text-red-400", dot: "bg-red-500" },
  HIGH: { chip: "border-orange-500/40 bg-orange-500/15 text-orange-400", dot: "bg-orange-400" },
  MEDIUM: { chip: "border-amber-500/40 bg-amber-500/15 text-amber-400", dot: "bg-amber-400" },
  LOW: { chip: "border-emerald-500/40 bg-emerald-500/15 text-emerald-400", dot: "bg-emerald-400" },
};

export default function RiskBadge({ level = "LOW", score, className = "" }) {
  const l = String(level).toUpperCase();
  const style = LEVEL_STYLES[l] || LEVEL_STYLES.LOW;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide ${style.chip} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {l}
      {score !== undefined && score !== null && (
        <span className="font-mono opacity-80">({Number(score).toFixed(0)})</span>
      )}
    </span>
  );
}