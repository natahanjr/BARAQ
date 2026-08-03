const LEVEL_STYLES = {
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
};

export default function RiskBadge({ level = "LOW", score }) {
  const l = String(level).toUpperCase();
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-semibold tracking-wide ${
        LEVEL_STYLES[l] || LEVEL_STYLES.LOW
      }`}
    >
      {l}
      {score !== undefined && score !== null && (
        <span className="font-mono opacity-80">({Number(score).toFixed(0)})</span>
      )}
    </span>
  );
}
