const LEVEL = {
  CRITICAL: {
    chip: "border-[var(--severity-critical-border)] bg-[var(--severity-critical-muted)] text-[var(--severity-critical)]",
    glyph: "■",
  },
  HIGH: {
    chip: "border-[var(--severity-high-border)] bg-[var(--severity-high-muted)] text-[var(--severity-high)]",
    glyph: "▲",
  },
  MEDIUM: {
    chip: "border-[var(--severity-medium-border)] bg-[var(--severity-medium-muted)] text-[var(--severity-medium)]",
    glyph: "●",
  },
  LOW: {
    chip: "border-[var(--status-healthy-border)] bg-[var(--status-healthy-muted)] text-[var(--status-healthy)]",
    glyph: "○",
  },
};

export default function RiskBadge({ level = "LOW", score, className = "" }) {
  const l = String(level).toUpperCase();
  const style = LEVEL[l] || LEVEL.LOW;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[11px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
    >
      <span aria-hidden="true" className="text-[9px] leading-none">{style.glyph}</span>
      {l}
      {score !== undefined && score !== null && (
        <span className="font-mono text-[11px] opacity-70">{Number(score).toFixed(0)}</span>
      )}
    </span>
  );
}
