const SEVERITY = {
  critical: {
    chip: "border-[var(--severity-critical-border)] bg-[var(--severity-critical-muted)] text-[var(--severity-critical)]",
    glyph: "■",
  },
  high: {
    chip: "border-[var(--severity-high-border)] bg-[var(--severity-high-muted)] text-[var(--severity-high)]",
    glyph: "▲",
  },
  medium: {
    chip: "border-[var(--severity-medium-border)] bg-[var(--severity-medium-muted)] text-[var(--severity-medium)]",
    glyph: "●",
  },
  low: {
    chip: "border-[var(--severity-low-border)] bg-[var(--severity-low-muted)] text-[var(--severity-low)]",
    glyph: "○",
  },
  info: {
    chip: "border-[var(--border-default)] bg-[var(--bg-surface-hover)] text-[var(--fg-secondary)]",
    glyph: "–",
  },
};

export default function SeverityBadge({ severity = "info", className = "" }) {
  const s = String(severity).toLowerCase();
  const style = SEVERITY[s] || SEVERITY.info;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[11px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
      title={s.toUpperCase()}
    >
      <span aria-hidden="true" className="text-[9px] leading-none">{style.glyph}</span>
      {s}
    </span>
  );
}
