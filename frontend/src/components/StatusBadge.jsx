const STATUS = {
  open: {
    chip: "border-[var(--severity-critical-border)] bg-[var(--severity-critical-muted)] text-[var(--severity-critical)]",
    glyph: "●",
  },
  in_progress: {
    chip: "border-[var(--severity-medium-border)] bg-[var(--severity-medium-muted)] text-[var(--severity-medium)]",
    glyph: "◐",
  },
  investigating: {
    chip: "border-[var(--severity-medium-border)] bg-[var(--severity-medium-muted)] text-[var(--severity-medium)]",
    glyph: "◑",
  },
  contained: {
    chip: "border-[var(--accent-violet-border)] bg-[var(--accent-violet-muted)] text-[var(--accent-violet)]",
    glyph: "◆",
  },
  closed: {
    chip: "border-[var(--status-healthy-border)] bg-[var(--status-healthy-muted)] text-[var(--status-healthy)]",
    glyph: "✓",
  },
  resolved: {
    chip: "border-[var(--status-healthy-border)] bg-[var(--status-healthy-muted)] text-[var(--status-healthy)]",
    glyph: "✓",
  },
  dismissed: {
    chip: "border-[var(--border-default)] bg-[var(--bg-surface-hover)] text-[var(--fg-muted)]",
    glyph: "–",
  },
};

export default function StatusBadge({ status = "open", className = "" }) {
  const s = String(status).toLowerCase();
  const style = STATUS[s] || STATUS.open;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-[3px] text-[11px] font-semibold tracking-wide uppercase ${style.chip} ${className}`}
    >
      <span aria-hidden="true" className="text-[9px] leading-none">{style.glyph}</span>
      {s}
    </span>
  );
}
