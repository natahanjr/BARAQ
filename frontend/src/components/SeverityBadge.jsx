// Severity is never communicated by color alone — each level also carries
// a shape marker (● ▲ ◆ ○) for color-independent recognition.
const SEVERITY_STYLES = {
  critical: { chip: "border-red-500/40 bg-red-500/15 text-red-400", mark: "●", markCls: "text-red-400" },
  high: { chip: "border-orange-500/40 bg-orange-500/15 text-orange-400", mark: "▲", markCls: "text-orange-400" },
  medium: { chip: "border-amber-500/40 bg-amber-500/15 text-amber-400", mark: "◆", markCls: "text-amber-400" },
  low: { chip: "border-sky-500/40 bg-sky-500/15 text-sky-400", mark: "○", markCls: "text-sky-400" },
  info: { chip: "border-slate-500/40 bg-slate-500/15 text-slate-400", mark: "○", markCls: "text-slate-400" },
};

export default function SeverityBadge({ severity = "info", className = "" }) {
  const s = String(severity).toLowerCase();
  const style = SEVERITY_STYLES[s] || SEVERITY_STYLES.info;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${style.chip} ${className}`}
      title={`${s.toUpperCase()} (${style.mark})`}
    >
      <span className={`text-[10px] leading-none ${style.markCls}`}>{style.mark}</span>
      {s}
    </span>
  );
}