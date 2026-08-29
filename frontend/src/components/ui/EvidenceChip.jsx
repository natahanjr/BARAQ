import { memo } from "react";

function EvidenceChip({ count, label, color = "cyan", onClick, className = "" }) {
  const colorMap = {
    cyan: "border-[var(--accent-cyan-muted)] bg-[var(--accent-cyan-subtle)] text-[var(--accent-cyan)]",
    violet: "border-[var(--accent-violet-muted)] bg-[var(--accent-violet-subtle)] text-[var(--accent-violet)]",
    red: "border-[var(--severity-critical-muted)] bg-[var(--severity-critical-subtle)] text-[var(--severity-critical)]",
    orange: "border-[var(--severity-high-muted)] bg-[var(--severity-high-subtle)] text-[var(--severity-high)]",
    amber: "border-[var(--severity-medium-muted)] bg-[var(--severity-medium-subtle)] text-[var(--severity-medium)]",
    green: "border-[var(--status-healthy-muted)] bg-[rgba(34,197,94,0.08)] text-[var(--status-healthy)]",
  };

  return (
    <button
      onClick={onClick}
      className={[
        "inline-flex items-center gap-1.5 rounded-[var(--radius-lg)] border px-2.5 py-1 text-[11px] font-semibold transition-all",
        colorMap[color] || colorMap.cyan,
        onClick && "hover:brightness-110 cursor-pointer",
        className,
      ].join(" ")}
    >
      <span className="tabular-nums">{count}</span>
      <span className="opacity-70">{label}</span>
    </button>
  );
}

export default memo(EvidenceChip);
