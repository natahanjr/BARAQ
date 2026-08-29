import { memo } from "react";
import Tooltip from "./Tooltip.jsx";

function MITREBadge({ id, name, tactic, compact = false, onClick, className = "" }) {
  const tag = (
    <button
      onClick={onClick}
      className={[
        "inline-flex items-center gap-1.5 rounded-[var(--radius-md)] border border-[var(--accent-violet-muted)] bg-[var(--accent-violet-subtle)] font-mono transition-colors",
        compact ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-1 text-[11px]",
        onClick && "hover:bg-[var(--accent-violet-muted)] cursor-pointer",
        className,
      ].join(" ")}
    >
      <span className="font-bold text-[var(--accent-violet)]">{id}</span>
      {!compact && name && (
        <span className="text-[var(--fg-secondary)] max-w-[120px] truncate">{name}</span>
      )}
    </button>
  );

  if (compact && name) {
    return (
      <Tooltip content={`${id} — ${name}${tactic ? ` (${tactic})` : ""}`}>
        {tag}
      </Tooltip>
    );
  }

  return tag;
}

export default memo(MITREBadge);
