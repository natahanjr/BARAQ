import { memo } from "react";

const severityColors = {
  critical: "border-[var(--severity-critical)] bg-[var(--severity-critical)]",
  high: "border-[var(--severity-high)] bg-[var(--severity-high)]",
  medium: "border-[var(--severity-medium)] bg-[var(--severity-medium)]",
  low: "border-[var(--severity-low)] bg-[var(--severity-low)]",
  info: "border-[var(--fg-muted)] bg-[var(--fg-muted)]",
};

function TimelineEntry({ timestamp, title, description, severity = "info", icon: Icon, active = false, onClick, className = "" }) {
  const fmtTime = (ts) => {
    if (!ts) return "";
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  };

  return (
    <div
      className={[
        "relative flex gap-3 pb-4 group",
        onClick && "cursor-pointer",
        className,
      ].join(" ")}
      onClick={onClick}
    >
      {/* Timeline line + dot */}
      <div className="flex flex-col items-center shrink-0">
        <span className={[
          "relative z-10 flex h-2.5 w-2.5 items-center justify-center rounded-full border-2 transition-all",
          severityColors[severity] || severityColors.info,
          active && "ring-2 ring-[var(--accent-cyan)] ring-offset-2 ring-offset-[var(--bg-app)]",
        ].join(" ")} />
        <div className="w-px flex-1 bg-[var(--border-subtle)] mt-1" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0 -mt-0.5">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="h-3.5 w-3.5 text-[var(--fg-muted)] shrink-0" />}
          <span className="text-[11px] font-mono text-[var(--fg-muted)]">{fmtTime(timestamp)}</span>
        </div>
        <p className="mt-0.5 text-[13px] font-medium text-[var(--fg-primary)] leading-tight">{title}</p>
        {description && (
          <p className="mt-0.5 text-[12px] text-[var(--fg-muted)] leading-relaxed line-clamp-2">{description}</p>
        )}
      </div>
    </div>
  );
}

export default memo(TimelineEntry);
