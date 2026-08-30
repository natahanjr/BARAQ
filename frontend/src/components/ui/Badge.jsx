import { memo } from "react";

const severityConfig = {
  critical: {
    bg: "bg-[var(--severity-critical-subtle)]",
    text: "text-[var(--severity-critical)]",
    border: "border-[var(--severity-critical-muted)]",
    dot: "bg-[var(--severity-critical)]",
  },
  high: {
    bg: "bg-[var(--severity-high-subtle)]",
    text: "text-[var(--severity-high)]",
    border: "border-[var(--severity-high-muted)]",
    dot: "bg-[var(--severity-high)]",
  },
  medium: {
    bg: "bg-[var(--severity-medium-subtle)]",
    text: "text-[var(--severity-medium)]",
    border: "border-[var(--severity-medium-muted)]",
    dot: "bg-[var(--severity-medium)]",
  },
  low: {
    bg: "bg-[var(--severity-low-subtle)]",
    text: "text-[var(--severity-low)]",
    border: "border-[var(--severity-low-muted)]",
    dot: "bg-[var(--severity-low)]",
  },
  info: {
    bg: "bg-[var(--severity-info-subtle)]",
    text: "text-[var(--fg-muted)]",
    border: "border-[var(--severity-info-muted)]",
    dot: "bg-[var(--severity-info)]",
  },
};

const sizeConfig = {
  sm: "px-1.5 py-0. text-[11px] gap-1",
  md: "px-2 py-0.5 text-[11px] gap-1.5",
  lg: "px-2.5 py-1 text-xs gap-1.5",
};

export function Badge({ severity = "info", size = "md", dot = false, pulse = false, children, className = "" }) {
  const s = severityConfig[severity] || severityConfig.info;
  return (
    <span
      className={[
        "inline-flex items-center font-semibold rounded-full border leading-none whitespace-nowrap",
        s.bg, s.text, s.border,
        sizeConfig[size],
        className,
      ].join(" ")}
    >
      {dot && (
        <span className={['h-1.5 w-1.5 rounded-full shrink-0', s.dot, pulse && 'animate-pulse'].join(' ')} />
      )}
      {children}
    </span>
  );
}

export function CountBadge({ count, critical = false, className = "" }) {
  if (!count && count !== 0) return null;
  const display = count > 999 ? "999+" : count;
  return (
    <span
      className={[
        "inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[11px] font-bold tabular-nums leading-none",
        critical
          ? "bg-[var(--severity-critical-muted)] text-[var(--severity-critical)]"
          : "bg-[var(--bg-surface-active)] text-[var(--fg-muted)]",
        className,
      ].join(" ")}
    >
      {display}
    </span>
  );
}

export function StatusDot({ status, size = "sm", pulse = false, className = "" }) {
  const colors = {
    online: "bg-[var(--status-healthy)]",
    healthy: "bg-[var(--status-healthy)]",
    warning: "bg-[var(--status-warning)]",
    degraded: "bg-[var(--status-warning)]",
    danger: "bg-[var(--status-danger)]",
    offline: "bg-[var(--status-danger)]",
    unknown: "bg-[var(--fg-muted)]",
  };
  const sizes = { xs: "h-1.5 w-1.5", sm: "h-2 w-2", md: "h-2.5 w-2.5", lg: "h-3 w-3" };
  return (
    <span
      className={[
        "inline-block rounded-full shrink-0",
        colors[status] || colors.unknown,
        sizes[size] || sizes.sm,
        (pulse || status === "online" || status === "healthy") && "animate-pulse",
        className,
      ].join(" ")}
    />
  );
}

export default memo(Badge);
