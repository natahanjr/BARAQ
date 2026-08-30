import { memo, useRef, useEffect } from "react";

const ACCENT_STYLES = {
  cyan: {
    iconBg: "bg-[var(--accent-cyan)]/[0.12]",
    iconColor: "text-[var(--accent-cyan)]",
    glow: "shadow-[0_0_20px_-6px_var(--accent-cyan)]",
    border: "hover:border-[var(--accent-cyan)]/30",
    barColor: "var(--accent-cyan)",
    gradient: "from-[var(--accent-cyan)]/[0.06] to-transparent",
  },
  violet: {
    iconBg: "bg-[var(--accent-violet)]/[0.12]",
    iconColor: "text-[var(--accent-violet)]",
    glow: "shadow-[0_0_20px_-6px_var(--accent-violet)]",
    border: "hover:border-[var(--accent-violet)]/30",
    barColor: "var(--accent-violet)",
    gradient: "from-[var(--accent-violet)]/[0.06] to-transparent",
  },
  red: {
    iconBg: "bg-[var(--severity-critical)]/[0.12]",
    iconColor: "text-[var(--severity-critical)]",
    glow: "shadow-[0_0_20px_-6px_var(--severity-critical)]",
    border: "hover:border-[var(--severity-critical)]/30",
    barColor: "var(--severity-critical)",
    gradient: "from-[var(--severity-critical)]/[0.06] to-transparent",
  },
  orange: {
    iconBg: "bg-[var(--severity-high)]/[0.12]",
    iconColor: "text-[var(--severity-high)]",
    glow: "shadow-[0_0_20px_-6px_var(--severity-high)]",
    border: "hover:border-[var(--severity-high)]/30",
    barColor: "var(--severity-high)",
    gradient: "from-[var(--severity-high)]/[0.06] to-transparent",
  },
  amber: {
    iconBg: "bg-[var(--severity-medium)]/[0.12]",
    iconColor: "text-[var(--severity-medium)]",
    glow: "shadow-[0_0_20px_-6px_var(--severity-medium)]",
    border: "hover:border-[var(--severity-medium)]/30",
    barColor: "var(--severity-medium)",
    gradient: "from-[var(--severity-medium)]/[0.06] to-transparent",
  },
  blue: {
    iconBg: "bg-[var(--severity-low)]/[0.12]",
    iconColor: "text-[var(--severity-low)]",
    glow: "shadow-[0_0_20px_-6px_var(--severity-low)]",
    border: "hover:border-[var(--severity-low)]/30",
    barColor: "var(--severity-low)",
    gradient: "from-[var(--severity-low)]/[0.06] to-transparent",
  },
  green: {
    iconBg: "bg-[var(--status-healthy)]/[0.12]",
    iconColor: "text-[var(--status-healthy)]",
    glow: "shadow-[0_0_20px_-6px_var(--status-healthy)]",
    border: "hover:border-[var(--status-healthy)]/30",
    barColor: "var(--status-healthy)",
    gradient: "from-[var(--status-healthy)]/[0.06] to-transparent",
  },
};

function MetricCard({ label, value, icon: Icon, trend, trendLabel, accent = "cyan", loading = false, zeroLabel, className = "" }) {
  const numRef = useRef(null);
  const prevVal = useRef(0);

  useEffect(() => {
    const el = numRef.current;
    if (!el) return;
    const target = Number(value) || 0;
    const start = prevVal.current;
    prevVal.current = target;
    if (start === target) { el.textContent = target.toLocaleString(); return; }
    const prefersReduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (prefersReduced) { el.textContent = target.toLocaleString(); return; }
    const duration = 600;
    const t0 = performance.now();
    let raf;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / duration);
      const ease = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(start + (target - start) * ease).toLocaleString();
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  const s = ACCENT_STYLES[accent] || ACCENT_STYLES.cyan;

  if (loading) {
    return (
      <div className={["rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-5", className].join(" ")}>
        <div className="h-3 w-20 rounded bg-[var(--bg-surface-active)] animate-pulse" />
        <div className="mt-3 h-8 w-16 rounded bg-[var(--bg-surface-active)] animate-pulse" />
      </div>
    );
  }

  return (
    <div className={[
      "group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-300 p-5",
      s.border,
      "hover:shadow-lg",
      className,
    ].join(" ")}>
      {/* Top-left gradient glow */}
      <div className={`absolute -left-8 -top-8 h-24 w-24 rounded-full bg-gradient-to-br ${s.gradient} blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-100`} />

      <div className="relative flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <p className="text-label text-[var(--fg-muted)]">
            {label}
          </p>
          <div className="mt-2 flex items-end gap-2.5">
            <span
              ref={numRef}
              className="text-[32px] font-bold tabular-nums tracking-tight text-[var(--fg-primary)] leading-none"
              style={{ fontFeatureSettings: '"tnum"' }}
            >
              {Number(value || 0).toLocaleString()}
            </span>
            {trend !== undefined && (
              <span className={`mb-1 flex items-center gap-0.5 text-[11px] font-semibold ${trend >= 0 ? "text-[var(--status-healthy)]" : "text-[var(--severity-critical)]"}`}>
                <span className="text-[11px]">{trend >= 0 ? "\u25B2" : "\u25BC"}</span>
                {Math.abs(trend)}%
              </span>
            )}
          </div>
          {Number(value || 0) === 0 && zeroLabel ? (
            <p className="mt-1.5 flex items-center gap-1 text-[11px] text-[var(--status-healthy)]">
              <svg className="h-3 w-3" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 8l3 3 7-7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              {zeroLabel}
            </p>
          ) : trendLabel ? (
            <p className="mt-1.5 text-[11px] text-[var(--fg-muted)]">{trendLabel}</p>
          ) : null}
        </div>

        {/* Icon with glowing background */}
        {Icon && (
          <div className={`relative flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--radius-lg)] ${s.iconBg} transition-all duration-300 group-hover:scale-110`}>
            <Icon className={`h-5 w-5 ${s.iconColor}`} />
          </div>
        )}
      </div>

      {/* Bottom accent bar */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-current to-transparent opacity-0 transition-opacity duration-300 group-hover:opacity-40" style={{ color: s.barColor }} />
    </div>
  );
}

export default memo(MetricCard);
