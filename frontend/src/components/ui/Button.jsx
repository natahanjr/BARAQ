import { forwardRef, memo } from "react";

const variants = {
  primary: "bg-[var(--accent-cyan)] text-[var(--fg-inverse)] hover:brightness-110 shadow-[var(--shadow-sm)]",
  secondary: "bg-[var(--bg-surface-raised)] text-[var(--fg-primary)] border border-[var(--border-default)] hover:bg-[var(--bg-surface-hover)]",
  ghost: "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]",
  danger: "bg-[var(--severity-critical)] text-white hover:brightness-110 shadow-[var(--shadow-sm)]",
  "danger-ghost": "text-[var(--severity-critical)] hover:bg-[var(--severity-critical-subtle)]",
};

const sizes = {
  xs: "h-7 px-2.5 text-[11px] gap-1.5 rounded-[var(--radius-md)]",
  sm: "h-8 px-3 text-xs gap-1.5 rounded-[var(--radius-lg)]",
  md: "h-9 px-4 text-sm gap-2 rounded-[var(--radius-lg)]",
  lg: "h-10 px-5 text-sm gap-2 rounded-[var(--radius-xl)]",
};

const Button = forwardRef(function Button({
  variant = "primary",
  size = "md",
  loading = false,
  icon: Icon,
  iconRight: IconRight,
  children,
  className = "",
  disabled,
  ...props
}, ref) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={[
        "inline-flex items-center justify-center font-medium transition-all duration-[var(--duration-fast)]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-cyan)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg-app)]",
        "disabled:opacity-50 disabled:pointer-events-none",
        "active:scale-[0.98]",
        variants[variant],
        sizes[size],
        className,
      ].join(" ")}
      {...props}
    >
      {loading ? (
        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      ) : Icon ? (
        <Icon className="h-4 w-4 shrink-0" />
      ) : null}
      {children}
      {IconRight && !loading && <IconRight className="h-4 w-4 shrink-0" />}
    </button>
  );
});

export default memo(Button);
