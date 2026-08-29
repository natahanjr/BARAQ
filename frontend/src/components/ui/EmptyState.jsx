import { memo } from "react";

function EmptyState({ icon: Icon, title, description, action, className = "" }) {
  return (
    <div className={["flex flex-col items-center justify-center py-16 px-8 text-center", className].join(" ")}>
      {Icon && (
        <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-[var(--radius-2xl)] bg-[var(--bg-surface-active)]">
          <Icon className="h-7 w-7 text-[var(--fg-muted)]" />
        </div>
      )}
      <h3 className="text-base font-semibold text-[var(--fg-primary)]">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-sm text-sm text-[var(--fg-muted)] leading-relaxed">{description}</p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export default memo(EmptyState);
