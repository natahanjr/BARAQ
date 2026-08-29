import { memo } from "react";

function PageHeader({ title, subtitle, label, actions, className = "" }) {
  return (
    <div className={["flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between", className].join(" ")}>
      <div>
        {label && (
          <span className="mb-1 inline-block text-[10px] font-bold uppercase tracking-[var(--tracking-widest)] text-[var(--accent-cyan)]">
            {label}
          </span>
        )}
        <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">{title}</h1>
        {subtitle && (
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">{subtitle}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export default memo(PageHeader);
