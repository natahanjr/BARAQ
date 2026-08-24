export default function PageHeader({ title, subtitle, actions, label }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {label && <p className="console-label mb-1.5">{label}</p>}
        <h2 className="text-[26px] font-bold leading-tight tracking-[-0.022em] text-slate-100 sm:text-[28px] dark:text-slate-100">
          {title}
        </h2>
        {subtitle && (
          <p className="mt-1 text-[13px] font-normal tracking-[-0.003em] text-slate-400">
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2.5">{actions}</div>}
    </div>
  );
}
