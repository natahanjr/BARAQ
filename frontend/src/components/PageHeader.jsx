export default function PageHeader({ title, subtitle, actions, label }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {label && <p className="console-label mb-1.5">{label}</p>}
        <h2 className="bg-gradient-to-r from-white via-slate-100 to-cyan-300/70 bg-clip-text text-2xl font-bold tracking-tight text-transparent sm:text-3xl">
          {title}
        </h2>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2.5">{actions}</div>}
    </div>
  );
}