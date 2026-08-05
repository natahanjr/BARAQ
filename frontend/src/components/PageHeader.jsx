export default function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h2 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">{title}</h2>
        {subtitle && <p className="mt-1.5 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-3">{actions}</div>}
    </div>
  );
}
