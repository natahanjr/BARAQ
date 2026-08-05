export default function Pagination({ page, totalPages, onChange }) {
  if (totalPages <= 1) return null;

  const pages = [];
  const start = Math.max(1, Math.min(page - 2, totalPages - 4));
  for (let i = start; i <= Math.min(totalPages, start + 4); i += 1) pages.push(i);

  const btn =
    "rounded-lg border px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40";
  const idle = "border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-700/70";
  const active = "border-cyan-500/40 bg-cyan-500/20 text-cyan-300";

  return (
    <div className="flex items-center justify-between gap-4">
      <button
        type="button"
        onClick={() => onChange(Math.max(1, page - 1))}
        disabled={page === 1}
        className={`${btn} ${idle}`}
      >
        ← Previous
      </button>

      <div className="flex items-center gap-1.5">
        {pages.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onChange(p)}
            className={`${btn} min-w-10 px-3 text-center ${p === page ? active : idle}`}
          >
            {p}
          </button>
        ))}
        <span className="px-2 text-xs text-slate-500">
          Page {page} of {totalPages}
        </span>
      </div>

      <button
        type="button"
        onClick={() => onChange(Math.min(totalPages, page + 1))}
        disabled={page === totalPages}
        className={`${btn} ${idle}`}
      >
        Next →
      </button>
    </div>
  );
}
