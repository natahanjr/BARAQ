export function Loading({ label = "Loading" }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-500">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
      <p className="mt-3 text-sm">{label}...</p>
    </div>
  );
}

export function EmptyState({ message = "No data available" }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-slate-600">
      <span className="text-3xl">◌</span>
      <p className="mt-2 text-sm">{message}</p>
    </div>
  );
}
