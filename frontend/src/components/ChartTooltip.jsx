export default function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-36 rounded-lg border border-slate-600/80 bg-slate-900/95 px-3.5 py-2.5 text-xs shadow-2xl backdrop-blur">
      {label !== undefined && label !== null && label !== "" && (
        <p className="mb-1.5 font-semibold text-slate-200">{label}</p>
      )}
      <div className="space-y-1">
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center justify-between gap-5">
            <span className="flex items-center gap-1.5 text-slate-400">
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: entry.color || entry.payload?.fill || entry.fill }}
              />
              {entry.name}
            </span>
            <span className="font-mono font-semibold text-slate-100">
              {formatter
                ? formatter(entry.value, entry)
                : typeof entry.value === "number"
                  ? entry.value.toLocaleString()
                  : entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
