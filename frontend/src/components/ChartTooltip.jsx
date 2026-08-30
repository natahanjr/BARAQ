export default function ChartTooltip({ active, payload, label, formatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-36 rounded-xl border border-[var(--border-default)] bg-[var(--bg-surface-overlay)] px-3.5 py-2.5 text-xs shadow-2xl backdrop-blur-md">
      {label !== undefined && label !== null && label !== "" && (
        <p className="mb-1.5 font-semibold text-[var(--fg-primary)]">{label}</p>
      )}
      <div className="space-y-1">
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center justify-between gap-5">
            <span className="flex items-center gap-1.5 text-[var(--fg-secondary)]">
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: entry.color || entry.payload?.fill || entry.fill }}
              />
              {entry.name}
            </span>
            <span className="font-mono font-semibold text-[var(--fg-primary)]">
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
