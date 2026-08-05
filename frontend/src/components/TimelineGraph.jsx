import { useMemo } from "react";

const COLORS = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-slate-500",
};

function pct(value, min, max) {
  if (max <= min) return 50;
  return Math.max(2, Math.min(98, ((value - min) / (max - min)) * 96 + 2));
}

function fmt(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * Horizontal time-axis visualization of the incident:
 * evidence + related events positioned on a shared clock, the ±30 min
 * correlation window shaded, and kill-chain stages as a bottom track.
 */
export default function TimelineGraph({ events = [], attackChain = [], windowMinutes = 30 }) {
  const { min, max, placed } = useMemo(() => {
    const ts = events
      .map((e) => (e.timestamp ? new Date(e.timestamp).getTime() : NaN))
      .filter(Number.isFinite);
    if (ts.length === 0) return { min: 0, max: 1, placed: [] };
    const lo = Math.min(...ts);
    const hi = Math.max(...ts);
    return { min: lo, max: hi, placed: ts };
  }, [events]);

  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-slate-700/50 bg-slate-800/20 p-6 text-center text-sm text-slate-400">
        No timestamped events to visualize
      </div>
    );
  }

  const windowStart = min - windowMinutes * 60 * 1000;
  const windowEnd = max + windowMinutes * 60 * 1000;
  const bandLeft = pct(windowStart, min, max);
  const bandWidth = ((windowEnd - windowStart) / (max - min)) * 96;

  return (
    <div className="space-y-4">
      {/* Time track */}
      <div className="relative pt-8">
        {/* Correlation window band */}
        <div
          className="absolute top-6 h-10 rounded-md border border-cyan-500/30 bg-cyan-500/10"
          style={{ left: `${bandLeft}%`, width: `${Math.max(6, bandWidth)}%` }}
          title={`±${windowMinutes} min correlation window`}
        />
        {/* Track line */}
        <div className="absolute top-[44px] right-0 left-0 h-px bg-slate-700/60" />
        {/* Events */}
        {events.map((event, idx) => {
          const t = event.timestamp ? new Date(event.timestamp).getTime() : null;
          if (t == null || !Number.isFinite(t)) return null;
          const severity = (event.severity || "info").toLowerCase();
          const isAnomaly = Boolean(event.is_anomaly);
          return (
            <div key={idx} className="absolute" style={{ left: `${pct(t, min, max)}%`, top: "12px" }}>
              <div className="group relative flex flex-col items-center">
                <div
                  className={`h-4 w-4 rounded-full border-2 border-slate-900 shadow ${
                    isAnomaly ? "bg-violet-500" : COLORS[severity] || COLORS.info
                  }`}
                />
                <div className="pointer-events-none absolute top-6 z-20 hidden w-52 rounded-lg border border-slate-700 bg-slate-900/95 p-2.5 shadow-xl group-hover:block">
                  <p className="text-[11px] font-semibold text-slate-100">
                    Event {event.event_id} {isAnomaly && <span className="text-violet-400">· ML anomaly</span>}
                  </p>
                  <p className="mt-0.5 text-[10px] text-slate-400">{fmt(event.timestamp)}</p>
                  <p className="mt-1 line-clamp-3 text-[10px] leading-snug text-slate-300">
                    {event.message || event.category}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
        {/* Axis labels */}
        <div className="absolute -top-1 left-0 text-[10px] text-slate-500">{fmt(new Date(min).toISOString())}</div>
        <div className="absolute -top-1 right-0 text-[10px] text-slate-500">{fmt(new Date(max).toISOString())}</div>
      </div>

      {/* Kill-chain stage track */}
      {attackChain && attackChain.length > 0 && (
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Kill-Chain Stages
          </p>
          <div className="flex flex-wrap gap-2">
            {attackChain.map((step, idx) => (
              <span
                key={idx}
                className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] font-medium text-cyan-300"
              >
                {idx + 1}. {step.step}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-cyan-500/40" /> ±{windowMinutes} min correlation window
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-violet-500" /> ML anomaly
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-500" /> critical
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-orange-500" /> high
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> medium
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-blue-500" /> low
        </span>
      </div>
    </div>
  );
}
