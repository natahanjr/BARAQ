import { useMemo } from "react";
import {
  HB_STYLE,
  HeartbeatGradients,
  Sweep,
  BpmBadge,
  LiveBadge,
  MonitorChrome,
} from "./heartbeatTheme.jsx";

const COLORS = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-500",
  info: "bg-slate-500",
};

const W = 1000;
const H = 170;
const PAD = 30;
const BASELINE = H * 0.62;

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

function beatShape(cx, bl, amp, bw) {
  return [
    [cx - bw * 1.5, bl],
    [cx - bw * 1.1, bl - 10],
    [cx - bw * 0.55, bl - 17],
    [cx - bw * 0.32, bl + 4],
    [cx, bl - amp],
    [cx + bw * 0.32, bl + 13],
    [cx + bw * 0.85, bl - 12],
    [cx + bw * 1.2, bl - 3],
    [cx + bw * 1.5, bl],
  ];
}

function restingPoints() {
  const pts = [];
  const n = 6;
  const amp = H * 0.32;
  for (let i = 0; i < n; i++) {
    const kick = i % 2 === 0 ? 1 : 0.86;
    const cx = PAD + ((i + 0.5) / n) * (W - PAD * 2);
    for (const p of beatShape(cx, BASELINE, amp * kick, 12)) pts.push(p);
  }
  pts.unshift([PAD, BASELINE]);
  pts.push([W - PAD, BASELINE]);
  return pts.map(([px, py]) => `${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
}

/**
 * Incident timeline rendered as a live patient monitor: always beating —
 * resting rhythm when idle, P-QRS-T spikes at every evidence/related event,
 * scanner sweep and afterglow keeping it alive, BPM rising with activity.
 */
export default function TimelineGraph({ events = [], attackChain = [], windowMinutes = 30 }) {
  const { min, max, times } = useMemo(() => {
    const ts = events
      .map((e) => (e.timestamp ? new Date(e.timestamp).getTime() : NaN))
      .filter(Number.isFinite);
    if (ts.length === 0) return { min: 0, max: 1, times: [] };
    return { min: Math.min(...ts), max: Math.max(...ts), times: ts };
  }, [events]);

  const x = (t) => PAD + ((t - min) / (max - min)) * (W - PAD * 2);
  const hasEvents = times.length > 0;

  const beats = [];
  if (hasEvents) {
    beats.push([x(min), BASELINE]);
    for (const t of times) {
      const cx = x(t);
      for (const p of beatShape(cx, BASELINE, H * 0.45, 14)) beats.push(p);
    }
    beats.push([x(max), BASELINE]);
  }
  const points =
    beats.length > 0 ? beats.map(([px, py]) => `${px.toFixed(1)},${py.toFixed(1)}`).join(" ") : restingPoints();

  const windowStart = min - windowMinutes * 60 * 1000;
  const windowEnd = max + windowMinutes * 60 * 1000;
  const bandLeft = x(windowStart);
  const bandRight = x(windowEnd);
  const pct = (t) => ((t - min) / (max - min)) * 100;
  const bpm = hasEvents ? Math.min(118, 74 + times.length) : 72;

  return (
    <div className="space-y-4">
      <div className="hb-screen relative overflow-hidden rounded-2xl border border-cyan-500/15 bg-slate-950 shadow-[inset_0_0_50px_rgba(8,145,178,0.08),0_8px_30px_rgba(0,0,0,0.45)]">
        <style>{HB_STYLE}</style>

        <MonitorChrome>
          <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full">
            <HeartbeatGradients />
            {hasEvents && (
              <rect
                x={bandLeft}
                y={6}
                width={Math.max(4, bandRight - bandLeft)}
                height={H - 12}
                rx={6}
                fill="rgba(34,211,238,0.05)"
                stroke="rgba(34,211,238,0.22)"
                strokeDasharray="4 4"
              />
            )}
            {[0.3, 0.5, 0.7].map((f) => (
              <line
                key={f}
                x1={PAD}
                y1={H * f}
                x2={W - PAD}
                y2={H * f}
                stroke="rgba(148,163,184,0.07)"
                strokeWidth="1"
              />
            ))}
            {Array.from({ length: 12 }).map((_, i) => {
              const cx = PAD + ((i + 0.5) / 12) * (W - PAD * 2);
              return (
                <line
                  key={`t${i}`}
                  x1={cx}
                  y1={BASELINE}
                  x2={cx}
                  y2={BASELINE + 5}
                  stroke="rgba(148,163,184,0.12)"
                  strokeWidth="1"
                />
              );
            })}
            <line
              x1={x(min) + 2}
              y1={BASELINE}
              x2={x(max) - 2}
              y2={BASELINE}
              stroke="rgba(34,211,238,0.22)"
              strokeWidth="1"
              strokeDasharray="2 6"
            />

            <polyline
              points={points}
              fill="none"
              stroke="url(#hbMain)"
              strokeWidth="5"
              strokeLinejoin="round"
              strokeLinecap="round"
              opacity="0.16"
            />
            <polyline
              points={points}
              fill="none"
              stroke="url(#hbMain)"
              strokeWidth="2.3"
              strokeLinejoin="round"
              strokeLinecap="round"
              filter="url(#hbGlow)"
              style={{ animation: "hb-breathe 2.2s ease-in-out infinite" }}
            />
            <polyline
              points={points}
              fill="none"
              stroke="rgba(164,244,255,0.45)"
              strokeWidth="1.1"
              strokeLinejoin="round"
              strokeLinecap="round"
              style={{ strokeDasharray: "6 12", animation: "hb-stream 1.2s linear infinite" }}
            />
          </svg>
          <Sweep />
        </MonitorChrome>

        {hasEvents ? (
          <>
            <div className="absolute bottom-2 left-4 text-[10px] text-slate-500">
              {fmt(new Date(min).toISOString())}
            </div>
            <div className="absolute right-4 bottom-2 text-[10px] text-slate-500">
              {fmt(new Date(max).toISOString())}
            </div>
          </>
        ) : (
          <div className="absolute bottom-2 left-4 text-[10px] text-slate-500">
            standing by · healthy resting rhythm
          </div>
        )}

        <div className="absolute top-2 right-2">
          <LiveBadge status={hasEvents ? "ACTIVE" : "LIVE"} />
        </div>
        <div className="absolute top-2 left-2">
          <BpmBadge bpm={bpm} />
        </div>
      </div>

      {hasEvents && (
        <div className="relative h-6">
          {events.map((event, idx) => {
            const t = event.timestamp ? new Date(event.timestamp).getTime() : null;
            if (t == null || !Number.isFinite(t)) return null;
            const severity = (event.severity || "info").toLowerCase();
            const isAnomaly = Boolean(event.is_anomaly);
            return (
              <div key={idx} className="absolute -top-0.5" style={{ left: `${pct(t)}%` }}>
                <div className="group relative flex flex-col items-center">
                  <div
                    className={`h-3.5 w-3.5 -translate-x-1/2 cursor-pointer rounded-full border-2 border-slate-900 shadow ${
                      isAnomaly ? "bg-violet-500" : COLORS[severity] || COLORS.info
                    }`}
                  />
                  <div className="pointer-events-none absolute top-7 z-20 hidden w-52 rounded-lg border border-slate-700 bg-slate-900/95 p-2.5 shadow-xl group-hover:block">
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
        </div>
      )}

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

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="font-bold text-emerald-400">♥</span> heartbeat at each event
        </span>
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
      </div>
    </div>
  );
}