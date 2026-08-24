import { useMemo, useRef, useState } from "react";
import {
  HB_STYLE,
  HeartbeatGradients,
  Sweep,
  BpmBadge,
  LiveBadge,
  MonitorChrome,
} from "./heartbeatTheme.jsx";

const W = 1000;
const H = 240;
const PAD_X = 16;
const BASELINE = H - 36;

function beatShape(x, bl, amp, bw) {
  return [
    [x - bw * 1.5, bl],
    [x - bw * 1.1, bl - 10],
    [x - bw * 0.55, bl - 17],
    [x - bw * 0.32, bl + 4],
    [x, bl - amp],
    [x + bw * 0.32, bl + 13],
    [x + bw * 0.85, bl - 12],
    [x + bw * 1.2, bl - 3],
    [x + bw * 1.5, bl],
  ];
}

function toPoints(pts) {
  return pts.map(([px, py]) => `${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
}

function restingWave() {
  const pts = [];
  const n = 7;
  const amp = H * 0.32;
  for (let i = 0; i < n; i++) {
    const kick = i % 2 === 0 ? 1 : 0.86;
    const x = PAD_X + ((i + 0.5) / n) * (W - PAD_X * 2);
    for (const p of beatShape(x, BASELINE, amp * kick, 14)) pts.push(p);
  }
  pts.unshift([PAD_X, BASELINE]);
  pts.push([W - PAD_X, BASELINE]);
  return toPoints(pts);
}

/**
 * A live 24 h heartbeat monitor for the dashboard: always beating — resting
 * ECG rhythm when idle, spikes scaled to event volume, red ticks when alerts
 * fire — with a scanner sweep and afterglow so it reads as alive 24/7.
 */
export default function HeartbeatChart({ data = [] }) {
  const svgRef = useRef(null);
  const [hover, setHover] = useState(null);

  const { points, alerts, active, bpm } = useMemo(() => {
    const n = data.length;
    if (n === 0) return { points: restingWave(), alerts: [], active: false, bpm: 72 };

    const bw = (W - PAD_X * 2) / n;
    const cx = (i) => PAD_X + i * bw + bw / 2;
    const hasActivity = data.some((d) => (d.count || 0) > 0);

    if (!hasActivity) {
      const pts = [];
      const bps = Math.min(6, Math.max(1, n));
      const amp = H * 0.32;
      for (let i = 0; i < bps; i++) {
        const x = PAD_X + ((i + 0.5) / bps) * (W - PAD_X * 2);
        for (const p of beatShape(x, BASELINE, amp * (i % 2 === 0 ? 1 : 0.86), 14)) pts.push(p);
      }
      pts.unshift([PAD_X, BASELINE]);
      pts.push([W - PAD_X, BASELINE]);
      return {
        points: toPoints(pts),
        alerts: data
          .map((d, i) => ({ x: cx(i), count: d.alerts || 0 }))
          .filter((a) => a.count > 0),
        active: false,
        bpm: 72,
      };
    }

    const maxCount = Math.max(1, ...data.map((d) => d.count || 0));
    const beatW = Math.min(16, bw * 0.22);
    const pts = [];
    for (let i = 0; i < n; i++) {
      const x = cx(i);
      const count = data[i].count || 0;
      if (count > 0) {
        const R = 26 + 150 * (count / maxCount);
        for (const p of beatShape(x, BASELINE, R, beatW)) pts.push(p);
      } else {
        const jitter = i % 2 === 0 ? 0 : 1.5;
        pts.push([x - beatW, BASELINE + jitter]);
        pts.push([x + beatW, BASELINE + jitter]);
      }
    }
    pts.unshift([PAD_X, BASELINE]);
    pts.push([W - PAD_X, BASELINE]);
    return {
      points: toPoints(pts),
      alerts: data
        .map((d, i) => ({ x: cx(i), count: d.alerts || 0 }))
        .filter((a) => a.count > 0),
      active: true,
      bpm: Math.min(118, 76 + maxCount),
    };
  }, [data]);

  const onMove = (e) => {
    if (data.length === 0) return;
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return;
    const n = data.length;
    const idx = Math.min(
      n - 1,
      Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * n))
    );
    setHover(idx);
  };

  const axisStep = Math.max(1, Math.ceil(data.length / 6));

  return (
    <div className="hb-screen relative h-full w-full rounded-2xl border border-cyan-500/15 bg-slate-950 shadow-[inset_0_0_50px_rgba(8,145,178,0.08),0_8px_30px_rgba(0,0,0,0.45)]">
      <style>{HB_STYLE}</style>

      <MonitorChrome>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="absolute inset-0 h-full w-full"
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        >
          <HeartbeatGradients />
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line
              key={f}
              x1={PAD_X}
              y1={BASELINE - (BASELINE - 24) * f}
              x2={W - PAD_X}
              y2={BASELINE - (BASELINE - 24) * f}
              stroke="rgba(148,163,184,0.07)"
              strokeWidth="1"
            />
          ))}
          {data.length > 0 &&
            data.map((_, i) => {
              const cx = PAD_X + (i + 0.5) * ((W - PAD_X * 2) / data.length);
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
            x1={PAD_X}
            y1={BASELINE}
            x2={W - PAD_X}
            y2={BASELINE}
            stroke="rgba(34,211,238,0.22)"
            strokeWidth="1"
            strokeDasharray="2 6"
          />

          <polyline
            points={points}
            fill="none"
            stroke="url(#hbMain)"
            strokeWidth="6"
            strokeLinejoin="round"
            strokeLinecap="round"
            opacity="0.18"
          />
          <polyline
            points={points}
            fill="none"
            stroke="url(#hbMain)"
            strokeWidth="2.4"
            strokeLinejoin="round"
            strokeLinecap="round"
            filter="url(#hbGlow)"
            style={{ animation: "hb-breathe 2.2s ease-in-out infinite" }}
          />
          <polyline
            points={points}
            fill="none"
            stroke="rgba(164,244,255,0.5)"
            strokeWidth="1.2"
            strokeLinejoin="round"
            strokeLinecap="round"
            style={{ strokeDasharray: "6 12", animation: "hb-stream 1.2s linear infinite" }}
          />

          {alerts.map((a, i) => (
            <g key={i}>
              <line
                x1={a.x}
                y1={BASELINE}
                x2={a.x}
                y2={BASELINE - Math.min(70, 24 + a.count * 4)}
                stroke="#f43f5e"
                strokeWidth="3.5"
                strokeLinecap="round"
                opacity="0.9"
              />
              <circle
                cx={a.x}
                cy={BASELINE - 8 - Math.min(70, 24 + a.count * 4)}
                r="3"
                fill="#fb7185"
              />
            </g>
          ))}

          {hover != null && (
            <line
              x1={PAD_X + (hover + 0.5) * ((W - PAD_X * 2) / data.length)}
              y1={16}
              x2={PAD_X + (hover + 0.5) * ((W - PAD_X * 2) / data.length)}
              y2={H - 8}
              stroke="rgba(34,211,238,0.5)"
              strokeWidth="1"
              strokeDasharray="3 3"
            />
          )}
        </svg>
        <Sweep />
      </MonitorChrome>

      {data.length > 0 && (
        <div className="absolute right-0 bottom-2 left-4 flex justify-between text-[10px] text-slate-500">
          {data.map((d, i) =>
            i % axisStep === 0 ? <span key={i}>{d.label || "—"}</span> : <span key={i} />
          )}
        </div>
      )}

      <div className="absolute top-2 right-2">
        <LiveBadge status={active ? "ACTIVE" : "LIVE"} />
      </div>
      <div className="absolute top-2 left-2">
        <BpmBadge bpm={bpm} />
      </div>

      {hover != null && (
        <div
          className="pointer-events-none absolute top-3 z-10 -translate-x-1/2 rounded-lg border border-slate-600/60 bg-slate-900/95 px-3 py-2 shadow-xl"
          style={{ left: `${((hover + 0.5) / data.length) * 100}%` }}
        >
          <p className="text-[11px] font-semibold text-slate-100">{data[hover].label || "—"}</p>
          <div className="mt-1 flex items-center gap-3 text-[10px]">
            <span className="flex items-center gap-1 text-emerald-400">
              <span className="h-1.5 w-4 rounded bg-emerald-400/70" /> {data[hover].count || 0} events
            </span>
            <span className="flex items-center gap-1 text-rose-400">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-400" /> {data[hover].alerts || 0} alerts
            </span>
          </div>
        </div>
      )}

      <div className="absolute bottom-2 left-2 flex items-center gap-3 text-[10px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="font-bold text-emerald-400">♥</span> events
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-4 rounded bg-rose-500" /> alerts
        </span>
      </div>
    </div>
  );
}