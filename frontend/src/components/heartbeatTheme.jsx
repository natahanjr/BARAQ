/**
 * Shared visual theme for the heartbeat monitors: gradients, glow, scanline
 * texture, animating sweep and live/BPM badges used by both the Dashboard
 * HeartbeatChart and the Investigation TimelineGraph.
 */

export const HB_STYLE = `
@keyframes hb-stream { to { stroke-dashoffset: -36; } }
@keyframes hb-sweep {
  0%   { left: -12%; opacity: 0; }
  10%  { opacity: 1; }
  88%  { opacity: 1; }
  100% { left: 106%; opacity: 0; }
}
@keyframes hb-breathe {
  0%, 100% { opacity: 0.75; }
  50%      { opacity: 1; }
}
@keyframes hb-heart {
  0%   { transform: scale(1); }
  4%   { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  8%   { transform: scale(1); }
  12%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  17%  { transform: scale(1); }
  21%  { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  25%  { transform: scale(1); }
  29%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  33%  { transform: scale(1); }
  38%  { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  42%  { transform: scale(1); }
  46%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  50%  { transform: scale(1); }
  54%  { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  58%  { transform: scale(1); }
  63%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  67%  { transform: scale(1); }
  71%  { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  75%  { transform: scale(1); }
  79%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  83%  { transform: scale(1); }
  88%  { transform: scale(1.5); filter: drop-shadow(0 0 14px rgba(244,63,94,0.95)); }
  92%  { transform: scale(1); }
  96%  { transform: scale(1.35); filter: drop-shadow(0 0 8px rgba(244,63,94,0.7)); }
  100% { transform: scale(1); }
}
@keyframes hb-scan {
  0%   { background-position: 0 0; }
  100% { background-position: 40px 0; }
}
`;

export function HeartbeatGradients() {
  return (
    <defs>
      <linearGradient id="hbMain" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stopColor="#22d3ee" />
        <stop offset="50%" stopColor="#34d399" />
        <stop offset="100%" stopColor="#2dd4bf" />
      </linearGradient>
      <linearGradient id="hbSweepFill" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stopColor="rgba(34,211,238,0)" />
        <stop offset="70%" stopColor="rgba(34,211,238,0.08)" />
        <stop offset="100%" stopColor="rgba(34,211,238,0.35)" />
      </linearGradient>
      <filter id="hbGlow" x="-30%" y="-140%" width="160%" height="420%">
        <feGaussianBlur stdDeviation="4" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
    </defs>
  );
}

/** Faint animated scanline texture overlaying the monitor screen. */
export function Scanlines() {
  return (
    <div
      className="pointer-events-none absolute inset-0 opacity-40"
      style={{
        backgroundImage:
          "repeating-linear-gradient(0deg, rgba(255,255,255,0.028) 0px, rgba(255,255,255,0.028) 1px, transparent 1px, transparent 3px)",
        animation: "hb-scan 0.5s linear infinite",
      }}
    />
  );
}

/** Scanner sweep with a bright leading edge and trailing afterglow. */
export function Sweep() {
  return (
    <div
      className="pointer-events-none absolute inset-y-0 w-40"
      style={{
        animation: "hb-sweep 2.8s linear infinite",
        background: "linear-gradient(90deg, transparent, rgba(34,211,238,0.10) 60%, rgba(34,211,238,0.38) 100%)",
        mixBlendMode: "screen",
      }}
    />
  );
}

/** Pulsing blood-pump hearts: a staggered wave of thumps sweeping the badge. */
export function BpmBadge({ bpm }) {
  return (
    <div className="flex items-center gap-0.5 rounded-full border border-rose-400/25 bg-black/45 px-2.5 py-1.5 backdrop-blur-sm">
      <style>{`
@keyframes hb-thump {
  0%   { transform: scale(0.55); opacity: 0.3; }
  13%  { transform: scale(1.55); opacity: 1; filter: drop-shadow(0 0 10px rgba(244,63,94,0.95)); }
  26%  { transform: scale(0.9); opacity: 0.85; }
  35%  { transform: scale(1.2); opacity: 1; filter: drop-shadow(0 0 6px rgba(244,63,94,0.7)); }
  48%  { transform: scale(0.55); opacity: 0.3; }
  100% { transform: scale(0.55); opacity: 0.3; }
}
`}</style>
      {[0, 1, 2, 3, 4].map((i) => (
        <span
          key={i}
          className="inline-block text-sm leading-none text-rose-400"
          style={{
            display: "inline-block",
            willChange: "transform",
            animation: `hb-thump 1.7s ease-out ${i * 0.34}s infinite`,
          }}
        >
          ♥
        </span>
      ))}
    </div>
  );
}

/** Live status pill. */
export function LiveBadge({ status = "LIVE" }) {
  return (
    <div className="flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 backdrop-blur-sm">
      <span className="h-2 w-2 animate-pulse rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.9)]" />
      <span className="text-[10px] font-bold tracking-widest text-red-300">{status}</span>
    </div>
  );
}

/** Shared monitor screen chrome (background, inset glow, scanlines). */
export function MonitorChrome({ children }) {
  return (
    <div className="absolute inset-0">
      <div
        className="absolute inset-0 rounded-2xl"
        style={{
          background: "radial-gradient(ellipse at 50% 110%, rgba(8,145,178,0.14), transparent 60%)",
        }}
      />
      {children}
      <Scanlines />
    </div>
  );
}