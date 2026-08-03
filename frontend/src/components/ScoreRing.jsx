export default function ScoreRing({ score }) {
  const clamped = Math.max(0, Math.min(100, score));
  const r = 34;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (clamped / 100) * circumference;
  const color = clamped >= 70 ? "#34d399" : clamped >= 40 ? "#fbbf24" : "#f87171";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="88" height="88" viewBox="0 0 88 88">
        <circle
          cx="44"
          cy="44"
          r={r}
          fill="none"
          stroke="#1e293b"
          strokeWidth="8"
        />
        <circle
          cx="44"
          cy="44"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 44 44)"
          style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.8s ease" }}
        />
      </svg>
      <div className="absolute text-center">
        <span className="block text-2xl font-bold text-slate-100">{clamped.toFixed(0)}</span>
        <span className="block text-[9px] uppercase tracking-widest text-slate-500">Score</span>
      </div>
    </div>
  );
}
