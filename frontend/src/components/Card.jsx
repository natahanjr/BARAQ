const TONES = {
  default:
    "border-slate-700/50 bg-gradient-to-br from-slate-800/70 via-slate-900/45 to-slate-950/60 shadow-[0_10px_35px_-14px_rgba(2,6,23,0.9)]",
  emerald:
    "border-emerald-500/30 bg-gradient-to-br from-emerald-900/30 via-slate-900/45 to-slate-950/60 shadow-[0_10px_35px_-14px_rgba(16,185,129,0.25)]",
  violet:
    "border-violet-500/30 bg-gradient-to-br from-violet-900/30 via-slate-900/45 to-slate-950/60 shadow-[0_10px_35px_-14px_rgba(139,92,246,0.25)]",
  amber:
    "border-amber-500/30 bg-gradient-to-br from-amber-900/30 via-slate-900/45 to-slate-950/60 shadow-[0_10px_35px_-14px_rgba(251,191,36,0.2)]",
};

export default function Card({ children, className = "", tone = "default", pad = true }) {
  return (
    <div
      className={`card-surface rounded-xl border backdrop-blur-sm ${TONES[tone] || TONES.default} ${pad ? "p-5 sm:p-6" : ""} ${className}`}
    >
      {children}
    </div>
  );
}