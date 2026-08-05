const TONES = {
  default: "border-slate-700/50 bg-gradient-to-br from-slate-800/40 to-slate-900/40",
  emerald: "border-emerald-500/30 bg-gradient-to-br from-emerald-900/20 to-emerald-800/10",
  violet: "border-violet-500/30 bg-gradient-to-br from-violet-900/20 to-violet-800/10",
  amber: "border-amber-500/30 bg-gradient-to-br from-amber-900/20 to-amber-800/10",
};

export default function Card({ children, className = "", tone = "default", pad = true }) {
  return (
    <div
      className={`rounded-xl border shadow-lg shadow-black/20 backdrop-blur-sm transition-colors ${
        TONES[tone] || TONES.default
      } ${pad ? "p-6" : ""} ${className}`}
    >
      {children}
    </div>
  );
}
