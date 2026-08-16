const TONES = {
  cyan: "from-cyan-500/15 via-slate-900/60 to-slate-900/70 border-cyan-400/25",
  green: "from-emerald-500/15 via-slate-900/60 to-slate-900/70 border-emerald-400/25",
  red: "from-red-500/15 via-slate-900/60 to-slate-900/70 border-red-400/25",
  amber: "from-amber-500/15 via-slate-900/60 to-slate-900/70 border-amber-400/25",
};

function toneFor(accent) {
  if (accent.includes("emerald")) return "green";
  if (accent.includes("red")) return "red";
  if (accent.includes("amber")) return "amber";
  return "cyan";
}

export default function StatCard({ label, value, sub, accent = "text-cyan-400", icon, hint }) {
  return (
    <div
      className={`card-surface relative overflow-hidden rounded-2xl border bg-gradient-to-br p-5 ${TONES[toneFor(accent)]}`}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="console-label">{label}</p>
        {icon && <span className="text-lg opacity-60">{icon}</span>}
      </div>
      <p className={`mt-2 font-mono text-2xl font-semibold tracking-tight ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
      {hint && <p className="mt-1 text-[11px] text-slate-600">{hint}</p>}
    </div>
  );
}