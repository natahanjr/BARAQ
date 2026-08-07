const TONES = {
  cyan: "border-cyan-500/20 bg-gradient-to-br from-cyan-500/10 via-slate-900/45 to-slate-950/60 shadow-[0_8px_30px_-12px_rgba(34,211,238,0.25)]",
  green: "border-emerald-500/20 bg-gradient-to-br from-emerald-500/10 via-slate-900/45 to-slate-950/60 shadow-[0_8px_30px_-12px_rgba(16,185,129,0.2)]",
  red: "border-red-500/20 bg-gradient-to-br from-red-500/10 via-slate-900/45 to-slate-950/60 shadow-[0_8px_30px_-12px_rgba(239,68,68,0.2)]",
  amber: "border-amber-500/20 bg-gradient-to-br from-amber-500/10 via-slate-900/45 to-slate-950/60 shadow-[0_8px_30px_-12px_rgba(251,191,36,0.2)]",
};

function toneFor(accent) {
  if (accent.includes("emerald")) return "green";
  if (accent.includes("red")) return "red";
  if (accent.includes("amber")) return "amber";
  return "cyan";
}

export default function StatCard({ label, value, sub, accent = "text-cyan-400", icon, hint }) {
  return (
    <div className={`rounded-xl border backdrop-blur-sm ${TONES[toneFor(accent)]} p-5`}>
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-slate-500">{label}</p>
        {icon && <span className="text-lg opacity-70">{icon}</span>}
      </div>
      <p className={`mt-2 text-2xl font-semibold tracking-tight ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
      {hint && <p className="mt-1 text-[11px] text-slate-600">{hint}</p>}
    </div>
  );
}