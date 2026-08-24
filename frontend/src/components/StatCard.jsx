const TONES = {
  cyan: "border-white/10",
  green: "border-white/10",
  red: "border-white/10",
  amber: "border-white/10",
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
      className={`card-surface relative overflow-hidden rounded-2xl border p-5 ${TONES[toneFor(accent)]}`}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="console-label">{label}</p>
        {icon && <span className="text-lg opacity-50">{icon}</span>}
      </div>
      <p className={`mt-2 text-[26px] font-bold tracking-[-0.03em] tabular-nums ${accent}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
      {hint && <p className="mt-1 text-[11px] text-slate-600">{hint}</p>}
    </div>
  );
}
