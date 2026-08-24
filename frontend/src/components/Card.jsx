const TONES = {
  default: "",
  emerald: "border-t-2 border-t-emerald-400/60",
  violet: "border-t-2 border-t-violet-400/60",
  amber: "border-t-2 border-t-amber-400/60",
};

export default function Card({ children, className = "", tone = "default", pad = true }) {
  return (
    <div
      className={`card-surface rounded-2xl border ${TONES[tone] || TONES.default} ${pad ? "p-5 sm:p-6" : ""} ${className}`}
    >
      {children}
    </div>
  );
}