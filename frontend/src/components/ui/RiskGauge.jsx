import { memo, useRef, useEffect } from "react";

function RiskGauge({ value = 0, size = 120, strokeWidth = 8, className = "" }) {
  const circleRef = useRef(null);
  const textRef = useRef(null);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(100, Math.max(0, value));
  const offset = circumference - (pct / 100) * circumference;

  const getColor = (v) => {
    if (v >= 80) return "var(--severity-critical)";
    if (v >= 60) return "var(--severity-high)";
    if (v >= 40) return "var(--severity-medium)";
    if (v >= 20) return "var(--severity-low)";
    return "var(--status-healthy)";
  };

  const getLabel = (v) => {
    if (v >= 80) return "CRITICAL";
    if (v >= 60) return "HIGH";
    if (v >= 40) return "MEDIUM";
    if (v >= 20) return "LOW";
    return "HEALTHY";
  };

  const color = getColor(pct);

  useEffect(() => {
    const el = circleRef.current;
    if (!el) return;
    el.style.strokeDashoffset = offset;
  }, [offset]);

  return (
    <div className={["relative inline-flex items-center justify-center", className].join(" ")}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border-subtle)"
          strokeWidth={strokeWidth}
        />
        <circle
          ref={circleRef}
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span ref={textRef} className="text-2xl font-bold tabular-nums text-[var(--fg-primary)]">
          {pct}
        </span>
        <span className="text-[11px] font-bold uppercase tracking-[var(--tracking-widest)]" style={{ color }}>
          {getLabel(pct)}
        </span>
      </div>
    </div>
  );
}

export default memo(RiskGauge);
