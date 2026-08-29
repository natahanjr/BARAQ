/** The BARAQ mark — a lightning bolt cutting through a hexagonal shield,
 *  duotone teal → gold with a pulsing glow. (בָּרָק = lightning.) */
export default function BARAQLogo({ className = "h-10 w-10", pulse = true }) {
  return (
    <svg className={className} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="bqShield" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#14b8a6" />
          <stop offset="100%" stopColor="#eab308" />
        </linearGradient>
        <linearGradient id="bqBolt" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ffffff" />
          <stop offset="100%" stopColor="#14b8a6" />
        </linearGradient>
        <filter id="bqGlow" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="2.2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      {/* Hexagonal shield */}
      <path
        d="M32 3 L57 13.5 L57 30 Q57 47 32 61 Q7 47 7 30 L7 13.5 Z"
        fill="url(#bqShield)"
        opacity="0.14"
      />
      <path
        d="M32 3 L57 13.5 L57 30 Q57 47 32 61 Q7 47 7 30 L7 13.5 Z"
        fill="none"
        stroke="url(#bqShield)"
        strokeWidth="2.2"
        opacity="0.85"
      />
      {/* Inner hex ring */}
      <path
        d="M32 9 L51 17 L51 30 Q51 43 32 54 Q13 43 13 30 L13 17 Z"
        fill="none"
        stroke="url(#bqShield)"
        strokeWidth="1"
        opacity="0.35"
      />
      {/* Lightning bolt */}
      <g filter={pulse ? "url(#bqGlow)" : undefined}>
        <path
          d="M36.5 12 L22 34.5 L30.5 34.5 L26.5 52 L44 27.5 L34.5 27.5 Z"
          fill="url(#bqBolt)"
          opacity="0.95"
        />
      </g>
    </svg>
  );
}