import { memo } from "react";

export function Skeleton({ className = "", variant = "text", width, height }) {
  const variants = {
    text: "h-3.5 rounded",
    title: "h-6 rounded w-1/3",
    circle: "rounded-full",
    rect: "rounded-[var(--radius-xl)]",
    card: "rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-surface)]",
  };

  return (
    <div
      className={["animate-pulse bg-[var(--bg-surface-active)]", variants[variant] || variants.text, className].join(" ")}
      style={{ width, height }}
      aria-hidden="true"
    />
  );
}

export function SkeletonCard({ rows = 3, className = "" }) {
  return (
    <div className={["rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-4", className].join(" ")}>
      <Skeleton variant="title" className="mb-3" />
      <div className="space-y-2.5">
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="w-full" />
        ))}
      </div>
    </div>
  );
}

export function SkeletonTable({ rows = 5, cols = 4, className = "" }) {
  return (
    <div className={["rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-surface)] overflow-hidden", className].join(" ")}>
      <div className="border-b border-[var(--border-subtle)] px-4 py-3">
        <div className="flex gap-4">
          {Array.from({ length: cols }).map((_, i) => (
            <Skeleton key={i} className="h-3 flex-1" />
          ))}
        </div>
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="border-b border-[var(--border-subtle)] last:border-0 px-4 py-3">
          <div className="flex gap-4">
            {Array.from({ length: cols }).map((_, i) => (
              <Skeleton key={i} className="h-3 flex-1" />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export function SkeletonStat({ className = "" }) {
  return (
    <div className={["rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-4", className].join(" ")}>
      <Skeleton className="h-3 w-20 mb-2" />
      <Skeleton className="h-7 w-16" />
    </div>
  );
}

export default memo(Skeleton);
