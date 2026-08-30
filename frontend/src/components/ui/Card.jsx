import { memo } from "react";

function Card({ children, className = "", hover = false, padding = true, ...props }) {
  return (
    <div
      className={[
        "rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-[var(--duration-normal)]",
        padding && "p-4",
        hover && "hover:border-[var(--border-strong)] hover:shadow-[var(--shadow-md)]",
        className,
      ].join(" ")}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className = "", ...props }) {
  return (
    <div className={["flex items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]", className].join(" ")} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className = "" }) {
  return (
    <h3 className={["text-card-title text-[var(--fg-primary)]", className].join(" ")}>
      {children}
    </h3>
  );
}

export function CardContent({ children, className = "", ...props }) {
  return <div className={["pt-3", className].join(" ")} {...props}>{children}</div>;
}

export default memo(Card);
