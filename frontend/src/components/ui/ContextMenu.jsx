import { memo, useEffect, useRef, useCallback, useState } from "react";
import { createPortal } from "react-dom";

/**
 * Context menu that appears on right-click.
 * Usage:
 *   <ContextMenu
 *     items={[
 *       { label: "Investigate", icon: "🔍", onClick: () => ... },
 *       { label: "Close", icon: "✕", onClick: () => ..., danger: true },
 *     ]}
 *   >
 *     <div>Right-click me</div>
 *   </ContextMenu>
 */
function ContextMenu({ items, children, className = "" }) {
  const [pos, setPos] = useState(null);
  const menuRef = useRef(null);

  const handleContextMenu = useCallback((e) => {
    e.preventDefault();
    // Calculate position, keeping menu within viewport
    const x = Math.min(e.clientX, window.innerWidth - 200);
    const y = Math.min(e.clientY, window.innerHeight - (items.length * 36 + 16));
    setPos({ x, y });
  }, [items.length]);

  const close = useCallback(() => setPos(null), []);

  useEffect(() => {
    if (!pos) return;
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        close();
      }
    };
    const keyHandler = (e) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("mousedown", handler);
    document.addEventListener("keydown", keyHandler);
    return () => {
      document.removeEventListener("mousedown", handler);
      document.removeEventListener("keydown", keyHandler);
    };
  }, [pos, close]);

  return (
    <>
      <div onContextMenu={handleContextMenu} className={className}>
        {children}
      </div>
      {pos && createPortal(
        <div
          ref={menuRef}
          className="fixed z-[var(--z-toast)] min-w-[180px] rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] py-1.5 shadow-[var(--shadow-xl)] animate-palette-in"
          style={{ left: pos.x, top: pos.y }}
          role="menu"
        >
          {items.map((item, i) => {
            if (item.separator) {
              return <div key={i} className="my-1 border-t border-[var(--border-subtle)]" />;
            }
            return (
              <button
                key={i}
                onClick={() => { item.onClick?.(); close(); }}
                className={[
                  "flex w-full items-center gap-2.5 px-3 py-1.5 text-[13px] transition-colors",
                  item.danger
                    ? "text-[var(--severity-critical)] hover:bg-[var(--severity-critical-subtle)]"
                    : "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]",
                ].join(" ")}
                role="menuitem"
              >
                {item.icon && <span className="text-[12px]">{item.icon}</span>}
                <span>{item.label}</span>
                {item.shortcut && (
                  <kbd className="ml-auto rounded border border-[var(--border-default)] bg-[var(--bg-surface-active)] px-1 py-0.5 font-mono text-[10px] text-[var(--fg-faint)]">
                    {item.shortcut}
                  </kbd>
                )}
              </button>
            );
          })}
        </div>,
        document.body
      )}
    </>
  );
}

export default memo(ContextMenu);
