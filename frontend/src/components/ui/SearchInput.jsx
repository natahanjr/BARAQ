import { memo, useRef, useEffect, useState } from "react";

function SearchInput({ value, onChange, placeholder = "Search...", debounce = 200, className = "" }) {
  const [local, setLocal] = useState(value || "");
  const timer = useRef(null);

  useEffect(() => {
    setLocal(value || "");
  }, [value]);

  const handleChange = (e) => {
    const v = e.target.value;
    setLocal(v);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => onChange?.(v), debounce);
  };

  const handleClear = () => {
    setLocal("");
    onChange?.("");
  };

  useEffect(() => () => clearTimeout(timer.current), []);

  return (
    <div className={["relative", className].join(" ")}>
      <svg
        className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--fg-muted)]"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
      >
        <circle cx="6.5" cy="6.5" r="4.5" />
        <path d="M10 10l4 4" />
      </svg>
      <input
        type="text"
        value={local}
        onChange={handleChange}
        placeholder={placeholder}
        className={[
          "w-full h-8 rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--input-bg)] pl-8 pr-7 text-[13px] text-[var(--fg-primary)] placeholder-[var(--input-placeholder)]",
          "outline-none transition-all focus:ring-2 focus:ring-[var(--accent-cyan)]/30 focus:ring-2 focus:ring-[var(--accent-cyan)]/30 focus:border-[var(--input-border-focus)] focus:ring-1 focus:ring-[var(--input-border-focus)]",
        ].join(" ")}
      />
      {local && (
        <button
          onClick={handleClear}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-[var(--radius-sm)] p-0.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors"
          aria-label="Clear search"
        >
          <svg className="h-3 w-3" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M4 4l8 8M12 4l-8 8" />
          </svg>
        </button>
      )}
    </div>
  );
}

export default memo(SearchInput);
