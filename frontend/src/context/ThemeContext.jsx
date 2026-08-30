import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

const ThemeContext = createContext(null);

const STORAGE_KEY = "baraq-theme";

function getSystemTheme() {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function resolveTheme(preference) {
  if (preference === "system") return getSystemTheme();
  return preference;
}

export function ThemeProvider({ children }) {
  const [preference, setPreference] = useState(() => {
    try { return localStorage.getItem(STORAGE_KEY) || "system"; } catch { return "system"; }
  });

  const resolved = resolveTheme(preference);

  useEffect(() => {
    const root = document.documentElement;
    if (resolved === "light") {
      root.classList.add("light");
    } else {
      root.classList.remove("light");
    }
    root.style.colorScheme = resolved;
  }, [resolved]);

  // Listen for keyboard shortcut theme toggle
  useEffect(() => {
    const handler = () => cycleTheme();
    window.addEventListener("baraq:cycle-theme", handler);
    return () => window.removeEventListener("baraq:cycle-theme", handler);
  }, [cycleTheme]);

  useEffect(() => {
    if (preference !== "system") return;
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const handler = () => {
      const root = document.documentElement;
      const next = mq.matches ? "light" : "dark";
      if (next === "light") {
        root.classList.add("light");
      } else {
        root.classList.remove("light");
      }
      root.style.colorScheme = next;
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [preference]);

  const setTheme = useCallback((next) => {
    setPreference(next);
    try { localStorage.setItem(STORAGE_KEY, next); } catch {}
  }, []);

  const cycleTheme = useCallback(() => {
    const order = ["dark", "light", "system"];
    const idx = order.indexOf(preference);
    const next = order[(idx + 1) % order.length];
    setTheme(next);
  }, [preference, setTheme]);

  const value = useMemo(() => ({
    theme: preference,
    resolvedTheme: resolved,
    setTheme,
    cycleTheme,
  }), [preference, resolved, setTheme, cycleTheme]);

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
