import { useEffect } from "react";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useFocusTrap(ref, active) {
  useEffect(() => {
    if (!active || !ref.current) return;
    const container = ref.current;
    const root = document.getElementById("root");

    const getFocusable = () =>
      Array.from(container.querySelectorAll(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement
      );

    const focusables = getFocusable();
    if (focusables.length) focusables[0].focus();
    else container.focus();

    const previouslyInert = root && root !== container && root.hasAttribute("inert");
    if (root && root !== container && !previouslyInert) {
      root.setAttribute("inert", "");
    }

    const handler = (e) => {
      if (e.key !== "Tab") return;
      const items = getFocusable();
      if (items.length === 0) {
        e.preventDefault();
        container.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    container.addEventListener("keydown", handler);
    return () => {
      container.removeEventListener("keydown", handler);
      if (root && root !== container && !previouslyInert) {
        root.removeAttribute("inert");
      }
    };
  }, [ref, active]);
}
