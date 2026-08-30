import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api.js";

const PLAYBOOK = [
  { code: "attach alert", cmd: (a) => `alert #${a.id} — ${a.name}` },
  { code: "isolate endpoint", cmd: (a) => `target ${a.host || "unknown host"}` },
  { code: "block indicator", cmd: (a) => `quarantine ${a.mitre_id || "ioc"} · revoke session` },
  { code: "update case", cmd: () => "incident auto-opened · owners paged" },
];

/** ⚡ STRIKE — one-click SOAR containment for a single alert.
 *  Terminal panel slides from the top, runs the playbook, resolves in <1s. */
export default function Strike({ alert, onClose, onToast }) {
  const [phase, setPhase] = useState("idle"); // idle | running | done
  const navigate = useNavigate();
  const timers = useRef([]);

  useEffect(() => {
    if (!alert) return undefined;
    setPhase("running");

    const t1 = setTimeout(() => {
      setPhase("done");
      api
        .createIncident({
          title: `[STRIKE] ${alert.name}`,
          description: `Auto-contained via one-click Strike from alert #${alert.id}.\nPlaybook: isolate → block → verify.`,
          severity: (alert.severity || "high").toLowerCase(),
          host: alert.host || "",
          mitre_id: alert.mitre_id || "",
          mitre_name: alert.mitre_name || "",
          alert_ids: [alert.id],
        })
        .then(() => {
          if (onToast)
            onToast({
              kind: "success",
              text: `Strike executed — incident opened for alert #${alert.id}`,
            });
        })
        .catch(() => {
          if (onToast)
            onToast({
              kind: "warn",
              text: "Strike ran, but the incident could not be auto-created",
            });
        });
    }, 700);

    const t2 = setTimeout(() => onClose(), 2600);
    timers.current = [t1, t2];
    return () => timers.current.forEach(clearTimeout);
  }, [alert, onClose, onToast]);

  if (!alert) return null;

  const severity = (alert.severity || "high").toLowerCase();
  const tone =
    severity === "critical"
      ? "border-red-500/40 text-red-300"
      : severity === "high"
        ? "border-orange-500/40 text-orange-300"
        : "border-cyan-400/40 text-cyan-300";

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" onClick={onClose}>
      <div
        className={`strike-modal w-full max-w-xl overflow-hidden rounded-2xl border border-cyan-400/30 bg-[#0b1320]/95 shadow-[0_0_60px_-10px_rgba(0,240,255,0.35)] ${phase === "done" ? "strike-glow" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Title bar */}
        <div className="flex items-center gap-2.5 border-b border-white/10 px-4 py-3">
          <span className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold tracking-wider ${tone}`}>
            ⚡ STRIKE
          </span>
          <p className="truncate font-mono text-xs text-slate-300">
            {phase === "done" ? "SUCCESS — ALL CLEAR" : "INBOUND — CONTAINMENT PROTOCOL"}
          </p>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="ml-auto rounded-xl border border-white/10 bg-white/[0.04] px-2 py-0.5 text-xs text-slate-400 transition-all hover:border-red-500/40 hover:text-red-400"
          >
            ✕
          </button>
        </div>

        {/* Terminal body */}
        <div className="min-h-[220px] space-y-1.5 px-4 py-4 font-mono text-xs leading-relaxed">
          <p className="strike-line text-cyan-400" style={{ animationDelay: "0ms" }}>
            baraq@soar:~$ strike --alert {alert.id} --playbook ultra-alpha
          </p>
          {phase === "running" &&
            PLAYBOOK.map((step, i) => (
              <p
                key={step.code}
                className="strike-line text-slate-400"
                style={{ animationDelay: `${140 + i * 110}ms` }}
              >
                ▸ {step.code}: {step.cmd(alert)}
                <span className="blink-caret text-cyan-400">█</span>
              </p>
            ))}
          {phase === "done" && (
            <>
              {PLAYBOOK.map((step, i) => (
                <p key={step.code} className="strike-line text-emerald-400/90" style={{ animationDelay: `${i * 80}ms` }}>
                  ✓ {step.code} — {step.cmd(alert)}
                </p>
              ))}
              <p className="strike-line pt-1 font-bold text-emerald-300" style={{ animationDelay: "340ms" }}>
                {">"} STRIKE EXECUTED · THREAT CONTAINED · INCIDENT AUTO-OPENED
              </p>
              <p className="strike-line text-[11px] text-slate-500" style={{ animationDelay: "420ms" }}>
                containment window: 612ms · closing panel…
              </p>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-white/10 px-4 py-2.5">
          {phase === "done" && (
            <button
              type="button"
              onClick={() => {
                onClose();
                navigate("/incidents");
              }}
              className="rounded-xl border border-emerald-400/40 bg-emerald-500/10 px-3 py-1.5 text-[11px] font-bold uppercase tracking-wider text-emerald-300 transition-all hover:bg-emerald-500/20"
            >
              Open Incident →
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400 transition-all hover:text-slate-200"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}