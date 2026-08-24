import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import TimelineGraph from "../components/TimelineGraph.jsx";
import {
  InvestigationIcon,
  ActivityIcon,
  AlertIcon,
  NetworkIcon,
} from "../components/icons.jsx";

const KINDS_COLOR = {
  user: "#38bdf8",
  device: "#818cf8",
  process: "#f472b6",
  ip: "#fb923c",
  domain: "#34d399",
  file: "#e879f9",
  technique: "#a3e635",
};

function StepDot({ index, active }) {
  return (
    <span
      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border font-mono text-xs font-bold ${
        active
          ? "border-cyan-500/50 bg-cyan-500/20 text-cyan-300"
          : "border-slate-700 bg-slate-800/60 text-slate-400"
      }`}
    >
      {index}
    </span>
  );
}

function EventChip({ event, compact }) {
  const colors = {
    critical: "border-red-500/40 bg-red-500/10 text-red-300",
    high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
    medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    low: "border-blue-500/40 bg-blue-500/10 text-blue-300",
  };

  const severity = (event.severity || "low").toLowerCase();
  const color = colors[severity] || colors.low;

  return (
    <div className={`rounded-lg border ${color} p-3`}>
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-black/30 px-2 py-0.5 font-mono text-[10px] text-slate-200">
            Event {event.event_id}
          </span>
          {event.is_anomaly && (
            <span className="rounded bg-violet-500/15 px-2 py-0.5 text-[10px] font-semibold text-violet-400">
              ML anomaly
            </span>
          )}
        </div>
        <span className="text-[11px] text-slate-400">
          {event.timestamp
            ? new Date(event.timestamp).toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "—"}
        </span>
      </div>
      {!compact && (
        <p className="text-xs leading-relaxed text-slate-300">{event.message || event.category}</p>
      )}
      <p className="mt-1.5 text-[11px] text-slate-400">
        User: <strong className="text-slate-200">{event.user || "—"}</strong>
        {event.risk_score != null && (
          <>
            {" "}
            · Risk: <strong className="text-slate-200">{event.risk_score.toFixed(0)}</strong>
          </>
        )}
      </p>
    </div>
  );
}

function AttackTimeline({ events }) {
  const rows = (events || [])
    .filter((e) => e.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  if (rows.length === 0) {
    return <EmptyState title="No timed events" subtitle="Nothing to lay out chronologically" />;
  }

  const railColor = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
  };

  return (
    <div className="relative ml-2 space-y-2 border-l border-slate-700/60 pl-6">
      {rows.map((e, idx) => {
        const sev = (e.severity || "low").toLowerCase();
        return (
          <div key={idx} className="relative">
            <span
              className={`absolute -left-[27px] top-3.5 h-3 w-3 rounded-full border-2 border-slate-950 ${
                railColor[sev] || railColor.low
              } ${e.is_anomaly ? "shadow-[0_0_8px_rgba(139,92,246,0.9)]" : ""}`}
            />
            <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 px-3.5 py-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-[10px] text-slate-500">
                  Event {e.event_id}
                  {e.is_anomaly && (
                    <span className="ml-1.5 rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-violet-400">
                      ML anomaly
                    </span>
                  )}
                </span>
                <span className="font-mono text-[10px] text-slate-400">
                  {new Date(e.timestamp).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-300">
                {e.message || e.category}
              </p>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-500">
                {e.user && (
                  <span>
                    user <strong className="text-slate-300">{e.user}</strong>
                  </span>
                )}
                {e.host && (
                  <span>
                    host <strong className="text-slate-300">{e.host}</strong>
                  </span>
                )}
                {e.risk_score != null && (
                  <span>
                    risk <strong className="text-slate-300">{e.risk_score.toFixed(0)}</strong>
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function InvolvedEntities({ data }) {
  const seen = new Map();
  const push = (kind, name) => {
    if (!name || name === "-") return;
    const key = `${kind}:${name}`;
    if (!seen.has(key)) seen.set(key, { kind, name, count: 0 });
    seen.get(key).count += 1;
  };
  for (const e of [...(data.evidence_events || []), ...(data.related_events || [])]) {
    push("user", e.user);
    push("device", e.host);
  }
  const rows = [...seen.values()].sort((a, b) => b.count - a.count).slice(0, 8);
  if (rows.length === 0) return null;

  return (
    <Card>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-white">Involved Entities</h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Users and hosts touching this alert — click to open in the entity graph
          </p>
        </div>
        <NetworkIcon className="h-5 w-5 text-cyan-400" />
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {rows.map((e) => (
          <Link
            key={e.key}
            to={`/entities?kind=${e.kind}&name=${encodeURIComponent(e.name)}`}
            className="flex items-center justify-between gap-2 rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2 transition-colors hover:border-cyan-500/40"
          >
            <span className="flex min-w-0 items-center gap-2">
              <span
                className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[9px] font-bold text-slate-950"
                style={{ backgroundColor: KINDS_COLOR[e.kind] || "#64748b" }}
              >
                {e.kind.slice(0, 1).toUpperCase()}
              </span>
              <span className="min-w-0">
                <span className="block truncate font-mono text-xs text-slate-200">{e.name}</span>
                <span className="block text-[10px] text-slate-500">
                  {e.kind} · {e.count} event{e.count === 1 ? "" : "s"}
                </span>
              </span>
            </span>
            <span className="shrink-0 text-[10px] text-cyan-400">→</span>
          </Link>
        ))}
      </div>
    </Card>
  );
}

function ConfidenceMeter({ score, label }) {
  const pct = Math.round((score || 0) * 100);
  const color =
    pct >= 75 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-500" : "bg-rose-500";
  return (
    <div>
      <div className="flex items-center justify-between text-[11px] text-slate-400">
        <span>
          Story confidence:{" "}
          <strong className="uppercase text-slate-200">{label || "low"}</strong>
        </span>
        <span className="font-mono">{pct}%</span>
      </div>
      <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function ProcessTreeNode({ node, depth, children }) {
  const isRoot = !node.parent_pid;
  const kids = children(node.pid);
  const [expanded, setExpanded] = useState(depth < 2 || isRoot);
  return (
    <li>
      <div
        className={`rounded-lg border px-3 py-2 ${
          node.seed
            ? "border-cyan-500/50 bg-cyan-500/10"
            : isRoot
              ? "border-violet-500/40 bg-violet-500/10"
              : "border-slate-700/50 bg-slate-800/30"
        }`}
      >
        <div className="flex flex-wrap items-center gap-2">
          {kids.length > 0 && (
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              aria-label={expanded ? "Collapse subtree" : "Expand subtree"}
              className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-black/30 font-mono text-[10px] text-slate-300 transition-colors hover:bg-slate-700"
            >
              {expanded ? "−" : `${kids.length}+`}
            </button>
          )}
          <span className="font-mono text-xs font-semibold text-slate-100">
            {node.name || "unknown"}
          </span>
          <span className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
            pid {node.pid}
          </span>
          {node.verified && (
            <span
              className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-300"
              title="Parent edge verified by telemetry"
            >
              ✓ verified
            </span>
          )}
          {node.seed && (
            <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-cyan-300">
              seed
            </span>
          )}
          {isRoot && (
            <span className="rounded bg-violet-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-violet-300">
              root
            </span>
          )}
          {node.source && (
            <span className="rounded bg-slate-700/40 px-1.5 py-0.5 text-[10px] text-slate-400">
              {node.source}
            </span>
          )}
          <span className="text-[10px] text-slate-500">
            {node.first_seen
              ? new Date(node.first_seen).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })
              : ""}
          </span>
        </div>
        {node.cmdline && (
          <p className="mt-1 truncate font-mono text-[10px] text-slate-500" title={node.cmdline}>
            {node.cmdline}
          </p>
        )}
      </div>
      {expanded && kids.length > 0 && (
        <ul className="ml-5 space-y-1.5 border-l border-slate-700/50 pl-3 pt-1.5">
          {kids.map((c) => (
            <ProcessTreeNode key={c.pid} node={c} depth={depth + 1} children={children} />
          ))}
        </ul>
      )}
    </li>
  );
}

function ProcessTreePanel({ tree }) {
  if (!tree || !tree.primary || tree.node_count === 0) {
    return (
      <Card>
        <h3 className="mb-2 text-base font-semibold text-white">Process Tree</h3>
        <p className="text-sm text-slate-400">
          No process-creation events found around this alert — the tree could not be
          reconstructed.
        </p>
      </Card>
    );
  }

  const primary = tree.primary;
  const children = (parentPid) =>
    (primary.nodes || []).filter((n) => n.parent_pid === parentPid && n.pid !== parentPid);
  const roots = (primary.nodes || []).filter((n) => !n.parent_pid);

  return (
    <Card>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-white">
            Process Tree{" "}
            <span className="text-xs font-normal text-slate-500">
              ({primary.node_count} nodes · host {primary.host})
            </span>
          </h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Reconstructed parent/child lineage · root → trigger process
          </p>
        </div>
        <span className="shrink-0 rounded bg-slate-800 px-2 py-1 font-mono text-[10px] text-slate-400">
          completeness {Math.round((tree.completeness || 0) * 100)}%
        </span>
      </div>

      {tree.chain && tree.chain.length > 1 && (
        <div className="mb-4 rounded-lg border border-violet-500/25 bg-violet-500/5 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-violet-300">
            Root → trigger chain
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {tree.chain.map((n, i) => (
              <span key={i} className="flex items-center gap-1.5">
                {i > 0 && <span className="text-[10px] text-slate-500">→</span>}
                <span
                  className={`rounded px-2 py-0.5 font-mono text-[11px] ${
                    n.seed
                      ? "bg-cyan-500/20 font-semibold text-cyan-300"
                      : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {n.name || `pid ${n.pid}`}
                </span>
              </span>
            ))}
          </div>
        </div>
      )}

      {tree.aftermath && tree.aftermath.length > 0 && (
        <div className="mb-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
            Launched after the trigger ({tree.aftermath.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {tree.aftermath.map((n, i) => (
              <span
                key={i}
                className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-300"
              >
                {n.name || `pid ${n.pid}`}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="max-h-96 space-y-0 overflow-y-auto">
        {roots.length > 0 ? (
          roots.map((n) => (
            <ul key={n.pid} className="space-y-1.5">
              <ProcessTreeNode node={n} depth={0} children={children} />
            </ul>
          ))
        ) : (
          <ul className="space-y-1.5">
            {(primary.nodes || []).slice(0, 50).map((n) => (
              <ProcessTreeNode key={n.pid} node={n} depth={0} children={() => []} />
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

function VerdictPanel({ verdict, alertId, onApply }) {
  const [applying, setApplying] = useState("");
  const [applied, setApplied] = useState("");
  const colors = {
    true_positive: "border-rose-500/50 bg-rose-500/10 text-rose-300",
    false_positive: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
    expected_behavior: "border-sky-500/50 bg-sky-500/10 text-sky-300",
    needs_review: "border-slate-600/50 bg-slate-800/50 text-slate-300",
  };
  if (!verdict) return null;

  const apply = async (value) => {
    setApplying(value);
    setApplied("");
    try {
      await api.submitAlertVerdict(alertId, { verdict: value, note: "Applied from investigation" });
      setApplied(value);
      if (onApply) onApply();
    } catch (e) {
      setApplied(`error: ${e.message}`);
    } finally {
      setApplying("");
    }
  };

  const pct = Math.round((verdict.confidence || 0) * 100);

  return (
    <Card>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-white">Suggested Verdict</h3>
        <span className="font-mono text-[10px] text-slate-500">auto-generated</span>
      </div>
      <div
        className={`rounded-lg border px-4 py-3 ${colors[verdict.suggested] || colors.needs_review}`}
      >
        <div className="flex items-center justify-between gap-3">
          <span className="text-sm font-bold uppercase tracking-wide">{verdict.label}</span>
          <span className="font-mono text-xs">{pct}%</span>
        </div>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-black/30">
          <div
            className="h-full rounded-full bg-current opacity-70"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>
      {verdict.reasons && verdict.reasons.length > 0 && (
        <ul className="mt-3 space-y-1">
          {verdict.reasons.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-[11px] text-slate-400">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-slate-600" />
              {r}
            </li>
          ))}
        </ul>
      )}
      {verdict.suggested !== "needs_review" && (
        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => apply(verdict.suggested)}
            disabled={!!applying}
            className="rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
          >
            {applying ? "Applying..." : `Apply: ${verdict.label}`}
          </button>
          <button
            type="button"
            onClick={() => apply("false_positive")}
            disabled={!!applying}
            className="rounded-lg border border-slate-700 px-4 py-2 text-xs text-slate-300 transition-colors hover:border-emerald-500/50 hover:text-emerald-300 disabled:opacity-50"
          >
            Mark FP
          </button>
          <button
            type="button"
            onClick={() => apply("expected_behavior")}
            disabled={!!applying}
            className="rounded-lg border border-slate-700 px-4 py-2 text-xs text-slate-300 transition-colors hover:border-sky-500/50 hover:text-sky-300 disabled:opacity-50"
          >
            Expected
          </button>
        </div>
      )}
      {applied && (
        <p className="mt-3 text-sm text-emerald-600 dark:text-emerald-400">
          {applied.startsWith("error") ? applied : "Verdict saved — feedback fed to ML"}
        </p>
      )}
    </Card>
  );
}

function RelatedAlertsPanel({ related, onSelect }) {
  if (!related || related.length === 0) return null;
  return (
    <Card>
      <div className="mb-4 flex items-center justify-between gap-2">
        <div>
          <h3 className="text-base font-semibold text-white">
            Related Alerts ({related.length})
          </h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Same story: shared events, host, user or correlation chain
          </p>
        </div>
      </div>
      <div className="space-y-2">
        {related.map((r) => (
          <button
            key={r.id}
            type="button"
            onClick={() => onSelect(String(r.id))}
            className="w-full rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2.5 text-left transition-colors hover:border-cyan-500/40"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="truncate text-xs font-semibold text-slate-200">
                  #{r.id} {r.name}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {r.verdict && (
                  <span className="rounded bg-black/30 px-1.5 py-0.5 font-mono text-[9px] text-slate-400">
                    {r.verdict}
                  </span>
                )}
                <span className="font-mono text-[10px] text-slate-500">
                  rel {r.relevance_score?.toFixed?.(1) ?? r.relevance_score}
                </span>
              </div>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-slate-500">
              <span className="font-mono">{r.rule}</span>
              <span>{r.reasons?.join(", ")}</span>
            </div>
          </button>
        ))}
      </div>
    </Card>
  );
}

function RiskProfilePanel({ profile }) {
  if (!profile) return null;
  const orig = profile.original_risk || 0;
  const adj = profile.adjusted_risk || 0;
  const max = Math.max(100, orig, adj);
  return (
    <Card>
      <h3 className="mb-3 text-base font-semibold text-white">Context-Adjusted Risk</h3>
      <div className="space-y-2">
        <div>
          <div className="flex justify-between text-[11px] text-slate-400">
            <span>Raw risk score</span>
            <span className="font-mono text-slate-200">{orig.toFixed(1)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-orange-500"
              style={{ width: `${(orig / max) * 100}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex justify-between text-[11px] text-slate-400">
            <span>Adjusted by context (×{profile.modifier})</span>
            <span className="font-mono text-emerald-300">{adj.toFixed(1)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-emerald-500"
              style={{ width: `${(adj / max) * 100}%` }}
            />
          </div>
        </div>
      </div>
      {profile.notes && profile.notes.length > 0 && (
        <ul className="mt-3 space-y-1">
          {profile.notes.map((n, i) => (
            <li key={i} className="text-[11px] text-slate-500">
              · {n}
            </li>
          ))}
        </ul>
      )}
      {profile.entities && profile.entities.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {profile.entities.map((e, i) => (
            <span
              key={i}
              className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300"
            >
              {e.kind}:{e.name} {e.risk_level} ({e.risk_score})
            </span>
          ))}
        </div>
      )}
    </Card>
  );
}

function StoryTimeline({ timeline }) {
  if (!timeline || timeline.length === 0) return null;
  const kindColor = {
    alert: "border-rose-500/40 text-rose-300",
    network: "border-sky-500/40 text-sky-300",
    event: "border-slate-600/50 text-slate-300",
  };
  return (
    <Card>
      <div className="mb-4 flex items-center justify-between gap-2">
        <div>
          <h3 className="text-base font-semibold text-white">
            Full Story Timeline ({timeline.length})
          </h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Evidence, process activity, network and related alerts in one view
          </p>
        </div>
      </div>
      <div className="relative ml-2 max-h-96 space-y-2 overflow-y-auto border-l border-slate-700/60 pl-6">
        {timeline.map((t, idx) => (
          <div key={idx} className="relative">
            <span
              className={`absolute -left-[27px] top-3 h-2.5 w-2.5 rounded-full border-2 border-slate-950 ${
                t.kind === "alert"
                  ? "bg-rose-500"
                  : t.kind === "network"
                    ? "bg-sky-500"
                    : t.tag === "evidence"
                      ? "bg-cyan-400"
                      : "bg-slate-600"
              }`}
            />
            <div className="rounded-lg border border-slate-700/40 bg-slate-900/30 px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-slate-200">{t.title}</span>
                <span className="font-mono text-[10px] text-slate-500">
                  {new Date(t.ts).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <span
                  className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${kindColor[t.kind] || kindColor.event}`}
                >
                  {t.kind}
                  {t.tag ? `·${t.tag}` : ""}
                </span>
                {t.detail && <span className="text-[10px] text-slate-500">{t.detail}</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function Investigation() {
  const [params, setParams] = useSearchParams();
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(params.get("alert") || "");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState("");

  useEffect(() => {
    api
      .alerts({ page_size: 100 })
      .then((r) => setAlerts(r.items || []))
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    const a = params.get("alert");
    if (a) setSelected(a);
  }, [params]);

  useEffect(() => {
    if (!selected) {
      setData(null);
      setExplanation("");
      return;
    }
    setError("");
    setData(null);
    api
      .investigate(selected)
      .then((d) => {
        setData(d);
        // Auto-run the AI analyst once the investigation context is loaded.
        api
          .assistantExplain(selected ? Number(selected) : undefined)
          .then((r) => setExplanation(r.reply))
          .catch(() => setExplanation(""));
      })
      .catch((e) => setError(e.message));
  }, [selected]);

  const chooseAlert = (id) => {
    setSelected(id);
    setParams(id ? { alert: id } : {});
  };

  const reload = () => {
    if (!selected) return;
    api
      .investigate(selected)
      .then((d) => setData(d))
      .catch((e) => setError(e.message));
  };

  const explain = async () => {
    setExplaining(true);
    setExplanation("");
    setError("");
    try {
      const res = await api.assistantExplain(selected ? Number(selected) : undefined);
      setExplanation(res.reply);
    } catch (e) {
      setError(e.message);
    } finally {
      setExplaining(false);
    }
  };

  const alert = alerts.find((a) => String(a.id) === String(selected));

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Threat Investigation"
        subtitle="Analyze attack chains, evidence and related events"
      />

      {/* Alert selection */}
      <Card>
        <label htmlFor="investigate-select" className="mb-3 block text-sm font-medium text-slate-300">
          Select Alert to Investigate
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <select
            id="investigate-select"
            value={selected}
            onChange={(e) => chooseAlert(e.target.value)}
            className="flex-1 rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2.5 text-sm text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          >
            <option value="">Select an alert...</option>
            {alerts.map((a) => (
              <option key={a.id} value={a.id}>
                #{a.id} {a.name} ({a.severity}) — {a.mitre_id}
              </option>
            ))}
          </select>
          {selected && (
            <button
              type="button"
              onClick={explain}
              disabled={explaining}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-600 to-violet-500 px-6 py-2.5 font-medium text-white transition-all hover:from-violet-500 hover:to-violet-400 disabled:opacity-50"
            >
              {explaining ? "Analyzing..." : "AI Analysis"}
            </button>
          )}
        </div>
      </Card>

      {error && <ErrorBanner message={error} />}

      {!selected && (
        <EmptyState
          title="No alert selected"
          subtitle="Choose an alert from the list above to start investigating"
          icon={<InvestigationIcon className="h-6 w-6" />}
        />
      )}

      {selected && !data && !error && <Loading label="Loading investigation data" />}

      {data && alert && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Alert summary */}
          <div className="lg:col-span-1">
            <Card>
              <h3 className="mb-4 text-base font-semibold text-white">Alert Summary</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Alert Name
                  </p>
                  <p className="mt-1 text-sm font-semibold text-white">{alert.name}</p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Severity
                  </p>
                  <div className="mt-1.5">
                    <SeverityBadge severity={alert.severity} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Risk
                  </p>
                  <div className="mt-1.5">
                    <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    MITRE ATT&CK
                  </p>
                  <p className="mt-1 font-mono text-sm text-white">{alert.mitre_id}</p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Status
                  </p>
                  <div className="mt-1.5">
                    <StatusBadge status={alert.status} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                    Detection Method
                  </p>
                  <p className="mt-1 text-sm capitalize text-slate-300">
                    {alert.detection_method || "rule"}
                  </p>
                </div>
              </div>
            </Card>

            <Card>
              <ConfidenceMeter
                score={data.story_confidence?.score}
                label={data.story_confidence?.label}
              />
              {data.story_confidence?.breakdown && (
                <ul className="mt-3 space-y-1 border-t border-slate-800/60 pt-3">
                  {data.story_confidence.breakdown.map((b, i) => (
                    <li key={i} className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>{b.factor}</span>
                      <span className="font-mono">{Math.round((b.score || 0) * 100)}%</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <VerdictPanel
              verdict={data.suggested_verdict}
              alertId={selected}
              onApply={reload}
            />

            <RiskProfilePanel profile={data.risk_profile} />
          </div>

          {/* Main investigation area */}
          <div className="space-y-6 lg:col-span-2">
            {/* Event timeline visualization */}
            <Card>
              <div className="mb-5 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <ActivityIcon className="h-5 w-5 text-cyan-400" />
                  <h3 className="text-base font-semibold text-white">Incident Timeline</h3>
                </div>
                <span className="text-[11px] text-slate-500">
                  {new Date().toLocaleDateString()} · {data.evidence_events?.length || 0} evidence +{" "}
                  {data.related_events?.length || 0} related events
                </span>
              </div>
              <TimelineGraph
                events={[
                  ...(data.evidence_events || []),
                  ...(data.related_events || []),
                ]}
                attackChain={data.attack_chain}
                windowMinutes={30}
              />
            </Card>

            {/* Full story timeline */}
            <StoryTimeline timeline={data.timeline} />

            {/* Process tree */}
            <ProcessTreePanel tree={data.process_tree} />

            {/* Related alerts */}
            <RelatedAlertsPanel related={data.related_alerts} onSelect={chooseAlert} />

            {/* Involved entities */}
            <InvolvedEntities data={data} />

            {/* Attack timeline */}
            <Card>
              <div className="mb-4 flex items-center gap-2">
                <ActivityIcon className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-semibold text-white">Attack Timeline</h3>
                <span className="text-[11px] text-slate-500">
                  {[data.evidence_events, data.related_events]
                    .flat()
                    .filter((e) => e && e.timestamp).length}{" "}
                  timed events
                </span>
              </div>
              <AttackTimeline
                events={[...(data.evidence_events || []), ...(data.related_events || [])]}
              />
            </Card>

            {/* Attack chain */}
            <Card>
              <div className="mb-5 flex items-center gap-2">
                <AlertIcon className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-semibold text-white">
                  Attack Chain ({data.attack_chain?.length || 0} steps)
                </h3>
              </div>
              {data.attack_chain && data.attack_chain.length > 0 ? (
                <div className="space-y-0">
                  {data.attack_chain.map((step, idx) => (
                    <div key={idx} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <StepDot index={idx + 1} active />
                        {idx < data.attack_chain.length - 1 && (
                          <div className="w-px flex-1 bg-gradient-to-b from-cyan-500/40 to-slate-700/40" />
                        )}
                      </div>
                      <div className="pb-6">
                        <p className="text-sm font-semibold text-slate-100">{step.step}</p>
                        <div className="mt-2 space-y-1.5">
                          {step.details.map((line, li) => (
                            <p
                              key={li}
                              className="rounded-lg border border-slate-700/40 bg-slate-800/30 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-400"
                            >
                              {line}
                            </p>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400">No attack chain steps available</p>
              )}
            </Card>

            {/* Evidence events */}
            <Card>
              <div className="mb-4 flex items-center gap-2">
                <ActivityIcon className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-semibold text-white">
                  Evidence Events ({data.evidence_events?.length || 0})
                </h3>
              </div>
              {data.evidence_events && data.evidence_events.length > 0 ? (
                <div className="max-h-96 space-y-2 overflow-y-auto">
                  {data.evidence_events.map((event, idx) => (
                    <EventChip key={idx} event={event} />
                  ))}
                </div>
              ) : (
                <EmptyState title="No evidence events" subtitle="No linked events recorded" />
              )}
            </Card>

            {/* Related events */}
            {data.related_events && data.related_events.length > 0 && (
              <Card>
                <div className="mb-4">
                  <h3 className="text-base font-semibold text-white">
                    Related Events ({data.related_events.length})
                  </h3>
                  <p className="mt-0.5 text-sm text-slate-400">
                    Events recorded ±30 minutes around the alert window
                  </p>
                </div>
                <div className="max-h-80 space-y-2 overflow-y-auto">
                  {data.related_events.map((event, idx) => (
                    <EventChip key={idx} event={event} compact />
                  ))}
                </div>
              </Card>
            )}

            {/* Network context */}
            {data.network_context && data.network_context.length > 0 && (
              <Card>
                <h3 className="mb-4 text-base font-semibold text-white">Network Context</h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {data.network_context.map((ctx, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-700/50 bg-slate-800/30 p-3"
                    >
                      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Connection
                      </p>
                      <p className="font-mono text-sm text-cyan-400">
                        {ctx.local_ip}:{ctx.local_port} → {ctx.remote_ip}:{ctx.remote_port}
                      </p>
                      <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                        <span>
                          Port: <strong className="font-mono">{ctx.remote_port}</strong>
                        </span>
                        <span>{ctx.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* Similar past incidents (RAG) */}
            {data.similar_incidents && data.similar_incidents.length > 0 && (
              <Card>
                <h3 className="mb-4 text-base font-semibold text-white">
                  Similar Past Incidents (resolved)
                </h3>
                <div className="space-y-3">
                  {data.similar_incidents.map((sim, idx) => (
                    <div key={idx} className="rounded-lg border border-violet-500/25 bg-violet-500/5 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-semibold text-slate-100">
                          #{sim.id} {sim.name}
                        </p>
                        <span className="rounded bg-black/30 px-2 py-0.5 text-[10px] font-mono text-slate-400">
                          {sim.mitre_id} · {sim.severity}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-slate-400">{sim.evidence}</p>
                      <p className="mt-1.5 text-xs text-cyan-300/80">
                        <span className="font-semibold text-cyan-400">Resolved via:</span>{" "}
                        {sim.recommendation}
                      </p>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* AI analysis */}
            {explanation && (
              <Card tone="violet">
                <h3 className="mb-3 text-base font-semibold text-white">AI Analysis</h3>
                <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-200">
                  {explanation}
                </p>
              </Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
