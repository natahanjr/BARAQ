import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import TimelineGraph from "../components/TimelineGraph.jsx";

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
          ? "border-[var(--accent-cyan)]/50 bg-[var(--accent-cyan)]/20 text-[var(--accent-cyan)]"
          : "border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--fg-muted)]"
      }`}
    >
      {index}
    </span>
  );
}

function EventChip({ event, compact }) {
  const colors = {
    critical: "border-[var(--severity-critical)]/40 bg-[var(--severity-critical)]/10 text-[var(--severity-critical)]",
    high: "border-[var(--severity-high)]/40 bg-[var(--severity-high)]/10 text-[var(--severity-high)]",
    medium: "border-[var(--severity-medium)]/40 bg-[var(--severity-medium)]/10 text-[var(--severity-medium)]",
    low: "border-[var(--severity-low)]/40 bg-[var(--severity-low)]/10 text-[var(--severity-low)]",
  };

  const severity = (event.severity || "low").toLowerCase();
  const color = colors[severity] || colors.low;

  return (
    <div className={`rounded-[var(--radius-2xl)] border ${color} p-3`}>
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded bg-[var(--bg-inset)] px-2 py-0.5 font-mono text-[10px] text-[var(--fg-primary)]">
            Event {event.event_id}
          </span>
          {event.is_anomaly && (
            <span className="rounded bg-[var(--accent-violet)]/15 px-2 py-0.5 text-[10px] font-semibold text-[var(--accent-violet)]">
              ML anomaly
            </span>
          )}
        </div>
        <span className="text-[11px] text-[var(--fg-muted)]">
          {event.timestamp
            ? new Date(event.timestamp).toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              })
            : "\u2014"}
        </span>
      </div>
      {!compact && (
        <p className="text-xs leading-relaxed text-[var(--fg-secondary)]">{event.message || event.category}</p>
      )}
      <p className="mt-1.5 text-[11px] text-[var(--fg-muted)]">
        User: <strong className="text-[var(--fg-primary)]">{event.user || "\u2014"}</strong>
        {event.risk_score != null && (
          <>
            {" "}
            · Risk: <strong className="text-[var(--fg-primary)]">{event.risk_score.toFixed(0)}</strong>
          </>
        )}
      </p>
    </div>
  );
}

function AttackTimeline({ events }) {
  const [expanded, setExpanded] = useState(new Set());
  const toggle = (i) => setExpanded((prev) => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; });

  const rows = (events || [])
    .filter((e) => e.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  if (rows.length === 0) {
    return <EmptyState title="No timed events" subtitle="Nothing to lay out chronologically" />;
  }

  const sevColors = {
    critical: { dot: "bg-[var(--severity-critical)]", ring: "ring-[var(--severity-critical)]/30", bg: "border-[var(--severity-critical)]/40 bg-[var(--severity-critical)]/10", text: "text-[var(--severity-critical)]", line: "from-[var(--severity-critical)]/60" },
    high: { dot: "bg-[var(--severity-high)]", ring: "ring-[var(--severity-high)]/30", bg: "border-[var(--severity-high)]/40 bg-[var(--severity-high)]/10", text: "text-[var(--severity-high)]", line: "from-[var(--severity-high)]/60" },
    medium: { dot: "bg-[var(--severity-medium)]", ring: "ring-[var(--severity-medium)]/30", bg: "border-[var(--severity-medium)]/40 bg-[var(--severity-medium)]/10", text: "text-[var(--severity-medium)]", line: "from-[var(--severity-medium)]/60" },
    low: { dot: "bg-[var(--severity-low)]", ring: "ring-[var(--severity-low)]/30", bg: "border-[var(--severity-low)]/40 bg-[var(--severity-low)]/10", text: "text-[var(--severity-low)]", line: "from-[var(--severity-low)]/60" },
  };

  const chains = [];
  let currentChain = [rows[0]];
  for (let i = 1; i < rows.length; i++) {
    const prev = new Date(rows[i - 1].timestamp).getTime();
    const curr = new Date(rows[i].timestamp).getTime();
    if (curr - prev < 5 * 60 * 1000) {
      currentChain.push(rows[i]);
    } else {
      chains.push(currentChain);
      currentChain = [rows[i]];
    }
  }
  chains.push(currentChain);

  return (
    <div className="space-y-3">
      {chains.map((chain, ci) => {
        const chainId = `chain-${ci}`;
        const isExpanded = expanded.has(chainId) || chain.length <= 3;
        const firstSev = (chain[0].severity || "low").toLowerCase();
        const sc = sevColors[firstSev] || sevColors.low;
        return (
          <div key={ci}>
            {chain.length > 3 && (
              <button
                onClick={() => toggle(chainId)}
                className="mb-1 flex w-full items-center gap-2 rounded-t-[var(--radius-2xl)] border border-b-0 border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-left transition-colors hover:bg-[var(--bg-inset)]"
              >
                <span className="text-[10px] text-[var(--fg-faint)]">{isExpanded ? "\u25BC" : "\u25B6"}</span>
                <span className="flex-1 text-[11px] font-medium text-[var(--fg-secondary)]">
                  Chain #{ci + 1} — {chain.length} events
                </span>
                <span className="font-mono text-[10px] text-[var(--fg-faint)]">
                  {new Date(chain[0].timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  {" \u2014 "}
                  {new Date(chain[chain.length - 1].timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </span>
              </button>
            )}
            <div className="relative ml-2 border-l-2 border-[var(--border-subtle)]">
              {(isExpanded ? chain : [chain[0]]).map((e, idx) => {
                const sev = (e.severity || "low").toLowerCase();
                const colors = sevColors[sev] || sevColors.low;
                const isLast = idx === (isExpanded ? chain.length - 1 : 0);
                return (
                  <div key={idx} className="relative ml-4 pb-4">
                    <span className={`absolute -left-[25px] top-3 h-3 w-3 rounded-full border-2 border-[var(--bg-primary)] ${colors.dot} ${e.is_anomaly ? `shadow-[0_0_10px_rgba(139,92,246,0.9)] ring-2 ${colors.ring}` : ""}`} />
                    {!isLast && isExpanded && (
                      <div className={`absolute -left-[23px] top-6 h-[calc(100%-12px)] w-0.5 bg-gradient-to-b ${colors.line} to-transparent`} />
                    )}
                    <div className={`rounded-[var(--radius-2xl)] border ${colors.bg} px-4 py-3 transition-all hover:shadow-md ${e.is_anomaly ? "ring-1 ring-[var(--accent-violet)]/30" : ""}`}>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-[var(--fg-faint)]">Event {e.event_id}</span>
                          {e.is_anomaly && (
                            <span className="rounded bg-[var(--accent-violet)]/20 px-1.5 py-0.5 text-[9px] font-bold text-[var(--accent-violet)]">ML ANOMALY</span>
                          )}
                        </div>
                        <span className="font-mono text-[10px] text-[var(--fg-muted)]">
                          {new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs leading-relaxed text-[var(--fg-secondary)]">{e.message || e.category}</p>
                      <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-[var(--fg-faint)]">
                        {e.user && <span>user <strong className="text-[var(--fg-secondary)]">{e.user}</strong></span>}
                        {e.host && <span>host <strong className="text-[var(--fg-secondary)]">{e.host}</strong></span>}
                        {e.risk_score != null && <span>risk <strong className="text-[var(--fg-secondary)]">{e.risk_score.toFixed(0)}</strong></span>}
                      </div>
                    </div>
                    {isExpanded && chain.length > 1 && (
                      <div className="absolute -left-[46px] top-2.5 flex h-5 w-5 items-center justify-center rounded-full bg-[var(--bg-inset)] text-[9px] font-bold text-[var(--fg-muted)] ring-1 ring-[var(--border-default)]">
                        {idx + 1}
                      </div>
                    )}
                  </div>
                );
              })}
              {!isExpanded && chain.length > 3 && (
                <p className="ml-4 mt-1 text-[10px] text-[var(--fg-faint)]">+{chain.length - 3} more events...</p>
              )}
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
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">Involved Entities</h3>
          <p className="mt-0.5 text-sm text-[var(--fg-muted)]">
            Users and hosts touching this alert — click to open in the entity graph
          </p>
        </div>
        <span className="text-[var(--accent-cyan)]">🔗</span>
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {rows.map((e) => (
          <Link
            key={e.key}
            to={`/rba?kind=${e.kind}&name=${encodeURIComponent(e.name)}`}
            className="flex items-center justify-between gap-2 rounded-[var(--radius-2xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 transition-colors hover:border-[var(--accent-cyan)]/40"
          >
            <span className="flex min-w-0 items-center gap-2">
              <span
                className="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[9px] font-bold"
                style={{ backgroundColor: KINDS_COLOR[e.kind] || "#64748b" }}
              >
                {e.kind.slice(0, 1).toUpperCase()}
              </span>
              <span className="min-w-0">
                <span className="block truncate font-mono text-xs text-[var(--fg-primary)]">{e.name}</span>
                <span className="block text-[10px] text-[var(--fg-faint)]">
                  {e.kind} · {e.count} event{e.count === 1 ? "" : "s"}
                </span>
              </span>
            </span>
            <span className="shrink-0 text-[10px] text-[var(--accent-cyan)]">→</span>
          </Link>
        ))}
      </div>
    </div>
  );
}

function ConfidenceMeter({ score, label }) {
  const pct = Math.round((score || 0) * 100);
  const color =
    pct >= 75 ? "bg-[var(--status-healthy)]" : pct >= 50 ? "bg-[var(--severity-medium)]" : "bg-[var(--severity-critical)]";
  return (
    <div>
      <div className="flex items-center justify-between text-[11px] text-[var(--fg-muted)]">
        <span>
          Story confidence:{" "}
          <strong className="uppercase text-[var(--fg-primary)]">{label || "low"}</strong>
        </span>
        <span className="font-mono">{pct}%</span>
      </div>
      <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
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
        className={`rounded-[var(--radius-2xl)] border px-3 py-2 ${
          node.seed
            ? "border-[var(--accent-cyan)]/50 bg-[var(--accent-cyan)]/10"
            : isRoot
              ? "border-[var(--accent-violet)]/40 bg-[var(--accent-violet)]/10"
              : "border-[var(--border-default)] bg-[var(--bg-inset)]"
        }`}
      >
        <div className="flex flex-wrap items-center gap-2">
          {kids.length > 0 && (
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              aria-label={expanded ? "Collapse subtree" : "Expand subtree"}
              className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-[var(--bg-inset)] font-mono text-[10px] text-[var(--fg-secondary)] transition-colors hover:bg-[var(--border-default)]"
            >
              {expanded ? "\u2212" : `${kids.length}+`}
            </button>
          )}
          <span className="font-mono text-xs font-semibold text-[var(--fg-primary)]">
            {node.name || "unknown"}
          </span>
          <span className="rounded bg-[var(--bg-inset)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--fg-muted)]">
            pid {node.pid}
          </span>
          {node.verified && (
            <span
              className="rounded bg-[var(--status-healthy)]/15 px-1.5 py-0.5 text-[10px] font-semibold text-[var(--status-healthy)]"
              title="Parent edge verified by telemetry"
            >
              ✓ verified
            </span>
          )}
          {node.seed && (
            <span className="rounded bg-[var(--accent-cyan)]/20 px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-cyan)]">
              seed
            </span>
          )}
          {isRoot && (
            <span className="rounded bg-[var(--accent-violet)]/20 px-1.5 py-0.5 text-[10px] font-semibold text-[var(--accent-violet)]">
              root
            </span>
          )}
          {node.source && (
            <span className="rounded bg-[var(--border-default)]/40 px-1.5 py-0.5 text-[10px] text-[var(--fg-muted)]">
              {node.source}
            </span>
          )}
          <span className="text-[10px] text-[var(--fg-faint)]">
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
          <p className="mt-1 truncate font-mono text-[10px] text-[var(--fg-faint)]" title={node.cmdline}>
            {node.cmdline}
          </p>
        )}
      </div>
      {expanded && kids.length > 0 && (
        <ul className="ml-5 space-y-1.5 border-l border-[var(--border-default)] pl-3 pt-1.5">
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
      <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
        <h3 className="mb-2 text-base font-semibold text-[var(--fg-primary)]">Process Tree</h3>
        <p className="text-sm text-[var(--fg-muted)]">
          No process-creation events found around this alert — the tree could not be
          reconstructed.
        </p>
      </div>
    );
  }

  const primary = tree.primary;
  const children = (parentPid) =>
    (primary.nodes || []).filter((n) => n.parent_pid === parentPid && n.pid !== parentPid);
  const roots = (primary.nodes || []).filter((n) => !n.parent_pid);

  return (
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">
            Process Tree{" "}
            <span className="text-xs font-normal text-[var(--fg-faint)]">
              ({primary.node_count} nodes · host {primary.host})
            </span>
          </h3>
          <p className="mt-0.5 text-sm text-[var(--fg-muted)]">
            Reconstructed parent/child lineage · root → trigger process
          </p>
        </div>
        <span className="shrink-0 rounded bg-[var(--bg-inset)] px-2 py-1 font-mono text-[10px] text-[var(--fg-muted)]">
          completeness {Math.round((tree.completeness || 0) * 100)}%
        </span>
      </div>

      {tree.chain && tree.chain.length > 1 && (
        <div className="mb-4 rounded-[var(--radius-2xl)] border border-[var(--accent-violet)]/25 bg-[var(--accent-violet)]/5 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--accent-violet)]">
            Root → trigger chain
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {tree.chain.map((n, i) => (
              <span key={i} className="flex items-center gap-1.5">
                {i > 0 && <span className="text-[10px] text-[var(--fg-faint)]">→</span>}
                <span
                  className={`rounded px-2 py-0.5 font-mono text-[11px] ${
                    n.seed
                      ? "bg-[var(--accent-cyan)]/20 font-semibold text-[var(--accent-cyan)]"
                      : "bg-[var(--bg-inset)] text-[var(--fg-secondary)]"
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
        <div className="mb-4 rounded-[var(--radius-2xl)] border border-[var(--accent-cyan)]/25 bg-[var(--accent-cyan)]/5 p-3">
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--accent-cyan)]">
            Launched after the trigger ({tree.aftermath.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {tree.aftermath.map((n, i) => (
              <span
                key={i}
                className="rounded bg-[var(--bg-inset)] px-2 py-0.5 font-mono text-[11px] text-[var(--fg-secondary)]"
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
    </div>
  );
}

function VerdictPanel({ verdict, alertId, onApply }) {
  const [applying, setApplying] = useState("");
  const [applied, setApplied] = useState("");
  const colors = {
    true_positive: "border-[var(--severity-critical)]/50 bg-[var(--severity-critical)]/10 text-[var(--severity-critical)]",
    false_positive: "border-[var(--status-healthy)]/50 bg-[var(--status-healthy)]/10 text-[var(--status-healthy)]",
    expected_behavior: "border-[var(--accent-cyan)]/50 bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)]",
    needs_review: "border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--fg-secondary)]",
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
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h3 className="text-base font-semibold text-[var(--fg-primary)]">Suggested Verdict</h3>
        <span className="font-mono text-[10px] text-[var(--fg-faint)]">auto-generated</span>
      </div>
      <div
        className={`rounded-[var(--radius-2xl)] border px-4 py-3 ${colors[verdict.suggested] || colors.needs_review}`}
      >
        <div className="flex items-center justify-between gap-3">
          <span className="text-sm font-bold uppercase tracking-wide">{verdict.label}</span>
          <span className="font-mono text-xs">{pct}%</span>
        </div>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
          <div
            className="h-full rounded-full bg-current opacity-70"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>
      {verdict.reasons && verdict.reasons.length > 0 && (
        <ul className="mt-3 space-y-1">
          {verdict.reasons.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-[11px] text-[var(--fg-muted)]">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-[var(--fg-faint)]" />
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
            className="rounded-xl bg-[var(--accent-cyan)] px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-[var(--accent-cyan)]/25 transition-all hover:shadow-xl disabled:opacity-50"
          >
            {applying ? "Applying..." : `Apply: ${verdict.label}`}
          </button>
          <button
            type="button"
            onClick={() => apply("false_positive")}
            disabled={!!applying}
            className="rounded-xl border border-[var(--border-default)] px-4 py-2 text-xs text-[var(--fg-secondary)] transition-colors hover:border-[var(--status-healthy)]/50 hover:text-[var(--status-healthy)] disabled:opacity-50"
          >
            Mark FP
          </button>
          <button
            type="button"
            onClick={() => apply("expected_behavior")}
            disabled={!!applying}
            className="rounded-xl border border-[var(--border-default)] px-4 py-2 text-xs text-[var(--fg-secondary)] transition-colors hover:border-[var(--accent-cyan)]/50 hover:text-[var(--accent-cyan)] disabled:opacity-50"
          >
            Expected
          </button>
        </div>
      )}
      {applied && (
        <p className="mt-3 text-sm text-[var(--status-healthy)]">
          {applied.startsWith("error") ? applied : "Verdict saved — feedback fed to ML"}
        </p>
      )}
    </div>
  );
}

function RelatedAlertsPanel({ related, onSelect }) {
  if (!related || related.length === 0) return null;
  return (
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">
            Related Alerts ({related.length})
          </h3>
          <p className="mt-0.5 text-sm text-[var(--fg-muted)]">
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
            className="w-full rounded-[var(--radius-2xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2.5 text-left transition-colors hover:border-[var(--accent-cyan)]/40"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="truncate text-xs font-semibold text-[var(--fg-primary)]">
                  #{r.id} {r.name}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {r.verdict && (
                  <span className="rounded bg-[var(--bg-inset)] px-1.5 py-0.5 font-mono text-[9px] text-[var(--fg-muted)]">
                    {r.verdict}
                  </span>
                )}
                <span className="font-mono text-[10px] text-[var(--fg-faint)]">
                  rel {r.relevance_score?.toFixed?.(1) ?? r.relevance_score}
                </span>
              </div>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-[var(--fg-faint)]">
              <span className="font-mono">{r.rule}</span>
              <span>{r.reasons?.join(", ")}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function RiskProfilePanel({ profile }) {
  if (!profile) return null;
  const orig = profile.original_risk || 0;
  const adj = profile.adjusted_risk || 0;
  const max = Math.max(100, orig, adj);
  return (
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <h3 className="mb-3 text-base font-semibold text-[var(--fg-primary)]">Context-Adjusted Risk</h3>
      <div className="space-y-2">
        <div>
          <div className="flex justify-between text-[11px] text-[var(--fg-muted)]">
            <span>Raw risk score</span>
            <span className="font-mono text-[var(--fg-primary)]">{orig.toFixed(1)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
            <div
              className="h-full rounded-full bg-[var(--severity-high)]"
              style={{ width: `${(orig / max) * 100}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex justify-between text-[11px] text-[var(--fg-muted)]">
            <span>Adjusted by context (×{profile.modifier})</span>
            <span className="font-mono text-[var(--status-healthy)]">{adj.toFixed(1)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-inset)]">
            <div
              className="h-full rounded-full bg-[var(--status-healthy)]"
              style={{ width: `${(adj / max) * 100}%` }}
            />
          </div>
        </div>
      </div>
      {profile.notes && profile.notes.length > 0 && (
        <ul className="mt-3 space-y-1">
          {profile.notes.map((n, i) => (
            <li key={i} className="text-[11px] text-[var(--fg-faint)]">
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
              className="rounded bg-[var(--bg-inset)] px-2 py-0.5 font-mono text-[10px] text-[var(--fg-secondary)]"
            >
              {e.kind}:{e.name} {e.risk_level} ({e.risk_score})
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function StoryTimeline({ timeline }) {
  if (!timeline || timeline.length === 0) return null;
  const kindColor = {
    alert: "border-[var(--severity-critical)]/40 text-[var(--severity-critical)]",
    network: "border-[var(--accent-cyan)]/40 text-[var(--accent-cyan)]",
    event: "border-[var(--border-default)] text-[var(--fg-secondary)]",
  };
  return (
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="mb-4 flex items-center justify-between gap-2">
        <div>
          <h3 className="text-base font-semibold text-[var(--fg-primary)]">
            Full Story Timeline ({timeline.length})
          </h3>
          <p className="mt-0.5 text-sm text-[var(--fg-muted)]">
            Evidence, process activity, network and related alerts in one view
          </p>
        </div>
      </div>
      <div className="relative ml-2 max-h-96 space-y-2 overflow-y-auto border-l border-[var(--border-subtle)] pl-6">
        {timeline.map((t, idx) => (
          <div key={idx} className="relative">
            <span
              className={`absolute -left-[27px] top-3 h-2.5 w-2.5 rounded-full border-2 border-[var(--bg-primary)] ${
                t.kind === "alert"
                  ? "bg-[var(--severity-critical)]"
                  : t.kind === "network"
                    ? "bg-[var(--accent-cyan)]"
                    : t.tag === "evidence"
                      ? "bg-[var(--accent-cyan)]"
                      : "bg-[var(--fg-faint)]"
              }`}
            />
            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold text-[var(--fg-primary)]">{t.title}</span>
                <span className="font-mono text-[10px] text-[var(--fg-faint)]">
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
                {t.detail && <span className="text-[10px] text-[var(--fg-faint)]">{t.detail}</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const SECTION_ICONS = {
  "what this alert likely means": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  ),
  "mitre att&ck mapping": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
    </svg>
  ),
  "detection": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
    </svg>
  ),
  "investigation": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  ),
  "containment": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  "why it's labeled": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  "pro tips": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83" />
    </svg>
  ),
  "bottom line": (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  ),
};

const SECTION_COLORS = {
  "what this alert likely means": "from-amber-500/10 to-orange-500/5 border-amber-500/20 text-amber-600",
  "mitre att&ck mapping": "from-red-500/10 to-rose-500/5 border-red-500/20 text-red-600",
  "detection": "from-emerald-500/10 to-green-500/5 border-emerald-500/20 text-emerald-600",
  "investigation": "from-blue-500/10 to-cyan-500/5 border-blue-500/20 text-blue-600",
  "containment": "from-purple-500/10 to-violet-500/5 border-purple-500/20 text-purple-600",
  "why it's labeled": "from-rose-500/10 to-pink-500/5 border-rose-500/20 text-rose-600",
  "pro tips": "from-cyan-500/10 to-teal-500/5 border-cyan-500/20 text-cyan-600",
  "bottom line": "from-emerald-500/10 to-green-500/5 border-emerald-500/20 text-emerald-600",
};

function getSectionColor(title) {
  const lower = title.toLowerCase();
  for (const [key, val] of Object.entries(SECTION_COLORS)) {
    if (lower.includes(key)) return val;
  }
  return "from-violet-500/10 to-indigo-500/5 border-violet-500/20 text-violet-600";
}

function getSectionIcon(title) {
  const lower = title.toLowerCase();
  for (const [key, val] of Object.entries(SECTION_ICONS)) {
    if (lower.includes(key)) return val;
  }
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" />
    </svg>
  );
}

function fmtInline(s) {
  const parts = [];
  let rest = s;
  let key = 0;
  while (rest) {
    const boldMatch = rest.match(/\*\*(.+?)\*\*/);
    const codeMatch = rest.match(/`(.+?)`/);
    if (boldMatch && (!codeMatch || boldMatch.index <= codeMatch.index)) {
      if (boldMatch.index > 0) parts.push(<span key={key++}>{rest.slice(0, boldMatch.index)}</span>);
      parts.push(<strong key={key++} className="font-semibold text-[var(--fg-primary)]">{boldMatch[1]}</strong>);
      rest = rest.slice(boldMatch.index + boldMatch[0].length);
    } else if (codeMatch) {
      if (codeMatch.index > 0) parts.push(<span key={key++}>{rest.slice(0, codeMatch.index)}</span>);
      parts.push(<code key={key++} className="rounded-md bg-[var(--bg-inset)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--accent-violet)]">{codeMatch[1]}</code>);
      rest = rest.slice(codeMatch.index + codeMatch[0].length);
    } else {
      parts.push(<span key={key++}>{rest}</span>);
      break;
    }
  }
  return parts;
}

function AIAnalysisContent({ text }) {
  if (!text) return null;

  const lines = text.split("\n");
  const sections = [];
  let current = null;
  let pendingTable = null;

  const flushTable = () => {
    if (pendingTable && current) {
      current.items.push({ kind: "table", rows: pendingTable });
      pendingTable = null;
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("### ")) {
      flushTable();
      if (current) sections.push(current);
      current = { title: trimmed.slice(4).trim(), items: [], type: "section" };
    } else if (trimmed.startsWith("## ")) {
      flushTable();
      if (current) sections.push(current);
      current = { title: trimmed.slice(3).trim(), items: [], type: "section" };
    } else if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
      if (!current) current = { title: "", items: [], type: "section" };
      const cells = trimmed.split("|").slice(1, -1).map((c) => c.trim());
      if (cells.every((c) => /^[-:]+$/.test(c))) {
        continue;
      }
      if (!pendingTable) pendingTable = [];
      pendingTable.push(cells);
    } else {
      flushTable();
      if (trimmed.startsWith("> ")) {
        if (!current) current = { title: "", items: [], type: "section" };
        current.items.push({ kind: "quote", text: trimmed.slice(2).trim() });
      } else if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        if (!current) current = { title: "", items: [], type: "section" };
        current.items.push({ kind: "bullet", text: trimmed.slice(2).trim() });
      } else if (trimmed.match(/^\d+\.\s/)) {
        if (!current) current = { title: "", items: [], type: "section" };
        current.items.push({ kind: "numbered", text: trimmed.replace(/^\d+\.\s/, "").trim() });
      } else if (trimmed) {
        if (!current) current = { title: "", items: [], type: "section" };
        current.items.push({ kind: "text", text: trimmed });
      }
    }
  }
  flushTable();
  if (current) sections.push(current);

  return (
    <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1 custom-scrollbar">
      {sections.map((sec, i) => {
        const colorClass = getSectionColor(sec.title);
        const icon = getSectionIcon(sec.title);

        return (
          <div key={i} className={`rounded-2xl border bg-gradient-to-br ${colorClass} backdrop-blur-sm overflow-hidden transition-all duration-300`}>
            {sec.title ? (
              <div className="flex items-center gap-2.5 px-4 py-3">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-white/50 dark:bg-black/20">
                  {icon}
                </div>
                <h4 className="text-[13px] font-bold uppercase tracking-wide">{sec.title}</h4>
              </div>
            ) : (
              <div className="h-0" />
            )}
            <div className={`${sec.title ? "px-4 pb-4" : "p-4"} space-y-2`}>
              {sec.items.map((item, j) => {
                if (item.kind === "quote") {
                  return (
                    <div key={j} className="rounded-xl border-l-[3px] border-current/30 bg-white/40 dark:bg-black/15 px-3 py-2.5 backdrop-blur-sm">
                      <p className="text-[12px] leading-relaxed text-[var(--fg-secondary)]">{fmtInline(item.text)}</p>
                    </div>
                  );
                }
                if (item.kind === "bullet") {
                  return (
                    <div key={j} className="flex items-start gap-2.5 rounded-lg bg-white/30 dark:bg-black/10 px-3 py-2 backdrop-blur-sm">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-60" />
                      <p className="text-[12px] leading-relaxed text-[var(--fg-secondary)]">{fmtInline(item.text)}</p>
                    </div>
                  );
                }
                if (item.kind === "numbered") {
                  return (
                    <div key={j} className="flex items-start gap-2.5 rounded-lg bg-white/30 dark:bg-black/10 px-3 py-2 backdrop-blur-sm">
                      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-current/20 text-[10px] font-bold">
                        {j + 1}
                      </span>
                      <p className="text-[12px] leading-relaxed text-[var(--fg-secondary)]">{fmtInline(item.text)}</p>
                    </div>
                  );
                }
                if (item.kind === "table") {
                  const [header, ...body] = item.rows;
                  return (
                    <div key={j} className="rounded-xl overflow-hidden border border-current/10 bg-white/40 dark:bg-black/15 backdrop-blur-sm">
                      <div className="overflow-x-auto">
                        <table className="w-full text-[11px]">
                          <thead>
                            <tr className="bg-current/[0.06]">
                              {header.map((cell, ci) => (
                                <th key={ci} className="px-3 py-2 text-left font-bold uppercase tracking-wider text-[var(--fg-primary)] whitespace-nowrap">
                                  {fmtInline(cell)}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-current/[0.06]">
                            {body.map((row, ri) => (
                              <tr key={ri} className="hover:bg-current/[0.03] transition-colors">
                                {row.map((cell, ci) => (
                                  <td key={ci} className="px-3 py-2 text-[var(--fg-secondary)] whitespace-nowrap">
                                    {fmtInline(cell)}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                }
                return (
                  <p key={j} className="text-[12px] leading-relaxed text-[var(--fg-secondary)]">{fmtInline(item.text)}</p>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
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
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Investigation</p>
          <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">Threat Investigation</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Analyze attack chains, evidence and related events</p>
        </div>
      </header>

      <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
        <label htmlFor="investigate-select" className="mb-3 block text-sm font-medium text-[var(--fg-secondary)]">
          Select Alert to Investigate
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <select
            id="investigate-select"
            value={selected}
            onChange={(e) => chooseAlert(e.target.value)}
            className="flex-1 rounded-xl border border-[var(--border-default)] bg-[var(--bg-inset)] px-4 py-2.5 text-sm text-[var(--fg-primary)] focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
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
              className="inline-flex items-center justify-center gap-2.5 rounded-xl bg-gradient-to-r from-violet-600 via-violet-500 to-indigo-500 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-violet-500/25 transition-all hover:shadow-xl hover:shadow-violet-500/30 hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:scale-100 disabled:shadow-none"
            >
              {explaining ? (
                <>
                  <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Analyzing...
                </>
              ) : (
                <>
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 2L2 7l10 5 10-5-10-5z" />
                    <path d="M2 17l10 5 10-5" />
                    <path d="M2 12l10 5 10-5" />
                  </svg>
                  AI Analysis
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {!selected && (
        <EmptyState
          title="No alert selected"
          subtitle="Choose an alert from the list above to start investigating"
          icon={<span className="text-2xl">🔍</span>}
        />
      )}

      {selected && !data && !error && <Loading label="Loading investigation data" />}

      {data && alert && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="lg:col-span-1">
            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <h3 className="mb-4 text-base font-semibold text-[var(--fg-primary)]">Alert Summary</h3>
              <div className="space-y-4">
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    Alert Name
                  </p>
                  <p className="mt-1 text-sm font-semibold text-[var(--fg-primary)]">{alert.name}</p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    Severity
                  </p>
                  <div className="mt-1.5">
                    <SeverityBadge severity={alert.severity} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    Risk
                  </p>
                  <div className="mt-1.5">
                    <RiskBadge level={alert.risk_level} score={alert.risk_score} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    MITRE ATT&CK
                  </p>
                  <p className="mt-1 font-mono text-sm text-[var(--fg-primary)]">{alert.mitre_id}</p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    Status
                  </p>
                  <div className="mt-1.5">
                    <StatusBadge status={alert.status} />
                  </div>
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                    Detection Method
                  </p>
                  <p className="mt-1 text-sm capitalize text-[var(--fg-secondary)]">
                    {alert.detection_method || "rule"}
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <ConfidenceMeter
                score={data.story_confidence?.score}
                label={data.story_confidence?.label}
              />
              {data.story_confidence?.breakdown && (
                <ul className="mt-3 space-y-1 border-t border-[var(--border-subtle)] pt-3">
                  {data.story_confidence.breakdown.map((b, i) => (
                    <li key={i} className="flex items-center justify-between text-[10px] text-[var(--fg-faint)]">
                      <span>{b.factor}</span>
                      <span className="font-mono">{Math.round((b.score || 0) * 100)}%</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="mt-6">
              <VerdictPanel
                verdict={data.suggested_verdict}
                alertId={selected}
                onApply={reload}
              />
            </div>

            <div className="mt-6">
              <RiskProfilePanel profile={data.risk_profile} />
            </div>
          </div>

          <div className="space-y-6 lg:col-span-2">
            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <div className="mb-5 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-[var(--accent-cyan)]">📊</span>
                  <h3 className="text-base font-semibold text-[var(--fg-primary)]">Incident Timeline</h3>
                </div>
                <span className="text-[11px] text-[var(--fg-faint)]">
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
            </div>

            <StoryTimeline timeline={data.timeline} />

            <ProcessTreePanel tree={data.process_tree} />

            <RelatedAlertsPanel related={data.related_alerts} onSelect={chooseAlert} />

            <InvolvedEntities data={data} />

            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <div className="mb-4 flex items-center gap-2">
                <span className="text-[var(--accent-cyan)]">⏱</span>
                <h3 className="text-base font-semibold text-[var(--fg-primary)]">Attack Timeline</h3>
                <span className="text-[11px] text-[var(--fg-faint)]">
                  {[data.evidence_events, data.related_events]
                    .flat()
                    .filter((e) => e && e.timestamp).length}{" "}
                  timed events
                </span>
              </div>
              <AttackTimeline
                events={[...(data.evidence_events || []), ...(data.related_events || [])]}
              />
            </div>

            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <div className="mb-5 flex items-center gap-2">
                <span className="text-[var(--accent-cyan)]">⛓</span>
                <h3 className="text-base font-semibold text-[var(--fg-primary)]">
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
                          <div className="w-px flex-1 bg-gradient-to-b from-[var(--accent-cyan)]/40 to-[var(--border-default)]/40" />
                        )}
                      </div>
                      <div className="pb-6">
                        <p className="text-sm font-semibold text-[var(--fg-primary)]">{step.step}</p>
                        <div className="mt-2 space-y-1.5">
                          {step.details.map((line, li) => (
                            <p
                              key={li}
                              className="rounded-[var(--radius-2xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3 py-2 font-mono text-[11px] leading-relaxed text-[var(--fg-muted)]"
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
                <p className="text-sm text-[var(--fg-muted)]">No attack chain steps available</p>
              )}
            </div>

            <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
              <div className="mb-4 flex items-center gap-2">
                <span className="text-[var(--accent-cyan)]">📋</span>
                <h3 className="text-base font-semibold text-[var(--fg-primary)]">
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
            </div>

            {data.related_events && data.related_events.length > 0 && (
              <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
                <div className="mb-4">
                  <h3 className="text-base font-semibold text-[var(--fg-primary)]">
                    Related Events ({data.related_events.length})
                  </h3>
                  <p className="mt-0.5 text-sm text-[var(--fg-muted)]">
                    Events recorded ±30 minutes around the alert window
                  </p>
                </div>
                <div className="max-h-80 space-y-2 overflow-y-auto">
                  {data.related_events.map((event, idx) => (
                    <EventChip key={idx} event={event} compact />
                  ))}
                </div>
              </div>
            )}

            {data.network_context && data.network_context.length > 0 && (
              <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
                <h3 className="mb-4 text-base font-semibold text-[var(--fg-primary)]">Network Context</h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {data.network_context.map((ctx, idx) => (
                    <div
                      key={idx}
                      className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-inset)] p-3"
                    >
                      <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-faint)]">
                        Connection
                      </p>
                      <p className="font-mono text-sm text-[var(--accent-cyan)]">
                        {ctx.local_ip}:{ctx.local_port} → {ctx.remote_ip}:{ctx.remote_port}
                      </p>
                      <div className="mt-2 flex items-center justify-between text-[11px] text-[var(--fg-muted)]">
                        <span>
                          Port: <strong className="font-mono">{ctx.remote_port}</strong>
                        </span>
                        <span>{ctx.state}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {data.similar_incidents && data.similar_incidents.length > 0 && (
              <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
                <h3 className="mb-4 text-base font-semibold text-[var(--fg-primary)]">
                  Similar Past Incidents (resolved)
                </h3>
                <div className="space-y-3">
                  {data.similar_incidents.map((sim, idx) => (
                    <div key={idx} className="rounded-[var(--radius-2xl)] border border-[var(--accent-violet)]/25 bg-[var(--accent-violet)]/5 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-semibold text-[var(--fg-primary)]">
                          #{sim.id} {sim.name}
                        </p>
                        <span className="rounded bg-[var(--bg-inset)] px-2 py-0.5 text-[10px] font-mono text-[var(--fg-muted)]">
                          {sim.mitre_id} · {sim.severity}
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-[var(--fg-muted)]">{sim.evidence}</p>
                      <p className="mt-1.5 text-xs text-[var(--accent-cyan)]/80">
                        <span className="font-semibold text-[var(--accent-cyan)]">Resolved via:</span>{" "}
                        {sim.recommendation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {explanation && (
              <div className="rounded-[var(--radius-2xl)] border border-[var(--accent-violet)]/15 bg-gradient-to-br from-[var(--accent-violet)]/[0.04] via-[var(--bg-surface)] to-indigo-500/[0.03] shadow-xl shadow-[var(--accent-violet)]/[0.02] overflow-hidden">
                <div className="relative px-6 pt-5 pb-4 border-b border-[var(--accent-violet)]/10">
                  <div className="absolute inset-0 bg-gradient-to-r from-violet-500/5 via-transparent to-indigo-500/5" />
                  <div className="relative flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-500 via-purple-500 to-indigo-600 shadow-lg shadow-violet-500/30">
                      <svg className="h-5 w-5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 2L2 7l10 5 10-5-10-5z" />
                        <path d="M2 17l10 5 10-5" />
                        <path d="M2 12l10 5 10-5" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h3 className="text-[15px] font-bold text-[var(--fg-primary)] tracking-tight">BARAQ AI Analysis</h3>
                      <p className="text-[11px] text-[var(--fg-muted)] mt-0.5">AI-powered investigation summary</p>
                    </div>
                    <div className="flex items-center gap-1.5 rounded-full bg-violet-500/10 px-3 py-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-violet-500 animate-pulse" />
                      <span className="text-[10px] font-semibold text-violet-600 uppercase tracking-wider">AI Generated</span>
                    </div>
                  </div>
                </div>
                <div className="p-5">
                  <AIAnalysisContent text={explanation} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
