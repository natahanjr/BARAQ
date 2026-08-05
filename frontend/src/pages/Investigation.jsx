import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import TimelineGraph from "../components/TimelineGraph.jsx";
import { InvestigationIcon, ActivityIcon, AlertIcon } from "../components/icons.jsx";

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
    setExplanation("");
    api
      .investigate(selected)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [selected]);

  const chooseAlert = (id) => {
    setSelected(id);
    setParams(id ? { alert: id } : {});
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
