import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { Tabs, MITREBadge } from "../components/ui/index.js";

const TACTICS = [
  { id: "TA0001", name: "Initial Access", color: "#ef4444", short: "IA" },
  { id: "TA0002", name: "Execution", color: "#f97316", short: "EX" },
  { id: "TA0003", name: "Persistence", color: "#eab308", short: "PE" },
  { id: "TA0004", name: "Privilege Escalation", color: "#f43f5e", short: "PrE" },
  { id: "TA0005", name: "Defense Evasion", color: "#a855f7", short: "DE" },
  { id: "TA0006", name: "Credential Access", color: "#ec4899", short: "CA" },
  { id: "TA0007", name: "Discovery", color: "#6366f1", short: "DI" },
  { id: "TA0008", name: "Lateral Movement", color: "#8b5cf6", short: "LM" },
  { id: "TA0009", name: "Collection", color: "#14b8a6", short: "CO" },
  { id: "TA0010", name: "Exfiltration", color: "#06b6d4", short: "EX" },
  { id: "TA0011", name: "Command and Control", color: "#3b82f6", short: "C2" },
  { id: "TA0040", name: "Impact", color: "#dc2626", short: "IM" },
];

const TACTIC_MAP = Object.fromEntries(TACTICS.map((t) => [t.name, t]));

function MITREAttack() {
  const [alerts, setAlerts] = useState([]);
  const [mlStatus, setMlStatus] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [view, setView] = useState("matrix");

  const load = useCallback(async () => {
    try {
      const [alertsData, ml] = await Promise.all([
        api.alerts({ page_size: 500 }).catch(() => ({ items: [] })),
        api.mlStatus().catch(() => ({})),
      ]);
      setAlerts(alertsData.items || []);
      setMlStatus(ml || {});
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 30000);
    return () => clearInterval(iv);
  }, [load]);

  const techniques = useMemo(() => {
    const map = {};
    for (const a of alerts) {
      const tid = a.mitre_id || a.mitre_technique;
      const tname = a.mitre_name || a.name || "Unknown";
      const tactic = a.mitre_tactic || "Unknown";
      if (!tid) continue;
      if (!map[tid]) {
        map[tid] = {
          id: tid,
          name: tname,
          tactic,
          detected: 0,
          falsePositives: 0,
          confidence: 90,
          alerts: [],
          severity: a.severity || "medium",
        };
      }
      map[tid].detected++;
      map[tid].alerts.push(a);
      if (a.status === "false_positive" || a.false_positive) map[tid].falsePositives++;
      if (a.severity === "critical") map[tid].confidence = Math.min(map[tid].confidence + 1, 100);
    }
    return Object.values(map).sort((a, b) => b.detected - a.detected);
  }, [alerts]);

  const filtered = useMemo(() => {
    let list = techniques;
    if (selectedTactic) list = list.filter((t) => t.tactic === selectedTactic);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (t) =>
          t.id.toLowerCase().includes(q) ||
          t.name.toLowerCase().includes(q) ||
          t.tactic.toLowerCase().includes(q),
      );
    }
    return list;
  }, [techniques, selectedTactic, search]);

  const coverage = useMemo(() => {
    const tacticsWithDetections = new Set(techniques.map((t) => TACTIC_MAP[t.tactic]?.id).filter(Boolean));
    return Math.round((tacticsWithDetections.size / TACTICS.length) * 100);
  }, [techniques]);

  if (loading) return <Loading label="Loading MITRE ATT&CK data" />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  const totalDetected = techniques.reduce((s, t) => s + t.detected, 0);
  const totalFP = techniques.reduce((s, t) => s + t.falsePositives, 0);
  const avgConfidence = techniques.length
    ? Math.round(techniques.reduce((s, t) => s + t.confidence, 0) / techniques.length)
    : 0;

  const statCards = [
    { label: "Coverage", value: `${coverage}%`, color: "var(--accent-cyan)", icon: "\uD83D\uDCCA" },
    { label: "Techniques Detected", value: techniques.length, color: "var(--accent-violet)", icon: "\uD83C\uDFAF" },
    { label: "Total Detections", value: totalDetected.toLocaleString(), color: "var(--severity-high)", icon: "\u26A0\uFE0F" },
    { label: "Avg Confidence", value: `${avgConfidence}%`, color: "var(--status-healthy)", icon: "\u2705" },
  ];

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* Header */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Threat Framework</p>
          <h1 className="mt-1 text-page-title text-[var(--fg-primary)]">MITRE ATT&CK</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">
            Real detections mapped to ATT&CK techniques from {alerts.length} alerts
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/alerts"
            className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-surface)] px-4 py-2 text-[12px] font-semibold text-[var(--fg-secondary)] transition-all hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]"
          >
            View All Alerts
          </Link>
        </div>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((s) => (
          <div key={s.label} className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5 transition-all duration-300 hover:border-[var(--border-strong)] hover:shadow-lg">
            <div className="absolute -right-6 -top-6 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-40" style={{ background: s.color }} />
            <div className="relative flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-2 text-[28px] font-bold tabular-nums leading-none" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>
                  {s.value}
                </p>
              </div>
              <span className="text-[18px] opacity-50">{s.icon}</span>
            </div>
          </div>
        ))}
      </div>

      {/* ML Model Status Bar */}
      <div className="flex flex-wrap items-center gap-4 rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-40 ${mlStatus.model_state === "HEALTHY" ? "bg-[var(--status-healthy)] animate-ping" : "bg-[var(--severity-critical)]"}`} />
            <span className={`relative inline-flex h-2 w-2 rounded-full ${mlStatus.model_state === "HEALTHY" ? "bg-[var(--status-healthy)]" : "bg-[var(--severity-critical)]"}`} />
          </span>
          <span className="text-[12px] font-semibold text-[var(--fg-secondary)]">ML Detection Engine</span>
        </div>
        <span className="text-[11px] text-[var(--fg-muted)]">v{mlStatus.version || "—"}</span>
        <span className="text-[11px] text-[var(--fg-muted)]">{mlStatus.samples?.toLocaleString() || "—"} samples</span>
        <span className="text-[11px] text-[var(--fg-muted)]">{mlStatus.scored_events?.toLocaleString() || "—"} scored</span>
        {mlStatus.drift && (
          <span className="rounded-full bg-[var(--severity-high)]/10 px-2 py-0.5 text-[10px] font-semibold text-[var(--severity-high)]">DRIFT DETECTED</span>
        )}
      </div>

      {/* Search + Filter */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative sm:w-80">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[14px] text-[var(--fg-faint)]">{"\uD83D\uDD0D"}</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search techniques..."
            className="w-full rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] py-2.5 pl-9 pr-3 text-[13px] text-[var(--fg-primary)] placeholder:text-[var(--fg-faint)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => setSelectedTactic(null)}
            className={`rounded-full px-3 py-1.5 text-[11px] font-semibold transition-all ${!selectedTactic ? "bg-[var(--accent-cyan)] text-white shadow-[0_0_12px_-3px_var(--accent-cyan)]" : "border border-[var(--border-default)] text-[var(--fg-muted)] hover:border-[var(--accent-cyan)]/40"}`}
          >
            All
          </button>
          {TACTICS.map((t) => {
            const count = techniques.filter((tech) => tech.tactic === t.name).length;
            return (
              <button
                key={t.id}
                onClick={() => setSelectedTactic(selectedTactic === t.name ? null : t.name)}
                className={`rounded-full px-3 py-1.5 text-[11px] font-semibold transition-all ${selectedTactic === t.name ? "text-white shadow-[0_0_12px_-3px_var(--accent-cyan)]" : "border border-[var(--border-default)] text-[var(--fg-muted)] hover:border-[var(--accent-cyan)]/40"}`}
                style={selectedTactic === t.name ? { background: t.color } : {}}
              >
                {t.name}
                {count > 0 && <span className="ml-1 opacity-60">{count}</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* View Toggle */}
      <Tabs
        tabs={[{ id: "matrix", label: "Matrix" }, { id: "table", label: "Table" }]}
        active={view}
        onChange={setView}
      />

      {/* ── Matrix View ──────────────────────────────────── */}
      {view === "matrix" && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5">
          <div className="overflow-x-auto">
            <div className="grid grid-cols-3 gap-3 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-12 min-w-[640px]">
              {TACTICS.map((tactic) => {
                const tacticTechs = filtered.filter((t) => t.tactic === tactic.name);
                const allTacticTechs = techniques.filter((t) => t.tactic === tactic.name);
                const has = allTacticTechs.length > 0;
                const isSelected = selectedTactic === tactic.name;
                return (
                  <div key={tactic.id} className="space-y-1.5">
                    <div
                      className="text-center cursor-pointer transition-opacity hover:opacity-80"
                      onClick={() => setSelectedTactic(isSelected ? null : tactic.name)}
                    >
                      <p className="text-[8px] font-bold uppercase tracking-wider leading-tight" style={{ color: tactic.color }}>
                        {tactic.name}
                      </p>
                      <p className="text-[7px] text-[var(--fg-faint)] mt-0.5">{tactic.id}</p>
                    </div>
                    <div
                      className={`rounded-[var(--radius-lg)] p-2.5 min-h-[80px] transition-all duration-200 cursor-pointer ${
                        isSelected ? "ring-2 shadow-lg" : has ? "border border-white/[0.06] hover:shadow-lg" : "border border-[var(--border-subtle)] bg-[var(--bg-inset)]"
                      }`}
                      style={has ? { background: `${tactic.color}0A` } : {}}
                      onClick={() => setSelectedTactic(isSelected ? null : tactic.name)}
                    >
                      {has ? (
                        <div className="space-y-1">
                          <p className="text-center text-[18px] font-bold" style={{ color: tactic.color }}>{allTacticTechs.length}</p>
                          {allTacticTechs.slice(0, 3).map((t) => (
                            <div
                              key={t.id}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedTechnique(selectedTechnique?.id === t.id ? null : t);
                              }}
                              className={`rounded-md px-1.5 py-0.5 text-center text-[8px] font-mono cursor-pointer truncate transition-all ${
                                selectedTechnique?.id === t.id ? "bg-white/[0.12] text-white" : "text-[var(--fg-secondary)] hover:bg-white/[0.06]"
                              }`}
                            >
                              <span className="font-bold">{t.id}</span>
                              <span className="ml-0.5 opacity-60">{t.detected}</span>
                            </div>
                          ))}
                          {allTacticTechs.length > 3 && (
                            <p className="text-center text-[7px] text-[var(--fg-faint)]">+{allTacticTechs.length - 3} more</p>
                          )}
                        </div>
                      ) : (
                        <div className="flex h-full items-center justify-center">
                          <span className="text-[11px] text-[var(--fg-faint)]">{"\u2014"}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Table View ───────────────────────────────────── */}
      {view === "table" && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[var(--border-subtle)]">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Technique</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Tactic</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Detections</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">False Pos.</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Confidence</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filtered.map((tech) => {
                  const tacticInfo = TACTIC_MAP[tech.tactic];
                  return (
                    <tr
                      key={tech.id}
                      className={`group transition-colors ${selectedTechnique?.id === tech.id ? "bg-white/[0.04]" : "hover:bg-white/[0.02]"}`}
                    >
                      <td className="px-5 py-3.5">
                        <button
                          onClick={() => setSelectedTechnique(selectedTechnique?.id === tech.id ? null : tech)}
                          className="flex items-center gap-2 text-left hover:opacity-80 transition-opacity"
                        >
                          <span className="inline-flex h-5 w-5 items-center justify-center rounded text-[9px] font-bold text-white" style={{ background: tacticInfo?.color || "#666" }}>
                            {tacticInfo?.short || "?"}
                          </span>
                          <div>
                            <p className="text-[12px] font-semibold text-[var(--fg-primary)]">{tech.id}</p>
                            <p className="text-[10px] text-[var(--fg-muted)] max-w-[200px] truncate">{tech.name}</p>
                          </div>
                        </button>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-semibold" style={{ background: `${tacticInfo?.color || "#666"}15`, color: tacticInfo?.color || "#666" }}>
                          {tech.tactic}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-[12px] font-semibold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>
                        {tech.detected}
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`text-[12px] font-semibold tabular-nums ${tech.falsePositives > 0 ? "text-[var(--severity-medium)]" : "text-[var(--fg-muted)]"}`} style={{ fontFeatureSettings: '"tnum"' }}>
                          {tech.falsePositives}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2.5">
                          <div className="h-1.5 w-16 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                            <div className="h-full rounded-full transition-all" style={{ width: `${tech.confidence}%`, background: tech.confidence >= 90 ? "var(--status-healthy)" : tech.confidence >= 70 ? "var(--severity-medium)" : "var(--severity-high)" }} />
                          </div>
                          <span className="text-[11px] font-semibold tabular-nums" style={{ color: tech.confidence >= 90 ? "var(--status-healthy)" : "var(--fg-secondary)", fontFeatureSettings: '"tnum"' }}>
                            {tech.confidence}%
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-1">
                          <Link
                            to={`/alerts?mitre=${tech.id}`}
                            className="rounded-lg border border-[var(--border-default)] px-2.5 py-1 text-[10px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]"
                          >
                            Alerts
                          </Link>
                          <button
                            onClick={() => setSelectedTechnique(selectedTechnique?.id === tech.id ? null : tech)}
                            className="rounded-lg border border-[var(--border-default)] px-2.5 py-1 text-[10px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--accent-violet)]/40 hover:text-[var(--accent-violet)]"
                          >
                            Detail
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No techniques found</div>
            )}
          </div>
        </div>
      )}

      {/* ── Technique Detail Panel ───────────────────────── */}
      {selectedTechnique && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6 space-y-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl text-white font-bold text-[13px]" style={{ background: TACTIC_MAP[selectedTechnique.tactic]?.color || "#666" }}>
                {selectedTechnique.id}
              </div>
              <div>
                <h2 className="text-[16px] font-bold text-[var(--fg-primary)]">{selectedTechnique.name}</h2>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-[12px] text-[var(--fg-muted)]">{selectedTechnique.tactic}</span>
                  <span className="text-[var(--fg-faint)]">·</span>
                  <span className="text-[12px] text-[var(--fg-muted)]">{TACTIC_MAP[selectedTechnique.tactic]?.id}</span>
                </div>
              </div>
            </div>
            <button onClick={() => setSelectedTechnique(null)} className="rounded-lg p-1.5 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] transition-colors">{"\u2715"}</button>
          </div>

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {[
              { label: "Detections", value: selectedTechnique.detected, color: "var(--accent-cyan)" },
              { label: "False Positives", value: selectedTechnique.falsePositives, color: selectedTechnique.falsePositives > 0 ? "var(--severity-medium)" : "var(--status-healthy)" },
              { label: "Confidence", value: `${selectedTechnique.confidence}%`, color: selectedTechnique.confidence >= 90 ? "var(--status-healthy)" : "var(--severity-medium)" },
              { label: "Alerts", value: selectedTechnique.alerts?.length || 0, color: "var(--accent-violet)" },
            ].map((s) => (
              <div key={s.label} className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-1 text-[22px] font-bold tabular-nums" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Recent Alerts for this Technique */}
          {selectedTechnique.alerts?.length > 0 && (
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-3">Recent Alerts</p>
              <div className="space-y-2 max-h-60 overflow-y-auto">
                {selectedTechnique.alerts.slice(0, 10).map((a) => (
                  <Link
                    key={a.id}
                    to={`/alerts/${a.id}`}
                    className="flex items-center justify-between rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 transition-all hover:border-[var(--accent-cyan)]/30 hover:bg-white/[0.02]"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className={`inline-flex h-2 w-2 shrink-0 rounded-full ${a.severity === "critical" ? "bg-[var(--severity-critical)]" : a.severity === "high" ? "bg-[var(--severity-high)]" : "bg-[var(--severity-medium)]"}`} />
                      <div className="min-w-0">
                        <p className="text-[12px] font-semibold text-[var(--fg-primary)] truncate">{a.name}</p>
                        <p className="text-[10px] text-[var(--fg-muted)]">{a.source} · {a.created_at ? new Date(a.created_at).toLocaleString() : ""}</p>
                      </div>
                    </div>
                    <span className="shrink-0 text-[10px] text-[var(--fg-muted)]">{a.severity}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* MITRE Reference */}
          <div className="flex items-center gap-3 pt-2 border-t border-[var(--border-subtle)]">
            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace(".", "/")}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]"
            >
              View on MITRE ATT&CK
              <svg width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 11L11 1M11 1H3M11 1v8"/></svg>
            </a>
            <Link
              to={`/alerts?mitre=${selectedTechnique.id}`}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent-cyan)]/10 px-3 py-1.5 text-[11px] font-semibold text-[var(--accent-cyan)] transition-all hover:bg-[var(--accent-cyan)]/20"
            >
              View All Alerts for {selectedTechnique.id}
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(MITREAttack);
