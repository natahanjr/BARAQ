import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { Badge, Tabs, SearchInput, MITREBadge, Button } from "../components/ui/index.js";

const TACTICS = [
  { id: "TA0001", name: "Initial Access", color: "var(--severity-critical)" },
  { id: "TA0002", name: "Execution", color: "var(--severity-high)" },
  { id: "TA0003", name: "Persistence", color: "var(--severity-high)" },
  { id: "TA0004", name: "Privilege Escalation", color: "var(--severity-critical)" },
  { id: "TA0005", name: "Defense Evasion", color: "var(--severity-medium)" },
  { id: "TA0006", name: "Credential Access", color: "var(--severity-critical)" },
  { id: "TA0007", name: "Discovery", color: "var(--severity-medium)" },
  { id: "TA0008", name: "Lateral Movement", color: "var(--severity-high)" },
  { id: "TA0009", name: "Collection", color: "var(--severity-medium)" },
  { id: "TA0010", name: "Exfiltration", color: "var(--severity-critical)" },
  { id: "TA0011", name: "Command and Control", color: "var(--severity-critical)" },
  { id: "TA0040", name: "Impact", color: "var(--severity-critical)" },
];

const SAMPLE_TECHNIQUES = [
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", detected: 14, falsePositives: 2, confidence: 94 },
  { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", detected: 8, falsePositives: 1, confidence: 96 },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence", detected: 6, falsePositives: 0, confidence: 98 },
  { id: "T1046", name: "Network Service Scanning", tactic: "Discovery", detected: 12, falsePositives: 3, confidence: 88 },
  { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control", detected: 22, falsePositives: 4, confidence: 85 },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", detected: 5, falsePositives: 1, confidence: 92 },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", detected: 9, falsePositives: 2, confidence: 90 },
  { id: "T1566", name: "Phishing", tactic: "Initial Access", detected: 3, falsePositives: 0, confidence: 100 },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", detected: 2, falsePositives: 0, confidence: 100 },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", detected: 1, falsePositives: 0, confidence: 100 },
  { id: "T1078", name: "Valid Accounts", tactic: "Persistence", detected: 7, falsePositives: 1, confidence: 93 },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", detected: 4, falsePositives: 1, confidence: 88 },
];

function MITREAttack() {
  const [techniques, setTechniques] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [view, setView] = useState("matrix");

  useEffect(() => {
    setTechniques(SAMPLE_TECHNIQUES);
    setLoading(false);
  }, []);

  const filtered = useMemo(() => {
    let list = techniques;
    if (selectedTactic) list = list.filter((t) => t.tactic === selectedTactic);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
    }
    return list;
  }, [techniques, selectedTactic, search]);

  const coverage = useMemo(() => {
    const total = TACTICS.length;
    const covered = new Set(techniques.map((t) => TACTICS.find((ta) => ta.name === t.tactic)?.id)).size;
    return Math.round((covered / total) * 100);
  }, [techniques]);

  if (loading) return <Loading label="Loading MITRE ATT&CK data" />;
  if (error) return <ErrorBanner message={error} />;

  const totalDetected = techniques.reduce((s, t) => s + t.detected, 0);
  const avgConfidence = Math.round(techniques.reduce((s, t) => s + t.confidence, 0) / techniques.length);

  const statCards = [
    { label: "Coverage", value: `${coverage}%`, color: "var(--accent-cyan)", icon: "\uD83D\uDCCA" },
    { label: "Techniques Detected", value: techniques.length, color: "var(--accent-violet)", icon: "\uD83C\uDFAF" },
    { label: "Total Detections", value: totalDetected.toLocaleString(), color: "var(--severity-high)", icon: "\u26A0\uFE0F" },
    { label: "Avg Confidence", value: `${avgConfidence}%`, color: "var(--status-healthy)", icon: "\u2705" },
  ];

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* Header */}
      <header>
        <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Threat Framework</p>
        <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">MITRE ATT&CK</h1>
        <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Interactive attack technique matrix and coverage analysis</p>
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
          {TACTICS.map((t) => (
            <button
              key={t.id}
              onClick={() => setSelectedTactic(selectedTactic === t.name ? null : t.name)}
              className={`rounded-full px-3 py-1.5 text-[11px] font-semibold transition-all ${selectedTactic === t.name ? "bg-[var(--accent-cyan)] text-white shadow-[0_0_12px_-3px_var(--accent-cyan)]" : "border border-[var(--border-default)] text-[var(--fg-muted)] hover:border-[var(--accent-cyan)]/40"}`}
            >
              {t.name}
            </button>
          ))}
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
            <div className="grid grid-cols-4 gap-3 sm:grid-cols-6 lg:grid-cols-12 min-w-[640px]">
              {TACTICS.map((tactic) => {
                const tacticTechs = techniques.filter((t) => t.tactic === tactic.name);
                const has = tacticTechs.length > 0;
                return (
                  <div key={tactic.id} className="group/tac space-y-1.5">
                    <div className="text-center">
                      <p className="text-[8px] font-bold uppercase tracking-wider leading-tight" style={{ color: has ? tactic.color : "var(--fg-faint)" }}>{tactic.name}</p>
                    </div>
                    <div
                      className={`rounded-[var(--radius-lg)] p-2.5 min-h-[72px] transition-all duration-200 cursor-pointer ${has ? "border border-white/[0.06] hover:shadow-lg" : "border border-[var(--border-subtle)] bg-[var(--bg-inset)]"}`}
                      style={has ? { background: `${tactic.color}08` } : {}}
                    >
                      {has ? (
                        <div className="space-y-1">
                          <p className="text-center text-[18px] font-bold" style={{ color: tactic.color }}>{tacticTechs.length}</p>
                          {tacticTechs.slice(0, 2).map((t) => (
                            <div
                              key={t.id}
                              onClick={() => setSelectedTechnique(selectedTechnique?.id === t.id ? null : t)}
                              className="rounded-md px-1 py-0.5 text-center text-[7px] font-mono text-[var(--fg-secondary)] hover:bg-white/[0.06] cursor-pointer truncate transition-colors"
                            >
                              {t.id}
                            </div>
                          ))}
                          {tacticTechs.length > 2 && <p className="text-center text-[7px] text-[var(--fg-faint)]">+{tacticTechs.length - 2}</p>}
                        </div>
                      ) : (
                        <div className="flex h-full items-center justify-center"><span className="text-[11px] text-[var(--fg-faint)]">{"\u2014"}</span></div>
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
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Detected</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">False Pos.</th>
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filtered.map((tech) => (
                  <tr
                    key={tech.id}
                    onClick={() => setSelectedTechnique(selectedTechnique?.id === tech.id ? null : tech)}
                    className="group cursor-pointer hover:bg-white/[0.02] transition-colors"
                  >
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2">
                        <MITREBadge id={tech.id} name={tech.name} compact />
                      </div>
                    </td>
                    <td className="px-5 py-3.5 text-[12px] text-[var(--fg-secondary)]">{tech.tactic}</td>
                    <td className="px-5 py-3.5 text-[12px] font-semibold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>{tech.detected}</td>
                    <td className="px-5 py-3.5 text-[12px] text-[var(--fg-muted)]">{tech.falsePositives}</td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div className="h-1.5 w-16 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                          <div className="h-full rounded-full" style={{ width: `${tech.confidence}%`, background: tech.confidence >= 90 ? "var(--status-healthy)" : tech.confidence >= 70 ? "var(--severity-medium)" : "var(--severity-high)" }} />
                        </div>
                        <span className="text-[11px] font-semibold tabular-nums" style={{ color: tech.confidence >= 90 ? "var(--status-healthy)" : "var(--fg-secondary)", fontFeatureSettings: '"tnum"' }}>{tech.confidence}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No techniques found</div>}
          </div>
        </div>
      )}

      {/* ── Technique Detail Panel ───────────────────────── */}
      {selectedTechnique && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--accent-cyan-muted)]">
                <span className="text-[16px]">{"\uD83C\uDFAF"}</span>
              </div>
              <div>
                <h2 className="text-[16px] font-bold text-[var(--fg-primary)]">{selectedTechnique.id} {"\u00B7"} {selectedTechnique.name}</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">{selectedTechnique.tactic}</p>
              </div>
            </div>
            <button onClick={() => setSelectedTechnique(null)} className="rounded-lg p-1.5 text-[var(--fg-muted)] hover:bg-[var(--bg-surface-hover)] transition-colors">{"\u2715"}</button>
          </div>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {[
              { label: "Detections", value: selectedTechnique.detected, color: "var(--accent-cyan)" },
              { label: "False Positives", value: selectedTechnique.falsePositives, color: selectedTechnique.falsePositives > 0 ? "var(--severity-medium)" : "var(--status-healthy)" },
              { label: "Confidence", value: `${selectedTechnique.confidence}%`, color: selectedTechnique.confidence >= 90 ? "var(--status-healthy)" : "var(--severity-medium)" },
            ].map((s) => (
              <div key={s.label} className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-1 text-[22px] font-bold tabular-nums" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>{s.value}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(MITREAttack);
