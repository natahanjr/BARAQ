import { memo, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

const inputCls = "w-full rounded-[var(--radius-md)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-4 py-2.5 text-[13px] text-[var(--fg-primary)] outline-none focus:border-[var(--accent-cyan)]/40";

function AttackPath() {
  const [entryTactic, setEntryTactic] = useState("");
  const [compromised, setCompromised] = useState("");
  const [prediction, setPrediction] = useState(null);
  const [blastRadius, setBlastRadius] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [blastEntity, setBlastEntity] = useState("");
  const [blastLoading, setBlastLoading] = useState(false);

  const predict = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setPrediction(null);
    try {
      const data = await api.post("/api/attack-path/predict", {
        entry_tactic: entryTactic.trim(),
        compromised_tactics: compromised.split(",").map((s) => s.trim()).filter(Boolean),
      });
      setPrediction(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const calcBlast = async (e) => {
    e.preventDefault();
    if (!blastEntity.trim()) return;
    setBlastLoading(true);
    setError("");
    setBlastRadius(null);
    try {
      const data = await api.post("/api/attack-path/blast-radius", {
        entity: blastEntity.trim(),
      });
      setBlastRadius(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setBlastLoading(false);
    }
  };

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Attack Path Prediction"
        subtitle="Predict adversary movement and assess blast radius"
        label="Threat Intelligence"
      />

      {error && <ErrorBanner message={error} />}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Predict Next Steps</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={predict} className="space-y-3">
              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Entry Tactic</label>
                <select value={entryTactic} onChange={(e) => setEntryTactic(e.target.value)} className={inputCls} required>
                  <option value="">Select tactic...</option>
                  <option value="initial-access">Initial Access</option>
                  <option value="execution">Execution</option>
                  <option value="persistence">Persistence</option>
                  <option value="privilege-escalation">Privilege Escalation</option>
                  <option value="defense-evasion">Defense Evasion</option>
                  <option value="credential-access">Credential Access</option>
                  <option value="discovery">Discovery</option>
                  <option value="lateral-movement">Lateral Movement</option>
                  <option value="collection">Collection</option>
                  <option value="exfiltration">Exfiltration</option>
                  <option value="impact">Impact</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Compromised Tactics (comma-separated)</label>
                <input
                  placeholder="e.g. initial-access, execution"
                  value={compromised}
                  onChange={(e) => setCompromised(e.target.value)}
                  className={inputCls}
                />
              </div>
              <Button type="submit" size="sm" disabled={loading || !entryTactic} aria-label="Predict attack path">
                {loading ? "Predicting..." : "Predict Attack Path"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Blast Radius Calculator</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={calcBlast} className="space-y-3">
              <div>
                <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Entity (host, user, or IP)</label>
                <input
                  placeholder="e.g. srv-web-01, admin@corp.local"
                  value={blastEntity}
                  onChange={(e) => setBlastEntity(e.target.value)}
                  className={inputCls}
                  required
                />
              </div>
              <Button type="submit" size="sm" disabled={blastLoading || !blastEntity.trim()}>
                {blastLoading ? "Calculating..." : "Calculate Blast Radius"}
              </Button>
            </form>

            {blastRadius && (
              <div className="mt-4 space-y-3">
                <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Risk Score</span>
                    <span className="text-[18px] font-bold" style={{ color: (blastRadius.risk_score || 0) > 0.7 ? "var(--severity-critical)" : (blastRadius.risk_score || 0) > 0.4 ? "var(--severity-high)" : "var(--status-healthy)" }}>
                      {blastRadius.risk_score != null ? (blastRadius.risk_score * 100).toFixed(0) : "\u2014"}
                    </span>
                  </div>
                </div>
                {blastRadius.connections != null && (
                  <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Connected Entities</p>
                    <p className="mt-1 text-[16px] font-bold text-[var(--fg-primary)]">{blastRadius.connections}</p>
                  </div>
                )}
                {blastRadius.entities?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {blastRadius.entities.map((ent) => (
                      <span key={ent} className="rounded-md bg-[var(--bg-inset)] px-2 py-1 font-mono text-[10px] font-medium text-[var(--fg-secondary)] ring-1 ring-[var(--border-subtle)]">
                        {ent}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {prediction && (
        <Card>
          <CardHeader>
            <CardTitle>Predicted Next Steps</CardTitle>
          </CardHeader>
          <CardContent>
            {prediction.path && prediction.path.length > 0 && (
              <div className="mb-4 flex items-center gap-2 text-[12px] text-[var(--fg-muted)]">
                <span className="font-semibold">Attack Flow:</span>
                {prediction.path.map((step, i) => (
                  <span key={i} className="flex items-center gap-2">
                    {i > 0 && <span className="text-[var(--accent-cyan)]">&rarr;</span>}
                    <Badge severity="info" size="sm">{step}</Badge>
                  </span>
                ))}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead>
                  <tr className="border-b border-[var(--border-subtle)]">
                    <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Technique</th>
                    <th className="pb-2 pr-4 font-semibold text-[var(--fg-muted)]">Tactic</th>
                    <th className="pb-2 font-semibold text-[var(--fg-muted)]">Probability</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {(prediction.next_steps || prediction.techniques || []).map((step, i) => (
                    <tr key={i}>
                      <td className="py-3 pr-4 text-[12px] text-[var(--fg-primary)]">{step.technique || step.name}</td>
                      <td className="py-3 pr-4"><Badge severity="info" size="sm">{step.tactic}</Badge></td>
                      <td className="py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--bg-inset)]">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${(step.probability || 0) * 100}%`,
                                background: (step.probability || 0) > 0.7 ? "var(--severity-critical)" : (step.probability || 0) > 0.4 ? "var(--severity-high)" : "var(--accent-cyan)",
                              }}
                            />
                          </div>
                          <span className="text-[11px] font-medium text-[var(--fg-secondary)]">
                            {((step.probability || 0) * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default memo(AttackPath);
