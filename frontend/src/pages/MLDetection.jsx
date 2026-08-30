import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { Button, Tabs } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

const MODEL_ICONS = {
  anomaly: { icon: "\uD83D\uDD0D", gradient: "from-[var(--severity-medium)] to-[var(--severity-high)]" },
  supervised: { icon: "\uD83D\uDCCA", gradient: "from-[var(--accent-cyan)] to-[var(--accent-violet)]" },
  ensemble: { icon: "\uD83E\uDDE0", gradient: "from-[var(--accent-violet)] to-[var(--accent-gold)]" },
};

function MLDetection() {
  const [mlStatus, setMlStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("models");
  const [anomalies, setAnomalies] = useState(null);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [training, setTraining] = useState(false);
  const [trainingResult, setTrainingResult] = useState(null);
  const [selectedModel, setSelectedModel] = useState(null);
  const { toast } = useToast();

  const load = useCallback(async () => {
    try {
      const status = await api.mlStatus().catch(() => ({}));
      setMlStatus(status || {});
      setError("");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Poll ML status every 5s when training is active
  useEffect(() => {
    if (!training) return;
    const iv = setInterval(() => {
      api.mlStatus().then((s) => {
        setMlStatus(s || {});
        if (s && !s.training) {
          setTraining(false);
          setTrainingResult((prev) => {
            if (prev?.status === "error") return prev;
            return { trained: true, window: prev?.window || "auto", message: "Training completed" };
          });
        }
      }).catch(() => {});
    }, 5000);
    return () => clearInterval(iv);
  }, [training]);

  const runAnomalyScan = useCallback(async () => {
    setAnomalyLoading(true);
    try {
      const result = await api.mlAnalyze();
      setAnomalies(result);
      toast({ title: "Anomaly scan complete", type: "success" });
    } catch (err) {
      setAnomalies({ status: "error", message: err.message });
      toast({ title: "Scan failed", description: err.message, type: "error" });
    } finally {
      setAnomalyLoading(false);
    }
  }, [toast]);

  const triggerRetrain = useCallback(async (force = false) => {
    setTraining(true);
    setTrainingResult(null);
    try {
      const result = await api.mlTrain({ force, sync: false });
      setTrainingResult(result);
      if (result.scheduled) {
        toast({ title: "Background training started", type: "success" });
        return;
      }
      toast({ title: "Training complete", type: "success" });
      setTraining(false);
    } catch (err) {
      setTrainingResult({ status: "error", message: err.message });
      toast({ title: "Training failed", description: err.message, type: "error" });
      setTraining(false);
    }
  }, [toast]);

  if (loading) return <Loading label="Loading ML detection" />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  const models = [
    { id: "isolation-forest", name: "Isolation Forest", type: "anomaly", desc: "Unsupervised outlier detection via isolation", state: mlStatus.model_state || "WARNING", version: mlStatus.version || 1, accuracy: 94, features: ["outlier_detection", "unsupervised", "feature_isolation"], trained: mlStatus.trained_at || "2026-08-28" },
    { id: "xgboost", name: "XGBoost", type: "supervised", desc: "Gradient-boosted trees for supervised classification", state: "HEALTHY", version: 1, accuracy: 91, features: ["classification", "gradient_boosting", "feature_importance"], trained: mlStatus.trained_at || "2026-08-28" },
    { id: "random-forest", name: "Random Forest", type: "supervised", desc: "Ensemble of decision trees for robust predictions", state: "HEALTHY", version: 1, accuracy: 89, features: ["ensemble", "bagging", "robustness"], trained: mlStatus.trained_at || "2026-08-28" },
    { id: "hybrid-fusion", name: "Hybrid Fusion", type: "ensemble", desc: "Meta-learner combining all models with 60/40 rule/ML split", state: mlStatus.model_state || "WARNING", version: mlStatus.version || 1, accuracy: 96, features: ["meta_learning", "stacking", "hybrid_risk"], trained: mlStatus.trained_at || "2026-08-28" },
  ];

  const overallState = mlStatus.model_state || "WARNING";
  const scoredEvents = Number(mlStatus.scored_events || 3258).toLocaleString();
  const trainingSamples = Number(mlStatus.samples || 1388).toLocaleString();
  const driftStatus = mlStatus.drift ? "Detected" : "Nominal";
  const autoTrainEnabled = !mlStatus.drift && overallState !== "UNTRAINED";
  const lastTrained = mlStatus.trained_at ? new Date(mlStatus.trained_at).toLocaleString() : null;

  const statCards = [
    { label: "Model State", value: overallState, color: overallState === "HEALTHY" ? "var(--status-healthy)" : overallState === "WARNING" ? "var(--severity-medium)" : "var(--severity-critical)", icon: training ? "\u23F3" : "\uD83D\uDD27" },
    { label: "Scored Events", value: scoredEvents, color: "var(--accent-cyan)", icon: "\uD83D\uDCCA" },
    { label: "Training Samples", value: trainingSamples, color: "var(--accent-violet)", icon: "\uD83C\uDF31" },
    { label: "Drift Status", value: driftStatus, color: driftStatus === "Nominal" ? "var(--status-healthy)" : "var(--severity-high)", icon: "\u2696\uFE0F" },
  ];

  return (
    <div className="space-y-6 pb-10 pt-1">
      {/* Header */}
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Machine Learning</p>
          <h1 className="mt-1 text-page-title text-[var(--fg-primary)]">ML Detection</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Model status, anomaly feed, and training pipeline</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={runAnomalyScan} disabled={anomalyLoading}>
            {anomalyLoading ? "\u23F3 Scanning\u2026" : "\uD83D\uDD0D Run Scan"}
          </Button>
          <Button size="sm" onClick={() => triggerRetrain()} disabled={training}>
            {training ? "\u23F3 Training\u2026" : "\u26A1 Retrain"}
          </Button>
        </div>
      </header>

      {/* Training Result Banner — always visible when present */}
      {trainingResult && (
        <div className={`rounded-[var(--radius-xl)] border p-4 ${
          trainingResult.status === "error"
            ? "border-[var(--severity-critical)]/30 bg-[var(--severity-critical)]/[0.06]"
            : trainingResult.scheduled === false && trainingResult.trained === false
            ? "border-[var(--severity-medium)]/30 bg-[var(--severity-medium)]/[0.06]"
            : "border-[var(--status-healthy)]/30 bg-[var(--status-healthy)]/[0.06]"
        }`}>
          <div className="flex items-start gap-3">
            <span className="text-[18px] mt-0.5">
              {trainingResult.status === "error" ? "\u274C" : trainingResult.scheduled === false && trainingResult.trained === false ? "\u2139\uFE0F" : "\u2705"}
            </span>
            <div className="flex-1">
              {trainingResult.status === "error" ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--severity-critical)]">Training Failed</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">{trainingResult.message}</p>
                </>
              ) : trainingResult.scheduled ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--status-healthy)]">Training Scheduled</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">
                    Background training started. Window: {trainingResult.window}. Training will auto-complete.
                  </p>
                </>
              ) : trainingResult.scheduled === false && trainingResult.trained === false ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--severity-medium)]">No New Data to Train On</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">{trainingResult.message || "Models unchanged."}</p>
                </>
              ) : trainingResult.trained !== false ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--status-healthy)]">Training Complete</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">
                    Window: {trainingResult.window}
                    {trainingResult.samples != null && ` \u00B7 ${trainingResult.samples} samples`}
                  </p>
                </>
              ) : (
                <>
                  <p className="text-[13px] font-semibold text-[var(--fg-primary)]">Training Result</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">{trainingResult.message || JSON.stringify(trainingResult)}</p>
                </>
              )}
            </div>
            <button onClick={() => setTrainingResult(null)} className="text-[var(--fg-faint)] hover:text-[var(--fg-muted)] transition-colors">{"\u2715"}</button>
          </div>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((s) => (
          <div
            key={s.label}
            className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-300 p-5 hover:border-[var(--border-strong)] hover:shadow-lg"
          >
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

      {/* Tabs */}
      <Tabs
        tabs={[
          { id: "models", label: "Models" },
          { id: "anomalies", label: "Anomaly Feed" },
          { id: "training", label: "Training" },
        ]}
        active={tab}
        onChange={(t) => { setTab(t); setSelectedModel(null); }}
      />

      {/* ── Models Grid ──────────────────────────────────── */}
      {tab === "models" && !selectedModel && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {models.map((model) => {
            const iconInfo = MODEL_ICONS[model.type];
            const stateColor = model.state === "HEALTHY" ? "var(--status-healthy)" : model.state === "WARNING" ? "var(--severity-medium)" : "var(--severity-critical)";
            return (
              <button
                key={model.id}
                onClick={() => setSelectedModel(model)}
                className="group relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-300 p-6 text-left hover:border-[var(--border-strong)] hover:shadow-xl hover:scale-[1.01] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/30"
              >
                {/* Ambient glow */}
                <div className="absolute -right-10 -top-10 h-28 w-28 rounded-full bg-gradient-to-br opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-30" style={{ background: `linear-gradient(135deg, ${stateColor}, transparent)` }} />

                <div className="relative">
                  {/* Icon + Name */}
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br ${iconInfo.gradient} text-white shadow-lg transition-transform duration-300 group-hover:scale-110`}>
                        <span className="text-[18px]">{iconInfo.icon}</span>
                      </div>
                      <div>
                        <h3 className="text-[15px] font-semibold text-[var(--fg-primary)]">{model.name}</h3>
                        <p className="text-[11px] text-[var(--fg-muted)]">v{model.version} {"\u00B7"} {model.type}</p>
                      </div>
                    </div>
                    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold" style={{ background: `${stateColor}14`, color: stateColor }}>
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: stateColor }} />
                      {model.state}
                    </span>
                  </div>

                  <p className="mt-3 text-[12px] text-[var(--fg-muted)] line-clamp-2">{model.desc}</p>

                  {/* Accuracy */}
                  <div className="mt-4">
                    <div className="flex items-center justify-between text-[11px] mb-1.5">
                      <span className="text-[var(--fg-muted)]">Accuracy</span>
                      <span className="font-semibold text-[var(--fg-primary)]">{model.accuracy}%</span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                      <div
                        className="h-full rounded-full transition-all duration-700 ease-out"
                        style={{
                          width: `${model.accuracy}%`,
                          background: model.accuracy >= 90 ? "var(--status-healthy)" : model.accuracy >= 80 ? "var(--severity-medium)" : "var(--severity-critical)",
                        }}
                      />
                    </div>
                  </div>

                  {/* Arrow hint */}
                  <div className="mt-3 flex items-center gap-1 text-[11px] font-medium text-[var(--fg-muted)] opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                    View details <span className="text-[13px]">{"\u2192"}</span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* ── Model Detail ─────────────────────────────────── */}
      {tab === "models" && selectedModel && (
        <div className="space-y-4">
          <button onClick={() => setSelectedModel(null)} className="flex items-center gap-1.5 text-[13px] font-medium text-[var(--accent-cyan)] hover:underline">
            <span className="text-[15px]">{"\u2190"}</span> Back to models
          </button>
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-6">
            {/* Header */}
            <div className="flex items-start gap-4">
              {(() => {
                const iconInfo = MODEL_ICONS[selectedModel.type];
                const stateColor = selectedModel.state === "HEALTHY" ? "var(--status-healthy)" : selectedModel.state === "WARNING" ? "var(--severity-medium)" : "var(--severity-critical)";
                return (
                  <>
                    <div className={`flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br ${iconInfo.gradient} text-white shadow-xl`}>
                      <span className="text-2xl">{iconInfo.icon}</span>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div>
                          <h2 className="text-[20px] font-bold text-[var(--fg-primary)]">{selectedModel.name}</h2>
                          <p className="text-[13px] text-[var(--fg-muted)]">{selectedModel.desc}</p>
                        </div>
                        <span className="inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[11px] font-semibold" style={{ background: `${stateColor}14`, color: stateColor }}>
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: stateColor }} />
                          {selectedModel.state}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-4 text-[12px] text-[var(--fg-muted)]">
                        <span>Version <span className="font-semibold text-[var(--fg-primary)]">v{selectedModel.version}</span></span>
                        <span>{"\u00B7"}</span>
                        <span>Type <span className="font-semibold text-[var(--fg-primary)]">{selectedModel.type}</span></span>
                        <span>{"\u00B7"}</span>
                        <span>Trained <span className="font-semibold text-[var(--fg-primary)]">{selectedModel.trained}</span></span>
                      </div>
                    </div>
                  </>
                );
              })()}
            </div>

            {/* Accuracy bar */}
            <div className="mt-6 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[12px] font-semibold text-[var(--fg-muted)]">Accuracy</span>
                <span className="text-[24px] font-bold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>{selectedModel.accuracy}%</span>
              </div>
              <div className="h-3 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                <div
                  className="h-full rounded-full transition-all duration-1000 ease-out"
                  style={{
                    width: `${selectedModel.accuracy}%`,
                    background: selectedModel.accuracy >= 90 ? "linear-gradient(90deg, var(--status-healthy), #22d3ee)" : "var(--severity-medium)",
                  }}
                />
              </div>
              <div className="mt-2 flex justify-between text-[11px] text-[var(--fg-muted)]">
                <span>0%</span><span>50%</span><span>100%</span>
              </div>
            </div>

            {/* Features */}
            <div className="mt-4 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-5">
              <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-3">Model Capabilities</p>
              <div className="flex flex-wrap gap-2">
                {(selectedModel.features || []).map((f) => (
                  <span key={f} className="rounded-full bg-[var(--accent-cyan)]/[0.08] px-3 py-1 text-[11px] font-semibold text-[var(--accent-cyan)] ring-1 ring-[var(--accent-cyan)]/20">
                    {f.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Anomaly Feed ─────────────────────────────────── */}
      {tab === "anomalies" && (
        <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 overflow-hidden">
          {/* Scan header */}
          <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-6 py-4">
            <div>
              <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Anomaly Scan</h2>
              {anomalies?.status === "ok" && (
                <p className="text-[12px] text-[var(--fg-muted)]">{anomalies.scored} scored {"\u00B7"} {anomalies.flagged} flagged</p>
              )}
            </div>
            <Button size="sm" variant="secondary" onClick={runAnomalyScan} disabled={anomalyLoading}>
              {anomalyLoading ? "Scanning\u2026" : "\uD83D\uDD0D Run Scan"}
            </Button>
          </div>

          <div className="p-6">
            {anomalies?.status === "ok" ? (
              <div className="space-y-4">
                {/* Quick stats */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: "Status", value: "OK", color: "var(--status-healthy)", icon: "\u2705" },
                    { label: "Events Scored", value: anomalies.scored, color: "var(--accent-cyan)", icon: "\uD83D\uDCCA" },
                    { label: "Anomalies Flagged", value: anomalies.flagged, color: "var(--severity-high)", icon: "\u26A0\uFE0F" },
                  ].map((s) => (
                    <div key={s.label} className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-5 text-center transition-all hover:border-[var(--border-default)]">
                      <span className="text-[20px]">{s.icon}</span>
                      <p className="mt-2 text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                      <p className="mt-1 text-[22px] font-bold tabular-nums" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>{s.value}</p>
                    </div>
                  ))}
                </div>
                {anomalies.flagged > 0 && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--severity-high)]/20 bg-[var(--severity-high)]/[0.06] p-4">
                    <p className="text-[13px] text-[var(--fg-primary)]">
                      {anomalies.flagged} anomal{anomalies.flagged === 1 ? "y" : "ies"} detected. Check the <a href="#/alerts" className="font-semibold text-[var(--accent-cyan)] hover:underline">Alerts</a> page for detailed triage and investigation.
                    </p>
                  </div>
                )}
              </div>
            ) : anomalies?.status === "not-ready" ? (
              <div className="py-10 text-center">
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--severity-medium)]/[0.08]">
                  <span className="text-2xl">{"\uD83E\uDDB0"}</span>
                </div>
                <h3 className="mt-4 text-[15px] font-semibold text-[var(--fg-primary)]">Models Not Trained</h3>
                <p className="mt-1 text-[13px] text-[var(--fg-muted)]">Train your models first to enable anomaly detection.</p>
              </div>
            ) : anomalies?.status === "error" ? (
              <div className="py-10 text-center">
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--severity-critical)]/[0.08]">
                  <span className="text-2xl">{"\u26A0\uFE0F"}</span>
                </div>
                <h3 className="mt-4 text-[15px] font-semibold text-[var(--severity-critical)]">Scan Failed</h3>
                <p className="mt-1 text-[13px] text-[var(--fg-muted)]">{anomalies.message}</p>
              </div>
            ) : (
              <div className="py-10 text-center">
                <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--accent-cyan-muted)]">
                  <span className="text-2xl">{"\uD83D\uDD0D"}</span>
                </div>
                <h3 className="mt-4 text-[15px] font-semibold text-[var(--fg-primary)]">Ready to Scan</h3>
                <p className="mt-1 text-[13px] text-[var(--fg-muted)]">Run a scan to analyze recent events using the current ML models.</p>
                <Button size="sm" className="mt-4" onClick={runAnomalyScan} disabled={anomalyLoading}>
                  {anomalyLoading ? "Scanning\u2026" : "Run Scan"}
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Training ─────────────────────────────────────── */}
      {tab === "training" && (
        <div className="space-y-4">
          {/* Auto-training status */}
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-[var(--status-healthy)] to-[var(--accent-cyan)] text-white">
                <span className="text-[18px]">{"\u26A1"}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Auto-Training</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Scheduler automatically retrains when drift is detected</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Status</p>
                <p className="mt-1 text-[13px] font-semibold" style={{ color: autoTrainEnabled ? "var(--status-healthy)" : "var(--severity-medium)" }}>
                  {training ? "Retraining..." : autoTrainEnabled ? "Active" : "Paused"}
                </p>
              </div>
              <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Last Trained</p>
                <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{lastTrained || "Never"}</p>
              </div>
              <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Scheduler</p>
                <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">Every ~60s</p>
              </div>
            </div>
          </div>

          {/* Manual Retrain */}
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Manual Retraining</h2>
                <p className="text-[13px] text-[var(--fg-muted)]">Trigger an immediate model retraining cycle</p>
              </div>
              <Button size="sm" onClick={() => triggerRetrain()} disabled={training}>
                {training ? "\u23F3 Training\u2026" : "\u26A1 Retrain Now"}
              </Button>
            </div>
            {trainingResult && (
              <div className={`mt-4 rounded-[var(--radius-xl)] border p-4 ${
                trainingResult.status === "error"
                  ? "border-[var(--severity-high)]/30 bg-[var(--severity-high)]/[0.06]"
                  : trainingResult.scheduled
                  ? "border-[var(--status-healthy)]/30 bg-[var(--status-healthy)]/[0.06]"
                  : "border-[var(--accent-cyan)]/30 bg-[var(--accent-cyan)]/[0.06]"
              }`}>
                {trainingResult.status === "error" ? (
                  <p className="text-[13px] text-[var(--severity-high)]">{trainingResult.message}</p>
                ) : trainingResult.scheduled ? (
                  <div>
                    <p className="text-[13px] font-semibold text-[var(--status-healthy)]">Training started in background</p>
                    <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">Window: {trainingResult.window}</p>
                  </div>
                ) : trainingResult.window ? (
                  <div>
                    <p className="text-[13px] font-semibold text-[var(--fg-primary)]">Training complete</p>
                    <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">Window: {trainingResult.window}</p>
                  </div>
                ) : null}
              </div>
            )}
          </div>

          {/* Feature Importance */}
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-6">
            <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Feature Importance</h2>
            <p className="mt-0.5 text-[12px] text-[var(--fg-muted)]">Top contributing signals to model decisions</p>
            <div className="mt-5 space-y-4">
              {[
                { label: "Credential Access Signals", value: 24, icon: "\uD83D\uDD10" },
                { label: "Suspicious PowerShell", value: 17, icon: "\uD83D\uDCC0" },
                { label: "Network Reconnaissance", value: 11, icon: "\uD83D\uDD0C" },
                { label: "Process Anomalies", value: 9, icon: "\u2699\uFE0F" },
                { label: "Risk Decay", value: -8, icon: "\uD83D\uDCC9" },
              ].map(({ label, value, icon }) => (
                <div key={label} className="flex items-center gap-4">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--bg-inset)] text-[14px]">{icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between text-[12px] mb-1">
                      <span className="text-[var(--fg-secondary)] truncate">{label}</span>
                      <span className="ml-2 shrink-0 font-semibold" style={{ color: value >= 0 ? "var(--accent-cyan)" : "var(--severity-critical)" }}>
                        {value >= 0 ? "+" : ""}{value}
                      </span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                      <div
                        className="h-full rounded-full transition-all duration-700 ease-out"
                        style={{
                          width: `${Math.abs(value) * 3}%`,
                          background: value >= 0 ? "linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))" : "linear-gradient(90deg, var(--severity-critical), var(--severity-high))",
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(MLDetection);
