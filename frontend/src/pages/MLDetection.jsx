import { memo, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { Button, Tabs } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

const MODEL_ICONS = {
  anomaly: { icon: "\uD83D\uDD0D", gradient: "from-[var(--severity-medium)] to-[var(--severity-high)]" },
  supervised: { icon: "\uD83D\uDCCA", gradient: "from-[var(--accent-cyan)] to-[var(--accent-violet)]" },
  ensemble: { icon: "\uD83E\uDDE0", gradient: "from-[var(--accent-violet)] to-[var(--accent-gold)]" },
  robustness: { icon: "\uD83D\uDEE1\uFE0F", gradient: "from-[var(--status-healthy)] to-[var(--accent-cyan)]" },
  online: { icon: "\u26A1", gradient: "from-[var(--accent-gold)] to-[var(--severity-medium)]" },
  temporal: { icon: "\uD83D\uDCC5", gradient: "from-[var(--accent-cyan)] to-[var(--accent-violet)]" },
  federated: { icon: "\uD83C\uDF10", gradient: "from-[var(--accent-violet)] to-[var(--accent-gold)]" },
  community: { icon: "\uD83D\uDC65", gradient: "from-[var(--status-healthy)] to-[var(--accent-cyan)]" },
  remediation: { icon: "\uD83D\uDD27", gradient: "from-[var(--severity-medium)] to-[var(--severity-high)]" },
  comparison: { icon: "\uD83D\uDCCA", gradient: "from-[var(--accent-cyan)] to-[var(--accent-violet)]" },
  retention: { icon: "\uD83D\uDCC1", gradient: "from-[var(--accent-gold)] to-[var(--status-healthy)]" },
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
  const [robustness, setRobustness] = useState(null);
  const [onlineLearning, setOnlineLearning] = useState(null);
  const [temporalBias, setTemporalBias] = useState(null);
  const [federated, setFederated] = useState(null);
  const [communityRules, setCommunityRules] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [retention, setRetention] = useState(null);
  const [ensemble, setEnsemble] = useState(null);
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
            if (prev?.trained) return prev;
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
      if (result.training) {
        toast({ title: "Training already in progress", type: "info" });
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

  const loadTabData = useCallback(async (tabId) => {
    try {
      switch (tabId) {
        case "robustness":
          if (!robustness) {
            const r = await api.mlRobustness();
            setRobustness(r);
          }
          break;
        case "online-learning":
          if (!onlineLearning) {
            const o = await api.mlOnlineLearning();
            setOnlineLearning(o);
          }
          break;
        case "temporal-bias":
          if (!temporalBias) {
            const t = await api.mlTemporalBias();
            setTemporalBias(t);
          }
          break;
        case "federated":
          if (!federated) {
            const f = await api.mlFederated();
            setFederated(f);
          }
          break;
        case "community":
          if (!communityRules) {
            const c = await api.mlCommunityRules();
            setCommunityRules(c);
          }
          break;
        case "remediation":
          if (!remediation) {
            const rm = await api.mlRemediation();
            setRemediation(rm);
          }
          break;
        case "comparison":
          if (!comparison) {
            const comp = await api.mlComparison();
            setComparison(comp);
          }
          break;
        case "retention":
          if (!retention) {
            const ret = await api.mlRetention();
            setRetention(ret);
          }
          break;
        case "ensemble":
          if (!ensemble) {
            const e = await api.mlEnsemble();
            setEnsemble(e);
          }
          break;
      }
    } catch (err) {
      console.error(`Failed to load ${tabId} data:`, err);
    }
  }, [robustness, onlineLearning, temporalBias, federated, communityRules, remediation, comparison, retention, ensemble]);

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
    { label: "Model State", value: overallState, color: overallState === "HEALTHY" ? "var(--status-healthy)" : overallState === "WARNING" ? "var(--severity-medium)" : "var(--severity-critical)", icon: training ? "\u23F3" : "\uD83D\uDD27", tab: "models" },
    { label: "Scored Events", value: scoredEvents, color: "var(--accent-cyan)", icon: "\uD83D\uDCCA", tab: "anomalies" },
    { label: "Training Samples", value: trainingSamples, color: "var(--accent-violet)", icon: "\uD83C\uDF31", tab: "training" },
    { label: "Drift Status", value: driftStatus, color: driftStatus === "Nominal" ? "var(--status-healthy)" : "var(--severity-high)", icon: "\u2696\uFE0F", tab: "anomalies" },
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

      {/* Training Result Banner */}
      {trainingResult && (
        <div className={`rounded-[var(--radius-xl)] border p-4 ${
          trainingResult.status === "error"
            ? "border-[var(--severity-critical)]/30 bg-[var(--severity-critical)]/[0.06]"
            : trainingResult.training
            ? "border-[var(--severity-medium)]/30 bg-[var(--severity-medium)]/[0.06]"
            : trainingResult.scheduled === false && trainingResult.trained === false
            ? "border-[var(--severity-medium)]/30 bg-[var(--severity-medium)]/[0.06]"
            : "border-[var(--status-healthy)]/30 bg-[var(--status-healthy)]/[0.06]"
        }`}>
          <div className="flex items-start gap-3">
            <span className="text-[18px] mt-0.5">
              {trainingResult.status === "error" ? "\u274C" : trainingResult.training ? "\u23F3" : trainingResult.scheduled === false && trainingResult.trained === false ? "\u2139\uFE0F" : "\u2705"}
            </span>
            <div className="flex-1">
              {trainingResult.status === "error" ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--severity-critical)]">Training Failed</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">{trainingResult.message}</p>
                </>
              ) : trainingResult.training ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--severity-medium)]">Training Already in Progress</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">{trainingResult.message || "Waiting for the current training run to finish..."}</p>
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
              ) : trainingResult.trained === true ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--status-healthy)]">Training Complete</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">
                    Window: {trainingResult.window}
                    {trainingResult.samples != null && ` \u00B7 ${trainingResult.samples} samples`}
                  </p>
                </>
              ) : trainingResult.window ? (
                <>
                  <p className="text-[13px] font-semibold text-[var(--fg-primary)]">Training Result</p>
                  <p className="text-[12px] text-[var(--fg-muted)] mt-0.5">Window: {trainingResult.window}</p>
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
            onClick={() => { setTab(s.tab); setSelectedModel(null); }}
            className="group relative overflow-hidden cursor-pointer rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-300 p-5 hover:border-[var(--border-strong)] hover:shadow-lg active:scale-[0.98]"
          >
            <div className="absolute -right-6 -top-6 h-20 w-20 rounded-full blur-2xl opacity-0 transition-opacity duration-500 group-hover:opacity-40" style={{ background: s.color }} />
            <div className="relative flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-2 text-[28px] font-bold tabular-nums leading-none" style={{ color: s.color, fontFeatureSettings: '"tnum"' }}>
                  {s.value}
                </p>
              </div>
              <span className="text-[18px] opacity-50 group-hover:opacity-100 transition-opacity">{s.icon}</span>
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
          { id: "ensemble", label: "Ensemble" },
          { id: "robustness", label: "Robustness" },
          { id: "online-learning", label: "Online Learning" },
          { id: "temporal-bias", label: "Temporal Bias" },
          { id: "federated", label: "Federated" },
          { id: "community", label: "Community Rules" },
          { id: "remediation", label: "Remediation" },
          { id: "comparison", label: "Comparison" },
          { id: "retention", label: "Retention" },
        ]}
        active={tab}
        onChange={(t) => { setTab(t); setSelectedModel(null); loadTabData(t); }}
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
                <div className="absolute -right-10 -top-10 h-28 w-28 rounded-full bg-gradient-to-br opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-30" style={{ background: `linear-gradient(135deg, ${stateColor}, transparent)` }} />
                <div className="relative">
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
                  <div className="mt-4">
                    <div className="flex items-center justify-between text-[11px] mb-1.5">
                      <span className="text-[var(--fg-muted)]">Accuracy</span>
                      <span className="font-semibold text-[var(--fg-primary)]">{model.accuracy}%</span>
                    </div>
                    <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                      <div className="h-full rounded-full transition-all duration-700 ease-out" style={{ width: `${model.accuracy}%`, background: model.accuracy >= 90 ? "var(--status-healthy)" : model.accuracy >= 80 ? "var(--severity-medium)" : "var(--severity-critical)" }} />
                    </div>
                  </div>
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
            <div className="mt-6 rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[12px] font-semibold text-[var(--fg-muted)]">Accuracy</span>
                <span className="text-[24px] font-bold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>{selectedModel.accuracy}%</span>
              </div>
              <div className="h-3 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                <div className="h-full rounded-full transition-all duration-1000 ease-out" style={{ width: `${selectedModel.accuracy}%`, background: selectedModel.accuracy >= 90 ? "linear-gradient(90deg, var(--status-healthy), #22d3ee)" : "var(--severity-medium)" }} />
              </div>
              <div className="mt-2 flex justify-between text-[11px] text-[var(--fg-muted)]">
                <span>0%</span><span>50%</span><span>100%</span>
              </div>
            </div>
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
          </div>
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
                      <div className="h-full rounded-full transition-all duration-700 ease-out" style={{ width: `${Math.abs(value) * 3}%`, background: value >= 0 ? "linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))" : "linear-gradient(90deg, var(--severity-critical), var(--severity-high))" }} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Ensemble ─────────────────────────────────────── */}
      {tab === "ensemble" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.ensemble.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.ensemble.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Ensemble Stackers</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Meta-learner combining Isolation Forest, XGBoost, and Markov predictions</p>
              </div>
            </div>
            {ensemble?.ensemble ? (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Trained</p>
                  <p className="mt-1 text-[13px] font-semibold" style={{ color: ensemble.ensemble.is_trained ? "var(--status-healthy)" : "var(--severity-medium)" }}>
                    {ensemble.ensemble.is_trained ? "Yes" : "No"}
                  </p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Meta Learner</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{ensemble.ensemble.active_meta_learner || "none"}</p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Min Samples</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{ensemble.ensemble.min_samples_required || 30}</p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Weights</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">
                    {ensemble.ensemble.meta_weights && Object.keys(ensemble.ensemble.meta_weights).length > 0
                      ? Object.entries(ensemble.ensemble.meta_weights).map(([k, v]) => `${k}: ${typeof v === "number" ? v.toFixed(2) : v}`).join(", ")
                      : "Fixed (0.6/0.4)"}
                  </p>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Ensemble data loading...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Robustness ───────────────────────────────────── */}
      {tab === "robustness" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.robustness.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.robustness.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Model Robustness</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">FGSM adversarial testing and cross-validation results</p>
              </div>
            </div>
            {robustness ? (
              <div className="space-y-4">
                {robustness.cross_user && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Cross-User Validation</p>
                    <pre className="text-[11px] text-[var(--fg-muted)] overflow-auto max-h-40">{JSON.stringify(robustness.cross_user, null, 2)}</pre>
                  </div>
                )}
                {robustness.cross_environment && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Cross-Environment Validation</p>
                    <pre className="text-[11px] text-[var(--fg-muted)] overflow-auto max-h-40">{JSON.stringify(robustness.cross_environment, null, 2)}</pre>
                  </div>
                )}
                {robustness.cross_platform && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Cross-Platform Validation</p>
                    <pre className="text-[11px] text-[var(--fg-muted)] overflow-auto max-h-40">{JSON.stringify(robustness.cross_platform, null, 2)}</pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading robustness data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Online Learning ──────────────────────────────── */}
      {tab === "online-learning" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.online.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.online.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Online Learning</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Incremental model updates and active learning suggestions</p>
              </div>
            </div>
            {onlineLearning ? (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Available</p>
                  <p className="mt-1 text-[13px] font-semibold" style={{ color: onlineLearning.online_learner_available ? "var(--status-healthy)" : "var(--severity-medium)" }}>
                    {onlineLearning.online_learner_available ? "Yes" : "No"}
                  </p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Should Update</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{onlineLearning.should_update ? "Yes" : "No"}</p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Active Learning</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{onlineLearning.active_learning_suggestions || 0} suggestions</p>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading online learning data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Temporal Bias ────────────────────────────────── */}
      {tab === "temporal-bias" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.temporal.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.temporal.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Temporal Bias Detection</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Hourly, daily, and monthly distribution shift analysis</p>
              </div>
            </div>
            {temporalBias ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Bias Detected</p>
                    <p className="mt-1 text-[13px] font-semibold" style={{ color: temporalBias.any_bias_detected ? "var(--severity-high)" : "var(--status-healthy)" }}>
                      {temporalBias.any_bias_detected ? "Yes" : "No"}
                    </p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Max PSI</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{temporalBias.max_psi || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Recommendation</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{temporalBias.recommendation || "N/A"}</p>
                  </div>
                </div>
                {temporalBias.hourly && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Hourly Distribution</p>
                    <p className="text-[11px] text-[var(--fg-muted)]">PSI: {temporalBias.hourly.psi} - {temporalBias.hourly.description}</p>
                  </div>
                )}
                {temporalBias.daily && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Daily Distribution</p>
                    <p className="text-[11px] text-[var(--fg-muted)]">PSI: {temporalBias.daily.psi} - {temporalBias.daily.description}</p>
                  </div>
                )}
                {temporalBias.monthly && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-2">Monthly Distribution</p>
                    <p className="text-[11px] text-[var(--fg-muted)]">PSI: {temporalBias.monthly.psi} - {temporalBias.monthly.description}</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading temporal bias data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Federated Learning ───────────────────────────── */}
      {tab === "federated" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.federated.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.federated.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Federated Learning</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Multi-organization model training without data sharing</p>
              </div>
            </div>
            {federated ? (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Available</p>
                  <p className="mt-1 text-[13px] font-semibold" style={{ color: federated.available ? "var(--status-healthy)" : "var(--severity-medium)" }}>
                    {federated.available ? "Yes" : "No"}
                  </p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Aggregator</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{federated.aggregator_class}</p>
                </div>
                <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Protocol</p>
                  <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">FedAvg</p>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading federated learning data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Community Rules ──────────────────────────────── */}
      {tab === "community" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.community.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.community.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Community Rules</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Sigma, correlation, and Python-native rule contributions</p>
              </div>
            </div>
            {communityRules ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Submitted</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{communityRules.statistics?.total_submitted || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Approved</p>
                    <p className="mt-1 text-[13px] font-semibold" style={{ color: "var(--status-healthy)" }}>{communityRules.statistics?.by_status?.approved || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Pending</p>
                    <p className="mt-1 text-[13px] font-semibold" style={{ color: "var(--severity-medium)" }}>{communityRules.statistics?.by_status?.pending || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Rule Types</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{communityRules.rule_types?.length || 0}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading community rules data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Remediation ──────────────────────────────────── */}
      {tab === "remediation" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.remediation.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.remediation.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">FN Remediation</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">Automated false negative analysis and improvement suggestions</p>
              </div>
            </div>
            {remediation ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total FNs</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{remediation.summary?.fn_summary?.total || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Actions</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{remediation.summary?.remediation_actions?.count || 0}</p>
                  </div>
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                    <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Patterns</p>
                    <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{remediation.summary?.fn_summary?.attack_types?.length || 0}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading remediation data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Comparison ───────────────────────────────────── */}
      {tab === "comparison" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.comparison.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.comparison.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">SOC Platform Comparison</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">BARAQ vs commercial alternatives</p>
              </div>
            </div>
            {comparison ? (
              <div className="space-y-4">
                {comparison.recommendation && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/[0.06] p-4">
                    <p className="text-[13px] font-semibold text-[var(--accent-cyan)]">Recommendation</p>
                    <p className="text-[12px] text-[var(--fg-muted)] mt-1">{comparison.recommendation.recommendation}</p>
                  </div>
                )}
                {comparison.radar_chart?.labels && (
                  <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
                    <p className="text-[12px] font-semibold text-[var(--fg-primary)] mb-3">Capability Dimensions</p>
                    <div className="space-y-2">
                      {comparison.radar_chart.labels.map((label, i) => (
                        <div key={label} className="flex items-center gap-3">
                          <span className="text-[11px] text-[var(--fg-muted)] w-32 shrink-0">{label}</span>
                          {comparison.radar_chart.datasets?.map((ds, j) => (
                            <div key={j} className="flex-1">
                              <div className="h-2 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
                                <div className="h-full rounded-full" style={{ width: `${(ds.data[i] || 0) * 10}%`, background: j === 0 ? "var(--accent-cyan)" : j === 1 ? "var(--accent-violet)" : "var(--accent-gold)" }} />
                              </div>
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading comparison data...</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Retention ────────────────────────────────────── */}
      {tab === "retention" && (
        <div className="space-y-4">
          <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br ${MODEL_ICONS.retention.gradient} text-white`}>
                <span className="text-[18px]">{MODEL_ICONS.retention.icon}</span>
              </div>
              <div>
                <h2 className="text-[15px] font-semibold text-[var(--fg-primary)]">Data Retention & Archival</h2>
                <p className="text-[12px] text-[var(--fg-muted)]">ML training data lifecycle management</p>
              </div>
            </div>
            {retention ? (
              <div className="space-y-4">
                {retention.storage_metrics ? (
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                      <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Active Models</p>
                      <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{retention.storage_metrics.active_models || 0}</p>
                    </div>
                    <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                      <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Archived</p>
                      <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{retention.storage_metrics.archived_models || 0}</p>
                    </div>
                    <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                      <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Archive Size</p>
                      <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{retention.storage_metrics.archive_size_mb || 0} MB</p>
                    </div>
                    <div className="rounded-[var(--radius-xl)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3.5">
                      <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Size</p>
                      <p className="mt-1 text-[13px] font-semibold text-[var(--fg-primary)]">{retention.storage_metrics.total_size_mb || 0} MB</p>
                    </div>
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <p className="text-[13px] text-[var(--fg-muted)]">No retention data available</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center">
                <p className="text-[13px] text-[var(--fg-muted)]">Loading retention data...</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default memo(MLDetection);
