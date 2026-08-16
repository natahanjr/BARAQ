import { useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import AssistantPanel from "../components/AssistantPanel.jsx";
import { Loading } from "../components/Feedback.jsx";
import { NetworkIcon, RefreshIcon } from "../components/icons.jsx";

const ENTITY_KINDS = ["user", "device", "ip", "domain", "file", "process", "technique"];

function EntityAnalyst() {
  const [kind, setKind] = useState("ip");
  const [name, setName] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

  const run = async () => {
    const n = name.trim();
    if (!n || analyzing) return;
    setAnalyzing(true);
    setResult("");
    setError("");
    try {
      const res = await api.assistantEntityExplain(kind, n);
      setResult(res.reply);
    } catch (e) {
      setError(e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <Card>
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-white">Entity Analyst</h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Explain <em>why</em> an IP, user, device, domain or hash is suspicious
          </p>
        </div>
        <NetworkIcon className="h-6 w-6 text-cyan-400" />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          className="rounded-lg border border-slate-700/60 bg-slate-900/70 px-2.5 py-2 text-xs text-slate-300 outline-none focus:border-cyan-500/50"
        >
          {ENTITY_KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="IP, host, user, domain, hash…"
          className="min-w-0 flex-1 rounded-lg border border-slate-700/60 bg-slate-900/70 px-3 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
        />
        <button
          type="button"
          onClick={run}
          disabled={analyzing || !name.trim()}
          className="inline-flex items-center gap-2 rounded-lg bg-violet-500/15 px-4 py-2 text-xs font-semibold text-violet-300 ring-1 ring-violet-500/40 transition-colors hover:bg-violet-500/25 disabled:opacity-50"
        >
          <RefreshIcon className="h-3.5 w-3.5" />
          {analyzing ? "Analysing…" : "Analyse entity"}
        </button>
      </div>

      {analyzing && <Loading label="Analysing entity" />}
      {error && !result && (
        <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
          {error}
        </div>
      )}
      {result && (
        <div className="mt-4 rounded-xl border border-slate-700/50 bg-slate-950/50 p-4">
          <p className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-slate-200">
            {result}
          </p>
        </div>
      )}
    </Card>
  );
}

export default function Assistant() {
  return (
    <div className="mx-auto max-w-4xl space-y-6 pb-12">
      <PageHeader
        title="AI Security Assistant"
        subtitle="Local threat intelligence engine — ask about alerts and entities"
      />

      <EntityAnalyst />

      <Card className="flex h-[540px] flex-col">
        <div className="flex items-center justify-between border-b border-slate-700/50 px-1 pb-3">
          <p className="text-sm font-medium text-slate-300">Conversation</p>
        </div>
        <div className="mt-4 flex min-h-0 flex-1 flex-col">
          <AssistantPanel compact />
        </div>
      </Card>
    </div>
  );
}