import { useState } from "react";
import { api } from "../api.js";
import AssistantPanel from "../components/AssistantPanel.jsx";
import { Loading } from "../components/Feedback.jsx";

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
    <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            Entity Analyst
          </h3>
          <p className="mt-0.5 text-sm text-slate-400">
            Explain <em>why</em> an IP, user, device, domain or hash is suspicious
          </p>
        </div>
        <svg className="h-6 w-6 text-cyan-400" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" />
        </svg>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
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
          className="min-w-0 flex-1 rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-[12px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
        />
        <button
          type="button"
          onClick={run}
          disabled={analyzing || !name.trim()}
          className="inline-flex items-center gap-2 rounded-xl border border-violet-500/25 bg-violet-500/[0.08] px-4 py-2.5 text-[12px] font-semibold text-violet-400 transition-all hover:bg-violet-500/[0.15] hover:shadow-[0_0_16px_-4px_rgba(139,92,246,0.2)] disabled:opacity-50"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" strokeWidth="2" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182" />
          </svg>
          {analyzing ? "Analysing…" : "Analyse entity"}
        </button>
      </div>

      {analyzing && <Loading label="Analysing entity" />}
      {error && !result && (
        <div className="mt-3 rounded-xl border p-4 text-sm" style={{ background: "var(--error-bg, #fef2f2)", borderColor: "var(--error-border, #fecaca)", color: "var(--error-text, #991b1b)" }}>
          {error}
        </div>
      )}
      {result && (
        <div
          className="mt-4 rounded-2xl border p-5 font-mono text-[13px] leading-relaxed shadow-inner"
          style={{ background: "#0f172a", borderColor: "rgba(255,255,255,0.04)", color: "#e2e8f0" }}
        >
          <p className="whitespace-pre-wrap">
            {result}
          </p>
        </div>
      )}
    </div>
  );
}

export default function Assistant() {
  return (
    <div className="mx-auto max-w-4xl space-y-6 pb-12">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">AI Security Assistant</h1>
        <p className="mt-1 text-sm text-slate-400">Local threat intelligence engine — ask about alerts and entities</p>
      </div>

      <EntityAnalyst />

      <div className="flex h-[540px] flex-col rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="border-b border-white/[0.06] pb-3">
          <p className="text-sm font-medium text-slate-300">Conversation</p>
        </div>
        <div className="mt-4 flex min-h-0 flex-1 flex-col">
          <AssistantPanel compact />
        </div>
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-[11px] font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
