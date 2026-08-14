import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { Loading } from "../components/Feedback.jsx";
import { AssistantIcon, NetworkIcon, RefreshIcon, TrashIcon } from "../components/icons.jsx";

const SUGGESTIONS = [
  "Explain the latest alert",
  "Summarize current incidents",
  "Show open high severity alerts",
  "Show recent events",
  "Is my fleet healthy?",
  "Recommend remediation actions",
];

const ENTITY_KINDS = ["user", "device", "ip", "domain", "file", "process", "technique"];

function MessageBubble({ message, index }) {
  const isUser = message.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`flex max-w-[85%] items-start gap-2.5 ${
          isUser ? "flex-row-reverse" : ""
        }`}
      >
        <span
          className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border text-sm ${
            isUser
              ? "border-cyan-500/40 bg-cyan-500/20"
              : "border-violet-500/40 bg-violet-500/20"
          }`}
          aria-hidden
        >
          {isUser ? "🧑‍💻" : <AssistantIcon className="h-4 w-4 text-violet-300" />}
        </span>
        <div
          className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
            isUser
              ? "rounded-tr-sm border border-cyan-500/30 bg-gradient-to-r from-cyan-600/30 to-cyan-500/15 text-cyan-50"
              : "rounded-tl-sm border border-slate-700/50 bg-slate-800/50 text-slate-200"
          }`}
        >
          <p className="whitespace-pre-wrap">{message.content}</p>
          {message.created_at && (
            <p className="mt-2 text-right text-[10px] text-slate-500">
              {new Date(message.created_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              })}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

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
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const bottomRef = useRef(null);

  useEffect(() => {
    api
      .assistantHistory()
      .then((r) => setMessages(r.items || []))
      .catch(() => setMessages([]));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  const send = async (text) => {
    const message = (text ?? input).trim();
    if (!message || busy) return;
    setInput("");
    setBusy(true);
    setError("");
    setMessages((m) => [...m, { role: "user", content: message }]);
    try {
      const res = await api.assistantChat(message);
      setMessages((m) => [...m, { role: "assistant", content: res.reply }]);
    } catch (e) {
      setError(e.message);
      setMessages((m) => [...m, { role: "assistant", content: `Error: ${e.message}` }]);
    } finally {
      setBusy(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const clearConversation = async () => {
    if (busy || messages.length === 0) return;
    if (!window.confirm("Clear the assistant conversation history?")) return;
    setBusy(true);
    setError("");
    try {
      await api.assistantClearHistory();
      setMessages([]);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6 pb-12">
      <PageHeader
        title="AI Security Assistant"
        subtitle="Local threat intelligence engine — ask about alerts and entities"
      />

      <EntityAnalyst />

      <Card className="flex h-[540px] flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/50 px-1 pb-3">
          <p className="text-sm font-medium text-slate-300">
            Conversation{" "}
            <span className="text-slate-500">({messages.length} messages)</span>
          </p>
          <button
            type="button"
            onClick={clearConversation}
            disabled={busy || messages.length === 0}
            className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:opacity-40"
          >
            <TrashIcon className="h-3.5 w-3.5" />
            Clear history
          </button>
        </div>

        {/* Messages */}
        <div className="flex-1 space-y-4 overflow-y-auto pr-1">
          {messages.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center">
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-violet-500/30 bg-violet-500/10">
                <AssistantIcon className="h-8 w-8 text-violet-400" />
              </div>
              <p className="mt-4 text-sm font-medium text-slate-300">
                Welcome to the BARAQ AI Assistant
              </p>
              <p className="mt-1 max-w-sm text-xs text-slate-500">
                Ask about threats, get analysis, and receive remediation recommendations
              </p>
              <div className="mt-6 flex flex-wrap justify-center gap-2">
                {SUGGESTIONS.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => send(s)}
                    className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-xs font-medium text-cyan-400 transition-colors hover:border-cyan-500/50 hover:bg-cyan-500/20"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m, i) => <MessageBubble key={i} message={m} />)
          )}

          {busy && (
            <div className="flex justify-start">
              <div className="flex items-center gap-2 rounded-2xl rounded-tl-sm border border-slate-700/50 bg-slate-800/50 px-4 py-3 text-xs text-slate-400">
                <span className="flex gap-1">
                  <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400 [animation-delay:-0.2s]" />
                  <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400 [animation-delay:-0.1s]" />
                  <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400" />
                </span>
                Analyzing
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {error && (
          <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            {error}
          </div>
        )}

        {/* Input */}
        <div className="flex items-center gap-2 border-t border-slate-700/50 pt-4">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Ask about threats, alerts, or incidents... (Enter to send)"
            rows={1}
            disabled={busy}
            className="max-h-32 flex-1 resize-none rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 disabled:opacity-50"
          />
          <button
            type="button"
            onClick={() => send()}
            disabled={busy || !input.trim()}
            className="rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-6 py-2.5 font-medium text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
          >
            {busy ? "..." : "Send"}
          </button>
        </div>
      </Card>
    </div>
  );
}
