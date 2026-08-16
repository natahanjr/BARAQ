import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { AssistantIcon, TrashIcon } from "./icons.jsx";

export const SUGGESTIONS = [
  "Explain the latest alert",
  "Summarize current incidents",
  "Show open high severity alerts",
  "Show recent events",
  "Is my fleet healthy?",
  "Recommend remediation actions",
];

function MessageBubble({ message }) {
  const isUser = message.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div className={`flex max-w-[85%] items-start gap-2.5 ${isUser ? "flex-row-reverse" : ""}`}>
        <span
          className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border text-sm ${
            isUser ? "border-cyan-500/40 bg-cyan-500/20" : "border-violet-500/40 bg-violet-500/20"
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

/** Chat engine shared by the full Assistant page and the global drawer. */
export default function AssistantPanel({ compact = false }) {
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
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Messages */}
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
        {messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-violet-500/30 bg-violet-500/10 shadow-[0_0_24px_-6px_rgba(123,97,255,0.6)]">
              <AssistantIcon className="h-7 w-7 text-violet-400" />
            </div>
            <p className="mt-3 text-sm font-medium text-slate-300">
              Welcome to the BARAQ AI Assistant
            </p>
            <p className="mt-1 max-w-sm text-xs text-slate-500">
              Ask about threats, get analysis, and receive remediation recommendations
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.slice(0, compact ? 4 : 6).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => send(s)}
                  className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-[11px] font-medium text-cyan-400 transition-colors hover:border-cyan-500/50 hover:bg-cyan-500/20"
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
        <div className="mb-2 rounded-lg border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Input */}
      <div className="flex items-center gap-2 border-t border-slate-700/50 pt-3">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about threats, alerts, or incidents… (Enter to send)"
          rows={1}
          disabled={busy}
          className="max-h-28 flex-1 resize-none rounded-lg border border-slate-700 bg-slate-800/70 px-3.5 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 disabled:opacity-50"
        />
        <button
          type="button"
          onClick={() => send()}
          disabled={busy || !input.trim()}
          className="rounded-lg bg-gradient-to-r from-cyan-600 to-violet-600 px-5 py-2.5 text-sm font-medium text-white transition-all hover:from-cyan-500 hover:to-violet-500 disabled:opacity-50"
        >
          {busy ? "…" : "Send"}
        </button>
        {!compact && (
          <button
            type="button"
            onClick={clearConversation}
            disabled={busy || messages.length === 0}
            title="Clear conversation history"
            className="rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-2.5 text-red-300 transition-colors hover:bg-red-500/20 disabled:opacity-40"
          >
            <TrashIcon className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}