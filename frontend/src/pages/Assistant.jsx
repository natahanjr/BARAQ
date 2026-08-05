import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { AssistantIcon } from "../components/icons.jsx";

const SUGGESTIONS = [
  "Explain the latest alert",
  "Summarize current incidents",
  "What's the threat distribution?",
  "Recommend remediation actions",
];

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

  return (
    <div className="mx-auto max-w-4xl space-y-6 pb-12">
      <PageHeader
        title="AI Security Assistant"
        subtitle="Local threat intelligence engine — ask about alerts and incidents"
      />

      <Card className="flex h-[620px] flex-col">
        {/* Messages */}
        <div className="flex-1 space-y-4 overflow-y-auto pr-1">
          {messages.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-center">
              <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-violet-500/30 bg-violet-500/10">
                <AssistantIcon className="h-8 w-8 text-violet-400" />
              </div>
              <p className="mt-4 text-sm font-medium text-slate-300">
                Welcome to the SentinelSOC AI Assistant
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
