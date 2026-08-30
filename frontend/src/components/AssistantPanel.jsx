import { useEffect, useRef, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api } from "../api.js";
import { AssistantIcon, TrashIcon, UserIcon } from "./icons.jsx";

export const SUGGESTIONS = [
  "Explain the latest alert",
  "Summarize current incidents",
  "Show open high severity alerts",
  "Show recent events",
  "Is my fleet healthy?",
  "Recommend remediation actions",
];

/* ------------------------------------------------------------------ */
/* Apple-style markdown renderers                                     */
/* ------------------------------------------------------------------ */
const mdComponents = {
  h1: ({ children }) => (
    <h1 className="mb-3 mt-1 text-lg font-bold tracking-tight text-white">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-2 mt-5 flex items-center gap-2 text-[15px] font-semibold tracking-tight text-white">
      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-2 mt-4 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
      {children}
    </h3>
  ),
  p: ({ children }) => (
    <p className="mb-3 text-[13px] leading-relaxed text-slate-300 last:mb-0">
      {children}
    </p>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-white">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-slate-400">{children}</em>
  ),
  ul: ({ children }) => (
    <ul className="mb-3 ml-1 space-y-1.5">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mb-3 ml-4 list-decimal space-y-1.5">{children}</ol>
  ),
  li: ({ children }) => (
    <li className="text-[13px] leading-relaxed text-slate-300">
      <span className="mr-1.5 inline-block h-1 w-1 translate-y-[-1px] rounded-full bg-cyan-400/60" />
      {children}
    </li>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-3 rounded-xl border-l-2 border-cyan-500/40 bg-cyan-500/[0.04] py-2 pl-4 text-[13px] text-slate-400">
      {children}
    </blockquote>
  ),
  code: ({ className, children, ...props }) => {
    const isBlock = className?.includes("language-");
    if (isBlock) {
      return (
        <div className="my-3 overflow-hidden rounded-xl border border-white/[0.06]">
          <div className="flex items-center gap-2 border-b border-white/[0.06] bg-white/[0.03] px-4 py-2">
            <span className="h-2 w-2 rounded-full bg-red-400/60" />
            <span className="h-2 w-2 rounded-full bg-amber-400/60" />
            <span className="h-2 w-2 rounded-full bg-emerald-400/60" />
            <span className="ml-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">
              {className.replace("language-", "")}
            </span>
          </div>
          <pre
            className="overflow-x-auto px-4 py-3 text-[12px] leading-relaxed"
            style={{ background: "#0f172a", color: "#e2e8f0" }}
          >
            <code>{children}</code>
          </pre>
        </div>
      );
    }
    return (
      <code
        className="rounded-md border border-white/[0.08] bg-white/[0.06] px-1.5 py-0.5 font-mono text-[12px] text-cyan-300"
        {...props}
      >
        {children}
      </code>
    );
  },
  pre: ({ children }) => <>{children}</>,
  table: ({ children }) => (
    <div className="my-3 overflow-hidden rounded-xl border border-white/[0.06]">
      <table className="w-full text-left text-[12px]">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="border-b border-white/[0.06] bg-white/[0.03]">{children}</thead>
  ),
  th: ({ children }) => (
    <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border-t border-white/[0.04] px-3 py-2.5 text-slate-300">
      {children}
    </td>
  ),
  hr: () => <hr className="my-4 border-white/[0.06]" />,
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-cyan-400 underline decoration-cyan-400/30 transition-all hover:text-cyan-300 hover:decoration-cyan-300/50"
    >
      {children}
    </a>
  ),
};

/* ------------------------------------------------------------------ */
/* Message Bubble                                                     */
/* ------------------------------------------------------------------ */
function MessageBubble({ message }) {
  const isUser = message.role === "user";
  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div className={`flex max-w-[85%] items-start gap-2.5 ${isUser ? "flex-row-reverse" : ""}`}>
        <span
          className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border text-sm ${
            isUser
              ? "border-cyan-500/40 bg-cyan-500/20"
              : "border-violet-500/40 bg-violet-500/20"
          }`}
          aria-hidden
        >
          {isUser ? <UserIcon className="h-4 w-4 text-cyan-300" /> : <AssistantIcon className="h-4 w-4 text-violet-300" />}
        </span>
        <div
          className={`rounded-2xl px-4 py-3 text-sm leading-relaxed ${
            isUser
              ? "rounded-tr-sm border border-cyan-500/30 bg-gradient-to-r from-cyan-600/30 to-cyan-500/15 text-cyan-50"
              : "rounded-tl-sm border border-white/[0.06] bg-white/[0.025] transition-all duration-200 text-slate-200 shadow-[0_2px_12px_-4px_rgba(0,0,0,0.3)]"
          }`}
        >
          {isUser ? (
            <p className="whitespace-pre-wrap">{message.content}</p>
          ) : (
            <div className="prose-baraq">
              <Markdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                {message.content}
              </Markdown>
            </div>
          )}
          {message.created_at && (
            <p className="mt-2 text-right text-[11px] text-slate-500/60">
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

/* ------------------------------------------------------------------ */
/* Chat Engine                                                         */
/* ------------------------------------------------------------------ */
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
      setMessages((m) => [
        ...m,
        { role: "assistant", content: `Error: ${e.message}` },
      ]);
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
              Ask about threats, get analysis, and receive remediation
              recommendations
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.slice(0, compact ? 4 : 6).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => send(s)}
                  className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-[11px] font-medium text-cyan-400 transition-all hover:border-cyan-500/50 hover:bg-cyan-500/20"
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
            <div className="flex items-center gap-3 rounded-2xl rounded-tl-sm border border-white/[0.06] bg-white/[0.025] transition-all duration-200 px-4 py-3 shadow-[0_2px_12px_-4px_rgba(0,0,0,0.3)]">
              <span className="flex gap-1">
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400 [animation-delay:-0.2s]" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400 [animation-delay:-0.1s]" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-violet-400" />
              </span>
              <span className="text-xs font-medium text-slate-400">
                Analyzing
              </span>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {error && (
        <div
          className="mb-2 rounded-xl border p-2.5 text-xs"
          style={{
            background: "var(--error-bg, #fef2f2)",
            borderColor: "var(--error-border, #fecaca)",
            color: "var(--error-text, #991b1b)",
          }}
        >
          {error}
        </div>
      )}

      {/* Input */}
      <div className="flex items-center gap-2 border-t border-white/[0.06] pt-3">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about threats, alerts, or incidents… (Enter to send)"
          rows={1}
          disabled={busy}
          className="max-h-28 flex-1 resize-none rounded-xl border border-white/[0.06] bg-white/[0.03] px-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-500 outline-none transition-all focus:ring-2 focus:ring-[var(--accent-cyan)]/30 focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10 disabled:opacity-50"
        />
        <button
          type="button"
          onClick={() => send()}
          disabled={busy || !input.trim()}
          className="rounded-xl bg-gradient-to-r from-cyan-600 to-violet-600 px-5 py-2.5 text-sm font-medium text-white shadow-[0_0_16px_-4px_rgba(139,92,246,0.3)] transition-all hover:from-cyan-500 hover:to-violet-500 hover:shadow-[0_0_24px_-4px_rgba(139,92,246,0.4)] disabled:opacity-50"
        >
          {busy ? "…" : "Send"}
        </button>
        {!compact && (
          <button
            type="button"
            onClick={clearConversation}
            disabled={busy || messages.length === 0}
            title="Clear conversation history"
            className="rounded-xl border border-red-500/25 bg-red-500/[0.08] px-2.5 py-2.5 text-red-300 transition-all hover:bg-red-500/[0.15] hover:shadow-[0_0_16px_-4px_rgba(239,68,68,0.2)] disabled:opacity-40"
          >
            <TrashIcon className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
