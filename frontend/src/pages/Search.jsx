import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { SearchIcon, BoltIcon, TrashIcon } from "../components/icons.jsx";

const RANGES = [
  { label: "15m", value: "-15m" },
  { label: "1h", value: "-1h" },
  { label: "24h", value: "-24h" },
  { label: "7d", value: "-7d" },
  { label: "30d", value: "-30d" },
];

const EXAMPLES = [
  'event_id=4625 | stats count by user | sort -count',
  'index=alerts severity=high | top 5 rule',
  '"powershell -enc" | table user, host, event_id | limit 20',
  'source=eventlog risk=High | stats count by category',
  'index=alerts | stats count, avg(risk_score) by host | sort -count | limit 10',
];

const BADGE_COLS = new Set(["severity", "risk_level", "risk"]);

export default function Search() {
  const [query, setQuery] = useState("");
  const [range, setRange] = useState("-24h");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [suggestions, setSuggestions] = useState([]);
  const [savedList, setSavedList] = useState(null);
  const [savedName, setSavedName] = useState("");
  const [savedMsg, setSavedMsg] = useState("");
  const suggestBox = useRef(null);

  useEffect(() => {
    api.savedSearches().then(setSavedList).catch(() => {});
  }, []);

  const run = useCallback(
    (q) => {
      const text = (q ?? query).trim();
      if (!text) return;
      setBusy(true);
      setError("");
      api
        .search(text, { earliest: range, limit: 1000 })
        .then(setResult)
        .catch((e) => setError(e.message))
        .finally(() => setBusy(false));
    },
    [query, range],
  );

  const saveCurrent = () => {
    const text = query.trim();
    if (!text) {
      setError("Nothing to save - enter a query first");
      return;
    }
    api
      .saveSearch({ name: savedName || text.split("|")[0].slice(0, 48), query: text, earliest: range })
      .then(() => {
        setSavedMsg("Saved");
        setSavedName("");
        setTimeout(() => setSavedMsg(""), 2000);
        return api.savedSearches();
      })
      .then(setSavedList)
      .catch((e) => setError(e.message));
  };

  const runSaved = (s) => {
    setQuery(s.query);
    setRange(s.earliest || "-24h");
    setBusy(true);
    setError("");
    api
      .runSavedSearch(s.id)
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const deleteSaved = (s) => {
    if (!window.confirm(`Delete saved search "${s.name}"?`)) return;
    api
      .deleteSavedSearch(s.id)
      .then(() => api.savedSearches())
      .then(setSavedList)
      .catch((e) => setError(e.message));
  };

  const onSuggest = (e) => {
    const v = e.target.value;
    setQuery(v);
    const last = v.split("|").pop().trim();
    if (last && !last.endsWith(" ")) {
      api.searchSuggest(last).then((s) => setSuggestions(s.suggestions)).catch(() => setSuggestions([]));
    } else setSuggestions([]);
  };

  useEffect(() => {
    const onClick = (e) => {
      if (suggestBox.current && !suggestBox.current.contains(e.target)) setSuggestions([]);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const pickSuggestion = (text) => {
    const parts = query.split("|");
    const tail = parts.pop();
    const before = tail.slice(0, tail.length - tail.trimStart().length);
    parts.push(before + text);
    setQuery(parts.join("|"));
    setSuggestions([]);
  };

  return (
    <div className="space-y-4 pb-12">
      <PageHeader
        label="Hunt"
        title="Search"
        subtitle="Hunting across events and alerts"
      />

      {/* Console shell */}
      <Card>
        <div className="relative">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-lg font-bold text-cyan-400 drop-shadow-[0_0_8px_rgba(0,240,255,0.6)]">
              |
            </span>
            <input
              value={query}
              onChange={onSuggest}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  if (suggestions.length && e.nativeEvent.isComposing === false) return;
                  run();
                }
              }}
              placeholder="Search… e.g. event_id=4625 | stats count by user"
              spellCheck={false}
              className="w-full rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2.5 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-500 focus:border-cyan-400/50 focus:shadow-[0_0_24px_-6px_rgba(0,240,255,0.4)]"
            />
            <button
              onClick={() => run()}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 px-5 py-2.5 text-sm font-semibold text-white transition-all hover:from-cyan-400 hover:to-violet-500 disabled:opacity-50"
            >
              <SearchIcon className="h-4 w-4" />
              {busy ? "Searching…" : "Search"}
            </button>
          </div>
          {suggestions.length > 0 && (
            <div
              ref={suggestBox}
              className="glass-line absolute left-0 right-0 top-full z-10 mt-2 overflow-hidden rounded-xl"
            >
              {suggestions.map((s, i) => (
                <button
                  key={i}
                  type="button"
                  onMouseDown={() => pickSuggestion(s.text)}
                  className="block w-full px-4 py-2.5 text-left font-mono text-[13px] text-cyan-300 transition-colors hover:bg-cyan-500/10"
                >
                  {s.type === "pipe" ? "| " : ""}
                  {s.text}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => setRange(r.value)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                range === r.value
                  ? "border-cyan-400/60 bg-cyan-500/15 text-cyan-300 shadow-[0_0_12px_-4px_rgba(0,240,255,0.6)]"
                  : "border-white/10 bg-white/[0.03] text-slate-500 hover:border-cyan-400/30 hover:text-slate-300"
              }`}
            >
              {r.label}
            </button>
          ))}
          <span className="ml-auto font-mono text-[10px] text-slate-600">
            index=events | index=alerts
          </span>
        </div>
      </Card>

      {/* Examples */}
      <div className="flex flex-wrap gap-2">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => {
              setQuery(ex);
              run(ex);
            }}
            className="rounded-xl border border-dashed border-white/15 px-3 py-1.5 font-mono text-[11px] text-slate-500 transition-colors hover:border-cyan-400/40 hover:text-cyan-300"
          >
            {ex}
          </button>
        ))}
      </div>

      {/* Saved searches */}
      {savedList && savedList.searches.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
            Saved Searches
          </p>
          <div className="flex flex-wrap gap-2">
            {savedList.searches.map((s) => (
              <div
                key={s.id}
                className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] py-1 pl-3 pr-1"
              >
                <button
                  type="button"
                  onClick={() => runSaved(s)}
                  className="font-mono text-xs text-cyan-300 transition-colors hover:text-cyan-200"
                >
                  {s.name}
                </button>
                <button
                  type="button"
                  onClick={() => deleteSaved(s)}
                  title="Delete"
                  className="rounded-lg p-1 text-slate-600 transition-colors hover:bg-red-500/10 hover:text-red-400"
                >
                  <TrashIcon className="h-3 w-3" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Save bar */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={savedName}
          onChange={(e) => setSavedName(e.target.value)}
          placeholder="Saved search name…"
          className="w-56 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50"
        />
        <button
          type="button"
          onClick={saveCurrent}
          className="rounded-xl border border-dashed border-white/15 px-3.5 py-2 text-xs text-slate-500 transition-colors hover:border-cyan-400/40 hover:text-cyan-300"
        >
          {savedMsg || "Save current query"}
        </button>
      </div>

      {busy && <Loading label="Running search…" />}

      {error && !busy && <ErrorBanner message={error} />}

      {result && !busy && (
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-4 font-mono text-xs text-slate-600">
            <span>
              <strong className="text-cyan-300">{result.total}</strong> results
            </span>
            <span>{result.elapsed_ms} ms</span>
            <span>index={result.index}</span>
            <BoltIcon className="h-3.5 w-3.5 text-violet-400" />
          </div>
          {result.rows.length === 0 ? (
            <EmptyState title="No results" subtitle="Nothing matched in the selected window" />
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table w-full">
                <thead>
                  <tr>
                    {result.columns.map((c) => (
                      <th key={c} className="whitespace-nowrap font-mono">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.slice(0, 500).map((row, i) => (
                    <tr key={i}>
                      {result.columns.map((c, j) => {
                        const raw = row[j];
                        const value = raw === null || raw === undefined ? "-" : String(raw);
                        return (
                          <td
                            key={c}
                            className="max-w-[420px] truncate font-mono text-[12px] text-slate-300"
                          >
                            {BADGE_COLS.has(c) &&
                            ["critical", "high", "medium", "low", "info"].includes(value.toLowerCase()) ? (
                              <SeverityBadge severity={value} />
                            ) : BADGE_COLS.has(c) &&
                              ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(value.toUpperCase()) ? (
                              <RiskBadge level={value.toUpperCase()} score={0} />
                            ) : (
                              value
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}