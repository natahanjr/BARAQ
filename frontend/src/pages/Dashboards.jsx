import { useCallback, useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  Area,
} from "recharts";
import { api, isAdmin } from "../api.js";
import ChartTooltip from "../components/ChartTooltip.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const EMPTY_FORM = {
  name: "",
  description: "",
  panels: [],
};

function PanelCard({ panel }) {
  if (panel.error) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg border border-red-500/20 bg-red-500/[0.04] p-4 text-xs text-red-300">
        {panel.error}
      </div>
    );
  }
  if (panel.viz === "count") {
    return (
      <div className="flex h-full flex-col items-center justify-center p-4">
        <span className="text-4xl font-bold text-violet-300">{panel.count ?? 0}</span>
        <span className="mt-1 text-xs text-slate-400">events / results</span>
      </div>
    );
  }
  if (panel.viz === "top" && panel.data?.length) {
    return (
      <div className="h-56 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={panel.data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
            <XAxis dataKey="name" stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
            <YAxis stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" fill="#7b61ff" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }
  if (panel.viz === "area" && panel.data?.length) {
    return (
      <div className="h-56 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={panel.data}>
            <defs>
              <linearGradient id="dashArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#00f0ff" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#00f0ff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
            <XAxis dataKey="t" stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
            <YAxis stroke="var(--chart-grid)" tick={{ fontSize: 10 }} />
            <Tooltip content={<ChartTooltip />} />
            <Area type="monotone" dataKey="value" stroke="#00f0ff" fill="url(#dashArea)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    );
  }
  return (
    <div className="max-h-72 overflow-auto p-2">
      <table className="data-table w-full">
        <thead>
          <tr className="text-[10px] uppercase tracking-wider text-slate-500">
            {panel.columns.map((c) => (
              <th key={c} className="px-2 py-1 font-mono">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/[0.04]">
          {panel.rows.slice(0, 50).map((row, i) => (
            <tr key={i}>
              {panel.columns.map((c, j) => (
                <td key={c} className="px-2 py-1 font-mono text-slate-300">
                  {row[j] === null || row[j] === undefined ? "-" : String(row[j]).slice(0, 60)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Dashboards() {
  const [dashboards, setDashboards] = useState(null);
  const [rendered, setRendered] = useState(null);
  const [active, setActive] = useState(null);
  const [searches, setSearches] = useState([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const load = useCallback(() => {
    api.dashboards().then(setDashboards).catch((e) => setError(e.message));
    api.savedSearches().then((s) => setSearches(s.searches || [])).catch(() => {});
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const open = (d) => {
    setActive(d);
    setRendered(null);
    api
      .renderDashboard(d.id)
      .then(setRendered)
      .catch((e) => setError(e.message));
  };

  const addPanel = () => {
    setForm((f) => ({
      ...f,
      panels: [
        ...f.panels,
        { id: Math.random().toString(36).slice(2, 10), title: "", saved_search_id: null, query: "", viz: "table", field: "", limit: 10, cols: 2 },
      ],
    }));
  };

  const saveDashboard = () => {
    if (!form.name.trim()) {
      setError("Dashboard needs a name");
      return;
    }
    const panels = form.panels.map((p) => ({
      id: p.id,
      title: p.title || p.query?.split("|")[0].trim().slice(0, 48) || "Panel",
      saved_search_id: p.saved_search_id || null,
      query: p.query || null,
      viz: p.viz,
      field: p.field,
      limit: Number(p.limit) || 10,
      cols: Number(p.cols) || 2,
    }));
    setBusy(true);
    setError("");
    api
      .createDashboard({ name: form.name.trim(), description: form.description, panels })
      .then(() => {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
        setCreating(false);
        setForm({ ...EMPTY_FORM });
        load();
      })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(false));
  };

  const remove = (d) => {
    if (!window.confirm(`Delete dashboard "${d.name}"?`)) return;
    api
      .deleteDashboard(d.id)
      .then(() => {
        if (active?.id === d.id) {
          setActive(null);
          setRendered(null);
        }
        load();
      })
      .catch((e) => setError(e.message));
  };

  return (
    <div className="space-y-6">
      <div className="rounded-3xl border border-white/[0.06] bg-white/[0.025] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[24px] font-bold tracking-[-0.03em] text-white">Dashboards</h1>
            <p className="mt-1 text-[13px] font-normal tracking-[-0.003em] text-slate-400">
              Analyst-built panels from saved searches — table, count, top-N and trend visualizations.
            </p>
          </div>
          {isAdmin() && (
            <button
              onClick={() => setCreating((c) => !c)}
              className="rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-5 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)]"
            >
              {creating ? "Cancel" : "New Dashboard"}
            </button>
          )}
        </div>
      </div>

      {error && <ErrorBanner message={error} onDismiss={() => setError("")} />}

      {creating && isAdmin() && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <h3 className="mb-4 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-slate-400">
            <span className="h-1 w-1 rounded-full bg-cyan-400" />
            New Dashboard
          </h3>
          <div className="mb-4 grid gap-3 md:grid-cols-2">
            <label className="block">
              <span className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">Name</span>
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">Description</span>
              <input
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                className="w-full rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
              />
            </label>
          </div>
          <div className="space-y-3">
            {form.panels.map((p, i) => (
              <div key={p.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                <div className="grid gap-2 md:grid-cols-4">
                  <input
                    value={p.title}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        panels: f.panels.map((x, j) => (j === i ? { ...x, title: e.target.value } : x)),
                      }))
                    }
                    placeholder="Panel title"
                    className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  />
                  <select
                    value={p.saved_search_id || ""}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        panels: f.panels.map((x, j) => (j === i ? { ...x, saved_search_id: e.target.value ? Number(e.target.value) : null } : x)),
                      }))
                    }
                    className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  >
                    <option value="">Saved search…</option>
                    {searches.map((s) => (
                      <option key={s.id} value={s.id}>{s.name}</option>
                    ))}
                  </select>
                  <input
                    value={p.query}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        panels: f.panels.map((x, j) => (j === i ? { ...x, query: e.target.value } : x)),
                      }))
                    }
                    placeholder="…or inline query"
                    className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                  />
                  <div className="flex gap-2">
                    <select
                      value={p.viz}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          panels: f.panels.map((x, j) => (j === i ? { ...x, viz: e.target.value } : x)),
                        }))
                      }
                      className="rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                    >
                      {["table", "count", "top", "area"].map((v) => (
                        <option key={v} value={v}>{v}</option>
                      ))}
                    </select>
                    <input
                      value={p.field}
                      onChange={(e) =>
                        setForm((f) => ({
                          ...f,
                          panels: f.panels.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)),
                        }))
                      }
                      placeholder="field"
                      className="w-24 rounded-xl border border-white/[0.06] bg-white/[0.03] px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 outline-none transition-all focus:border-cyan-500/40 focus:ring-2 focus:ring-cyan-500/10"
                    />
                    <button
                      onClick={() =>
                        setForm((f) => ({ ...f, panels: f.panels.filter((_, j) => j !== i) }))
                      }
                      className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]"
                    >
                      ×
                    </button>
                  </div>
                </div>
              </div>
            ))}
            <button
              onClick={addPanel}
              className="rounded-xl border border-dashed border-white/[0.08] bg-white/[0.02] px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition-all hover:border-white/[0.14] hover:bg-white/[0.04]"
            >
              + Add panel
            </button>
          </div>
          <button
            onClick={saveDashboard}
            disabled={busy}
            className="mt-4 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.08] px-5 py-2.5 text-[13px] font-semibold text-cyan-400 transition-all hover:bg-cyan-500/[0.15] hover:shadow-[0_0_20px_-4px_rgba(0,240,255,0.2)] disabled:opacity-50"
          >
            {saved ? "Saved" : busy ? "Saving…" : "Create Dashboard"}
          </button>
        </div>
      )}

      {dashboards === null ? (
        <Loading />
      ) : dashboards.dashboards.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-white/[0.06] bg-white/[0.02] py-16 text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/[0.06] bg-white/[0.04] text-2xl text-slate-500">
            ◌
          </div>
          <p className="mt-4 text-sm font-semibold text-slate-300">No dashboards</p>
          <p className="mt-1 max-w-sm text-xs text-slate-500">
            Create a dashboard to pin saved searches as live panels — the enterprise SOC overview.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {dashboards.dashboards.map((d) => (
            <div
              key={d.id}
              className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-5 transition-all hover:border-white/[0.12] hover:bg-white/[0.035] hover:shadow-[0_8px_32px_-8px_rgba(0,0,0,0.4)]"
            >
              <div className="mb-3 h-0.5 w-full rounded-full bg-gradient-to-r from-cyan-500/40 via-violet-500/30 to-transparent" />
              <button onClick={() => open(d)} className="block w-full text-left">
                <span className="text-[13px] font-semibold text-white transition-colors hover:text-cyan-300">{d.name}</span>
                <span className="ml-2 text-[11px] text-slate-500">{d.panels.length} panel(s)</span>
              </button>
              <p className="mt-1 text-[12px] text-slate-400">{d.description || "No description."}</p>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => open(d)}
                  className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]"
                >
                  Open
                </button>
                {isAdmin() && (
                  <button
                    onClick={() => remove(d)}
                    className="rounded-xl border border-red-500/20 bg-red-500/[0.06] px-3 py-1.5 text-[11px] font-semibold text-red-300 transition-all hover:bg-red-500/[0.12]"
                  >
                    Delete
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {active && (
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-6">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-[15px] font-bold tracking-[-0.02em] text-white">{active.name}</h3>
              <p className="text-[12px] text-slate-400">{active.description}</p>
            </div>
            <button
              onClick={() => open(active)}
              disabled={busy}
              className="rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition-all hover:bg-white/[0.06]"
            >
              Refresh
            </button>
          </div>
          {rendered === null ? (
            <Loading label="Rendering panels" />
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              {rendered.panels.map((p) => (
                <div key={p.id} className="rounded-xl border border-white/[0.04] bg-white/[0.02] p-4">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="text-[13px] font-semibold text-slate-200">{p.title}</span>
                    <span className="text-[10px] text-slate-500">
                      {p.total} rows · {p.elapsed_ms} ms
                    </span>
                  </div>
                  <PanelCard panel={p} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="flex justify-center pt-4">
        <p className="text-[11px] font-medium text-slate-500/50">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}
