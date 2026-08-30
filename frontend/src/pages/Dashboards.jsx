import { memo, useCallback, useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, AreaChart, Area } from "recharts";
import { api, isAdmin } from "../api.js";
import ChartTooltip from "../components/ChartTooltip.jsx";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

function PanelCard({ panel }) {
  if (panel.error) {
    return (
      <div className="flex h-full items-center justify-center rounded-[var(--radius-xl)] border border-[var(--severity-critical-border)] bg-[var(--severity-critical)]/[0.04] p-4 text-[12px] text-[var(--severity-critical)]">
        {panel.error}
      </div>
    );
  }
  if (panel.viz === "count") {
    return (
      <div className="flex h-full flex-col items-center justify-center p-4">
        <span className="text-[36px] font-bold text-[var(--accent-violet)]">{panel.count ?? 0}</span>
        <span className="mt-1 text-[11px] uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Events</span>
      </div>
    );
  }
  if (panel.viz === "table" && panel.data?.length) {
    const columns = panel.columns || Object.keys(panel.data[0] || {});
    return (
      <div className="overflow-auto max-h-56">
        <table className="w-full text-left">
          <thead>
            <tr>
              {columns.map((col) => (
                <th key={col} className="px-3 py-2 text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {panel.data.map((row, i) => (
              <tr key={i} className="hover:bg-[var(--bg-surface-hover)] transition-colors">
                {columns.map((col) => (
                  <td key={col} className="px-3 py-2 text-[12px] text-[var(--fg-secondary)] border-b border-[var(--border-subtle)]">
                    {row[col] ?? "\u2014"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  if (panel.viz === "top" && panel.data?.length) {
    return (
      <div className="h-56 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={panel.data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
            <XAxis dataKey="name" stroke="var(--border-subtle)" tick={{ fontSize: 10, fill: "var(--fg-muted)" }} />
            <YAxis stroke="var(--border-subtle)" tick={{ fontSize: 10, fill: "var(--fg-muted)" }} />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="count" fill="var(--accent-violet)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    );
  }
  if (panel.viz === "timeseries" && panel.data?.length) {
    return (
      <div className="h-56 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={panel.data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
            <XAxis dataKey="name" stroke="var(--border-subtle)" tick={{ fontSize: 10, fill: "var(--fg-muted)" }} />
            <YAxis stroke="var(--border-subtle)" tick={{ fontSize: 10, fill: "var(--fg-muted)" }} />
            <Tooltip content={<ChartTooltip />} />
            <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.12} strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    );
  }
  return (
    <div className="flex h-full items-center justify-center py-12 text-[12px] text-[var(--fg-muted)]">
      No data
    </div>
  );
}

function Dashboards() {
  const [dashboards, setDashboards] = useState([]);
  const [selected, setSelected] = useState(null);
  const [panels, setPanels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingPanels, setLoadingPanels] = useState(false);
  const [error, setError] = useState("");

  const loadDashboards = useCallback(async () => {
    try {
      const res = await api.dashboards();
      const list = Array.isArray(res) ? res : (res?.items || res?.dashboards || []);
      setDashboards(list);
      setError("");
    } catch (err) {
      setDashboards([]);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDashboards(); }, [loadDashboards]);

  useEffect(() => {
    if (!selected) return;
    setLoadingPanels(true);
    api.renderDashboard(selected.id).then((res) => {
      setPanels(res?.panels || res?.items || []);
    }).catch(() => {
      setPanels([]);
    }).finally(() => setLoadingPanels(false));
  }, [selected]);

  if (loading) return <Loading label="Loading dashboards" />;
  if (error) return <ErrorBanner message={error} onRetry={loadDashboards} />;

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Dashboards"
        subtitle="Custom analytics and visualization panels"
        actions={isAdmin() ? <Button size="sm">+ New Dashboard</Button> : undefined}
      />

      <div className="flex gap-5">
        {/* Sidebar list */}
        <div className="w-56 shrink-0 space-y-1">
          {dashboards.map((d) => (
            <button
              key={d.id}
              onClick={() => setSelected(d)}
              className={`w-full rounded-[var(--radius-lg)] px-3 py-2 text-left text-[13px] transition-colors ${
                selected?.id === d.id
                  ? "bg-[var(--accent-cyan)]/[0.08] font-semibold text-[var(--accent-cyan)]"
                  : "text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)]"
              }`}
            >
              {d.name}
            </button>
          ))}
          {dashboards.length === 0 && (
            <p className="px-3 py-4 text-[12px] text-[var(--fg-muted)]">No dashboards</p>
          )}
        </div>

        {/* Main panel area */}
        <div className="min-w-0 flex-1">
          {selected ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-[18px] font-bold text-[var(--fg-primary)]">{selected.name}</h2>
                  {selected.description && (
                    <p className="mt-0.5 text-[12px] text-[var(--fg-muted)]">{selected.description}</p>
                  )}
                </div>
                {isAdmin() && (
                  <div className="flex gap-2">
                    <Button variant="secondary" size="xs">Edit</Button>
                    <Button variant="ghost" size="xs">Delete</Button>
                  </div>
                )}
              </div>

              {loadingPanels ? (
                <Loading label="Loading panels" />
              ) : (
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  {panels.map((panel, i) => (
                    <Card key={i} padding={false}>
                      <div className="px-4 pt-3 pb-1">
                        <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">{panel.title || panel.name || `Panel ${i + 1}`}</p>
                      </div>
                      <PanelCard panel={panel} />
                    </Card>
                  ))}
                  {panels.length === 0 && (
                    <Card>
                      <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No panels configured</div>
                    </Card>
                  )}
                </div>
              )}
            </div>
          ) : (
            <Card>
              <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">Select a dashboard</div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(Dashboards);
