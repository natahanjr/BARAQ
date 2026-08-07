import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "../api.js";
import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import { Loading, EmptyState, ErrorBanner } from "../components/Feedback.jsx";
import { NetworkIcon, RefreshIcon } from "../components/icons.jsx";

const KINDS = {
  user: { label: "User", color: "#38bdf8" },
  device: { label: "Device", color: "#818cf8" },
  process: { label: "Process", color: "#f472b6" },
  ip: { label: "IP", color: "#fb923c" },
  domain: { label: "Domain", color: "#34d399" },
  file: { label: "File", color: "#e879f9" },
  technique: { label: "Technique", color: "#a3e635" },
  threat_actor: { label: "Threat Actor", color: "#f87171" },
};

const RISK_COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#10b981",
};

const DEPTHS = [1, 2, 3];

function keyOf({ kind, name }) {
  return `${kind}:${name}`;
}

function radialLayout(nodes, edges, centerKey) {
  const pos = new Map([[centerKey, { x: 0, y: 0 }]]);
  const depth = new Map([[centerKey, 0]]);
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.source)) adj.set(e.source, []);
    if (!adj.has(e.target)) adj.set(e.target, []);
    adj.get(e.source).push(e.target);
    adj.get(e.target).push(e.source);
  }
  const queue = [centerKey];
  while (queue.length) {
    const cur = queue.shift();
    const d = depth.get(cur) ?? 0;
    for (const nb of adj.get(cur) || []) {
      if (pos.has(nb)) continue;
      depth.set(nb, d + 1);
      queue.push(nb);
    }
  }
  const levels = new Map();
  for (const n of nodes) {
    const d = depth.get(n.id) ?? 1;
    if (!levels.has(d)) levels.set(d, []);
    levels.get(d).push(n.id);
  }
  for (const [d, ids] of levels) {
    if (d === 0) continue;
    const R = 165 * d;
    ids.forEach((id, i) => {
      const angle = (i / ids.length) * Math.PI * 2 - Math.PI / 2;
      pos.set(id, { x: R * Math.cos(angle), y: R * Math.sin(angle) });
    });
  }
  return pos;
}

function EntityNodeWidget({ data, selected }) {
  const meta = KINDS[data.kind] || { label: data.kind, color: "#64748b" };
  const riskColor = RISK_COLORS[data.risk_level] || "#64748b";
  const size = Math.min(64, data.risk_score || 16);

  return (
    <div
      className="relative w-[168px] rounded-lg border bg-slate-900/90 px-2.5 py-2 shadow-[0_12px_30px_-12px_rgba(2,6,23,0.9)] backdrop-blur transition-shadow hover:shadow-cyan-500/10"
      style={{
        borderColor: selected ? "#22d3ee" : riskColor,
        outline: selected ? "2px solid rgba(34,211,238,0.35)" : "none",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: "#475569" }} />
      <Handle type="source" position={Position.Right} style={{ background: "#475569" }} />
      <div className="flex items-center justify-between gap-2">
        <span
          className="flex h-5 w-5 items-center justify-center rounded text-[10px] font-bold text-slate-950"
          style={{ backgroundColor: meta.color }}
        >
          {meta.label.slice(0, 1)}
        </span>
        <span className="font-mono text-[10px] font-semibold text-slate-400">
          {data.risk_score?.toFixed(0) ?? "—"}
        </span>
      </div>
      <p className="mt-1.5 truncate text-xs font-medium text-slate-100" title={data.name}>
        {data.name}
      </p>
      <div className="mt-1.5 flex items-center justify-between text-[9px] text-slate-500">
        <span className="uppercase tracking-wider">{meta.label}</span>
        <span>
          <span className="text-cyan-400">{data.alerts_count}</span> a ·{" "}
          <span className="text-slate-400">{data.events_count}</span> e
        </span>
      </div>
      <div className="mt-1 h-[3px] overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full"
          style={{ backgroundColor: riskColor, width: `${size + 18}%` }}
        />
      </div>
    </div>
  );
}

const NODE_TYPES = { entity: EntityNodeWidget };

function GraphCanvas({ nodes, edges, onNodeClick }) {
  const { fitView } = useReactFlow();

  useEffect(() => {
    fitView({ padding: 0.2, duration: 400 });
  }, [nodes, edges, fitView]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      onNodeClick={(_, node) => onNodeClick(node.id)}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.15}
      maxZoom={2.5}
      colorMode="dark"
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={24} color="#1e293b" />
      <Controls showInteractive={false} />
      <MiniMap
        pannable
        zoomable
        nodeColor={(node) =>
          RISK_COLORS[node.data.risk_level] || "#334155"
        }
        maskColor="rgba(2,6,23,0.75)"
        style={{ backgroundColor: "#0f172a" }}
      />
    </ReactFlow>
  );
}

function RiskRing({ score, level }) {
  const clamped = Math.max(0, Math.min(100, score ?? 0));
  const r = 32;
  const c = 2 * Math.PI * r;
  const color = RISK_COLORS[level] || RISK_COLORS.LOW;
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r={r} fill="none" stroke="var(--chart-track)" strokeWidth="7" />
        <circle
          cx="40"
          cy="40"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c - (clamped / 100) * c}
          transform="rotate(-90 40 40)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute text-center">
        <span className="block text-xl font-bold text-slate-100">{clamped.toFixed(0)}</span>
        <span className="block text-[8px] uppercase tracking-widest text-slate-500">Risk</span>
      </div>
    </div>
  );
}

function PropertyRow({ k, v }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-800/50 py-1.5 text-xs last:border-0">
      <span className="shrink-0 text-slate-500">{k}</span>
      <span className="min-w-0 truncate text-right font-mono text-slate-200" title={String(v)}>
        {String(v)}
      </span>
    </div>
  );
}

export default function EntityGraph() {
  const [status, setStatus] = useState(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [graphKey, setGraphKey] = useState(null);
  const [depth, setDepth] = useState(2);
  const [search, setSearch] = useState("");
  const [searchKind, setSearchKind] = useState("auto");
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState("");

  const [selected, setSelected] = useState(null);
  const [profile, setProfile] = useState(null);
  const [profileError, setProfileError] = useState("");

  const applyGraph = useCallback((data, centerKey) => {
    const gf = data.nodes || [];
    const ge = data.edges || [];
    const layout = radialLayout(
      gf.map((n) => ({ ...n, id: keyOf(n) })),
      ge.map((e) => ({ source: keyOf(e.source), target: keyOf(e.target) })),
      centerKey,
    );
    setNodes(
      gf.map((n) => ({
        id: keyOf(n),
        type: "entity",
        position: layout.get(keyOf(n)) || { x: 0, y: 0 },
        data: n,
      })),
    );
    setEdges(
      ge.map((e) => {
        const source = keyOf(e.source);
        const target = keyOf(e.target);
        return {
          id: `${source}-${e.rel}-${target}`,
          source,
          target,
          type: "smoothstep",
          label: String(e.rel).toUpperCase(),
          labelBgStyle: { fill: "#0f172a", fillOpacity: 0.8 },
          labelStyle: { fontSize: 9, fill: "#94a3b8" },
          markerEnd: { type: MarkerType.ArrowClosed, color: "#334155" },
          style: { stroke: "#334155", strokeWidth: 1.2 },
        };
      }),
    );
  }, []);

  const loadGraph = useCallback(
    (kind, name) => {
      setError("");
      return api
        .entityGraph(kind, name, depth)
        .then((data) => {
          applyGraph(data, keyOf({ kind, name }));
          setGraphKey(`${kind}:${name}`);
        })
        .catch((e) => setError(e.message));
    },
    [depth, applyGraph],
  );

  const focusAuto = useCallback(
    (name) => {
      const order = ["ip", "device", "user", "domain", "process", "file", "technique"];
      const attempt = (i) => {
        if (i >= order.length) {
          setError(`No entity matching "${name}"`);
          return Promise.resolve();
        }
        return api
          .entityGraph(order[i], name, depth)
          .then((data) => {
            applyGraph(data, keyOf({ kind: order[i], name }));
            setGraphKey(`${order[i]}:${name}`);
          })
          .catch(() => attempt(i + 1));
      };
      return attempt(0);
    },
    [depth, applyGraph],
  );

  const load = useCallback(() => {
    setLoading(true);
    api
      .entityStatus()
      .then(async (st) => {
        setStatus(st);
        const top = st.top_risk && st.top_risk[0];
        if (top) {
          await loadGraph(top.kind, top.name);
        } else {
          const ov = await api.entityOverview(depth);
          applyGraph(ov, null);
          setGraphKey(null);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [loadGraph, applyGraph, depth]);

  useEffect(() => {
    load();
  }, [load]);

  const handleSearch = () => {
    const name = search.trim();
    if (!name) return;
    setError("");
    if (searchKind === "auto") focusAuto(name);
    else loadGraph(searchKind, name);
  };

  const handleSync = () => {
    setSyncing(true);
    api
      .syncEntities()
      .then(() => load())
      .catch((e) => setError(e.message))
      .finally(() => setSyncing(false));
  };

  const openProfile = useCallback((nodeId) => {
    const sep = nodeId.indexOf(":");
    const [kind, name] = [nodeId.slice(0, sep), nodeId.slice(sep + 1)];
    setSelected(nodeId);
    setProfile(null);
    setProfileError("");
    api
      .entityProfile(kind, name, 2)
      .then(setProfile)
      .catch((e) => setProfileError(e.message));
  }, []);

  const neighbors = [];
  if (profile?.subgraph?.edges && selected) {
    for (const e of profile.subgraph.edges) {
      const s = keyOf(e.source);
      const t = keyOf(e.target);
      if (s === selected && t !== selected) neighbors.push({ other: e.target, rel: e.rel, dir: "→" });
      else if (t === selected && s !== selected)
        neighbors.push({ other: e.source, rel: e.rel, dir: "←" });
      else if (s === selected && t === selected)
        neighbors.push({ other: e.target, rel: e.rel, dir: "↔" });
    }
  }

  const entity = profile?.entity;

  const byKind = status?.by_kind ? Object.entries(status.by_kind).sort((a, b) => b[1] - a[1]) : [];
  const kindChips = byKind
    .filter(([, c]) => c > 0)
    .map(([k, c]) => ({ kind: k, count: c }));

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Entity Intelligence"
        subtitle="Attack-surface graph linking users, devices, processes and indicators"
        actions={
          <div className="flex items-center gap-3">
            {status && (
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 font-mono text-[11px] text-cyan-300">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                {status.provider} · {status.total_entities.toLocaleString()} entities ·{" "}
                {status.total_edges.toLocaleString()} links
              </span>
            )}
            <button
              type="button"
              onClick={() => load()}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/[0.08]"
            >
              <RefreshIcon className="h-4 w-4" />
              Refresh
            </button>
            <button
              type="button"
              onClick={handleSync}
              disabled={syncing}
              className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:bg-white/[0.08] disabled:opacity-50"
            >
              <NetworkIcon className="h-4 w-4" />
              {syncing ? "Rebuilding…" : "Rebuild graph"}
            </button>
          </div>
        }
      />

      {/* Kind legend + entity search + depth */}
      <Card pad={false} className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {kindChips.map((k) => (
              <button
                key={k.kind}
                type="button"
                onClick={() => {
                  setSearchKind(k.kind);
                  setSearch("");
                  const top = status?.top_risk?.[0];
                  if (top && top.kind === k.kind && top.name) {
                    loadGraph(k.kind, top.name);
                  } else {
                    api.entities({ kind: k.kind, limit: 1 }).then((res) => {
                      const first = res.items && res.items[0];
                      if (first && first.name) loadGraph(k.kind, first.name);
                    });
                  }
                }}
                className="rounded-md border border-slate-700/60 bg-slate-900/40 px-2.5 py-1 text-[11px] text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200"
              >
                <span className="font-semibold" style={{ color: KINDS[k.kind]?.color || "#64748b" }}>
                  {k.kind}
                </span>{" "}
                {k.count.toLocaleString()}
              </button>
            ))}
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <span className="text-[11px] uppercase tracking-wider text-slate-500">Focus depth</span>
            {DEPTHS.map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => setDepth(d)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  depth === d
                    ? "bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/40"
                    : "bg-slate-900/40 text-slate-400 hover:text-slate-200"
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <select
            value={searchKind}
            onChange={(e) => setSearchKind(e.target.value)}
            className="rounded-lg border border-slate-700/60 bg-slate-900/70 px-2.5 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500/50"
          >
            <option value="auto">Auto-detect kind</option>
            {Object.entries(KINDS).map(([v, m]) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="Search IP, user, host, hash, domain…"
            className="w-full max-w-md rounded-lg border border-slate-700/60 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-500/50"
          />
          <button
            type="button"
            onClick={handleSearch}
            className="rounded-lg bg-cyan-500/15 px-3.5 py-1.5 text-xs font-semibold text-cyan-300 ring-1 ring-cyan-500/40 transition-colors hover:bg-cyan-500/25"
          >
            Focus entity
          </button>
          {graphKey && (
            <button
              type="button"
              onClick={() =>
                api.entityOverview(depth).then((ov) => {
                  applyGraph(ov, null);
                  setGraphKey(null);
                })
              }
              className="rounded-lg px-3 py-1.5 text-xs font-medium text-slate-400 transition-colors hover:text-slate-200"
            >
              Overview
            </button>
          )}
        </div>
      </Card>

      {error && !loading && (
        <ErrorBanner message={error} onRetry={load} />
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_360px]">
        {/* Canvas */}
        <Card pad={false} className="h-[620px] overflow-hidden lg:h-[720px]">
          {loading ? (
            <Loading label="Building entity graph" />
          ) : nodes.length === 0 ? (
            <EmptyState
              title="Graph is empty"
              subtitle="Run Rebuild graph to extract entities from telemetry"
              icon="◌"
            />
          ) : (
            <ReactFlowProvider>
              <GraphCanvas nodes={nodes} edges={edges} onNodeClick={openProfile} />
            </ReactFlowProvider>
          )}
        </Card>

        {/* Profile panel */}
        <div className="space-y-4">
          {!selected && (
            <Card>
              <div className="flex items-center gap-3">
                <NetworkIcon className="h-7 w-7 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-semibold text-white">Investigate an entity</h3>
                  <p className="mt-0.5 text-xs text-slate-400">
                    Click any node to open its intelligence profile — risk, relationships,
                    linked alerts and telemetry footprint.
                  </p>
                </div>
              </div>
            </Card>
          )}

          {selected && profileError && <ErrorBanner message={profileError} />}
          {selected && profile && (
            <Card>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    {KINDS[entity.kind]?.label || entity.kind}
                  </p>
                  <h3 className="mt-0.5 truncate text-base font-semibold text-white" title={entity.name}>
                    {entity.name}
                  </h3>
                  <div className="mt-1.5 flex items-center gap-2">
                    <RiskBadge level={entity.risk_level} />
                    <span className="text-[11px] text-slate-500">
                      {entity.events_count} events · {entity.alerts_count} alerts
                    </span>
                  </div>
                </div>
                <RiskRing score={entity.risk_score} level={entity.risk_level} />
              </div>

              {Object.keys(entity.properties || {}).length > 0 && (
                <div className="mt-4">
                  <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    Properties
                  </h4>
                  <div className="rounded-lg border border-slate-800/60 bg-slate-950/40 px-3 py-1">
                    {Object.entries(entity.properties).map(([k, v]) => (
                      <PropertyRow key={k} k={k} v={v} />
                    ))}
                  </div>
                </div>
              )}

              {neighbors.length > 0 && (
                <div className="mt-4">
                  <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    Relationships
                  </h4>
                  <div className="space-y-1.5">
                    {neighbors.slice(0, 10).map((n, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => openProfile(keyOf(n.other))}
                        className="flex w-full items-center justify-between gap-2 rounded-lg border border-slate-800/60 bg-slate-900/40 px-2.5 py-1.5 text-left transition-colors hover:border-cyan-500/40"
                      >
                        <span className="truncate font-mono text-xs text-slate-200">
                          {n.dir}{" "}
                          <span style={{ color: KINDS[n.other.kind]?.color || "#64748b" }}>
                            {n.other.kind}
                          </span>
                        </span>
                        <span className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-cyan-400">{n.rel}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {entity.alerts_count > 0 && profile.related_alerts && profile.related_alerts.length > 0 && (
                <div className="mt-4">
                  <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                    Linked alerts
                  </h4>
                  <div className="space-y-1.5">
                    {profile.related_alerts.slice(0, 5).map((a) => (
                      <Link
                        key={a.id}
                        to={`/alerts/${a.id}`}
                        className="block rounded-lg border border-slate-800/60 bg-slate-900/40 px-2.5 py-1.5 transition-colors hover:border-slate-600"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-xs text-slate-200">{a.name}</span>
                          <span className="shrink-0 rounded border border-white/5 bg-black/30 px-1.5 font-mono text-[9px] text-slate-400">
                            {a.risk_score?.toFixed(0) ?? a.severity ?? ""}
                          </span>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {entity.first_seen && (
                <p className="mt-4 text-[10px] text-slate-600">
                  First seen {new Date(entity.first_seen).toLocaleString()} · Last seen{" "}
                  {new Date(entity.last_seen).toLocaleString()}
                </p>
              )}
            </Card>
          )}
          {selected && !profile && !profileError && <Loading label="Loading profile" />}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
        <span className="uppercase tracking-wider">Node kinds</span>
        {Object.entries(KINDS).map(([k, m]) => (
          <span key={k} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: m.color }} />
            {m.label}
          </span>
        ))}
        <span className="ml-2 inline-flex items-center gap-1.5 font-mono">a=alerts · e=events</span>
      </div>
    </div>
  );
}