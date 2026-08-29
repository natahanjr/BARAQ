import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Tabs, MetricCard, SearchInput, FilterBar, Button, Drawer, Tooltip, SkeletonTable } from "../components/ui/index.js";
import { useToast } from "../components/ui/Toast.jsx";

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

const STATE_COLORS = {
  ESTABLISHED: "var(--status-healthy)",
  LISTEN: "var(--accent-cyan)",
  SYN_SENT: "var(--severity-medium)",
  TIME_WAIT: "var(--accent-violet)",
  CLOSE_WAIT: "var(--severity-high)",
  "": "var(--fg-muted)",
};

const METHOD_COLORS = {
  GET: "var(--status-healthy)",
  POST: "var(--accent-cyan)",
  PUT: "var(--severity-medium)",
  DELETE: "var(--severity-critical)",
  PATCH: "var(--accent-violet)",
  HEAD: "var(--fg-muted)",
  OPTIONS: "var(--fg-muted)",
};

const HTTP_STATUS_COLORS = {
  2: "var(--status-healthy)",
  3: "var(--accent-cyan)",
  4: "var(--severity-high)",
  5: "var(--severity-critical)",
};

const PORT_LABELS = {
  20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
  53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
  443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
  8001: "BARAQ", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
};

const TABS = [
  { id: "topology", label: "Topology" },
  { id: "connections", label: "Connections" },
  { id: "dns", label: "DNS" },
  { id: "http", label: "HTTP" },
  { id: "analytics", label: "Analytics" },
];

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

function fmtBytes(b) {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = b;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function fmtDuration(s) {
  if (!s || s <= 0) return "—";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function isPrivateIP(ip) {
  if (!ip) return false;
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)/.test(ip);
}

function classifyIP(ip) {
  if (!ip) return "unknown";
  if (ip === "127.0.0.1" || ip === "::1") return "loopback";
  if (isPrivateIP(ip)) return "internal";
  return "external";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Network Topology (ReactFlow-compatible SVG)
 * ═══════════════════════════════════════════════════════════════════════════ */

function NetworkTopology({ connections, onNodeClick, onConnectionClick }) {
  const svgRef = useRef(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0 });

  // Build nodes from connections
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map();
    const edgeList = [];

    // Add "Internet" node
    nodeMap.set("INTERNET", { id: "INTERNET", label: "INTERNET", type: "internet", x: 400, y: 40, risk: 0 });

    connections.forEach((conn) => {
      const src = conn.local_ip || "unknown";
      const dst = conn.remote_ip;
      if (!dst) return;

      // Source node
      if (!nodeMap.has(src)) {
        nodeMap.set(src, {
          id: src,
          label: src,
          type: isPrivateIP(src) ? "host" : "ip",
          x: 200 + Math.random() * 200,
          y: 200 + Math.random() * 100,
          risk: 0,
          connections: 0,
        });
      }
      const srcNode = nodeMap.get(src);
      srcNode.connections = (srcNode.connections || 0) + 1;

      // Destination node
      if (!nodeMap.has(dst)) {
        nodeMap.set(dst, {
          id: dst,
          label: dst,
          type: isPrivateIP(dst) ? "host" : "ip",
          x: 400 + Math.random() * 200,
          y: 200 + Math.random() * 100,
          risk: 0,
          connections: 0,
        });
      }
      const dstNode = nodeMap.get(dst);
      dstNode.connections = (dstNode.connections || 0) + 1;

      // Edge
      edgeList.push({
        id: `${src}-${dst}`,
        source: src,
        target: dst,
        label: `${conn.state || "TCP"} ${conn.remote_port || ""}`,
        port: conn.remote_port,
        state: conn.state,
        bytes: (conn.bytes_sent || 0) + (conn.bytes_recv || 0),
        connection: conn,
      });
    });

    return { nodes: Array.from(nodeMap.values()), edges: edgeList };
  }, [connections]);

  // Auto-layout: simple force-directed (one pass)
  const layoutNodes = useMemo(() => {
    const n = nodes.map((nd) => ({ ...nd }));
    const map = new Map(n.map((nd) => [nd.id, nd]));
    // Simple layout: internet at top, hosts in middle, IPs at right
    n.forEach((nd) => {
      if (nd.type === "internet") { nd.x = 400; nd.y = 40; }
      else if (nd.type === "host") { nd.x = 200 + Math.random() * 200; nd.y = 180 + Math.random() * 80; }
      else { nd.x = 450 + Math.random() * 150; nd.y = 180 + Math.random() * 80; }
    });
    return n;
  }, [nodes]);

  const nodeColor = (nd) => {
    if (nd.type === "internet") return "var(--fg-muted)";
    if (nd.risk >= 80) return "var(--severity-critical)";
    if (nd.risk >= 60) return "var(--severity-high)";
    if (nd.risk >= 40) return "var(--severity-medium)";
    return "var(--status-healthy)";
  };

  const handleMouseDown = (e) => {
    if (e.target === svgRef.current || e.target.tagName === "rect") {
      setDragging(true);
      dragStart.current = { x: e.clientX - transform.x, y: e.clientY - transform.y };
    }
  };

  const handleMouseMove = (e) => {
    if (!dragging) return;
    setTransform((t) => ({ ...t, x: e.clientX - dragStart.current.x, y: e.clientY - dragStart.current.y }));
  };

  const handleMouseUp = () => setDragging(false);

  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform((t) => ({ ...t, scale: Math.max(0.3, Math.min(3, t.scale * delta)) }));
  };

  const nodeMap = new Map(layoutNodes.map((nd) => [nd.id, nd]));

  return (
    <div className="relative w-full overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-inset)]" style={{ height: 400 }}>
      {/* Controls */}
      <div className="absolute right-3 top-3 z-10 flex gap-1.5">
        <button onClick={() => setTransform((t) => ({ ...t, scale: Math.min(3, t.scale * 1.2) }))} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Zoom in">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M8 3v10M3 8h10" /></svg>
        </button>
        <button onClick={() => setTransform((t) => ({ ...t, scale: Math.max(0.3, t.scale * 0.8) }))} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Zoom out">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 8h10" /></svg>
        </button>
        <button onClick={() => setTransform({ x: 0, y: 0, scale: 1 })} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Reset view">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3h10v10H3z" /></svg>
        </button>
      </div>

      {/* Legend */}
      <div className="absolute left-3 top-3 z-10 flex flex-col gap-1 rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)]/90 px-2.5 py-2 text-[10px]">
        {[
          ["Host", "var(--status-healthy)"],
          ["External IP", "var(--accent-cyan)"],
          ["Internet", "var(--fg-muted)"],
        ].map(([label, color]) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: color }} />
            <span className="text-[var(--fg-muted)]">{label}</span>
          </div>
        ))}
      </div>

      <svg
        ref={svgRef}
        className="w-full h-full"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        style={{ cursor: dragging ? "grabbing" : "grab" }}
      >
        <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}>
          {/* Edges */}
          {edges.map((edge) => {
            const src = nodeMap.get(edge.source);
            const tgt = nodeMap.get(edge.target);
            if (!src || !tgt) return null;
            return (
              <g key={edge.id} onClick={() => onConnectionClick?.(edge)} className="cursor-pointer">
                <line
                  x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                  stroke="var(--border-default)" strokeWidth="1.5"
                  className="transition-colors hover:stroke-[var(--accent-cyan)]"
                />
                <text
                  x={(src.x + tgt.x) / 2} y={(src.y + tgt.y) / 2 - 4}
                  textAnchor="middle" className="fill-[var(--fg-faint)] text-[8px] font-mono pointer-events-none"
                >
                  {edge.label}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {layoutNodes.map((nd) => (
            <g key={nd.id} onClick={() => onNodeClick?.(nd)} className="cursor-pointer">
              {nd.type === "internet" ? (
                <>
                  <rect x={nd.x - 30} y={nd.y - 14} width={60} height={28} rx={6} fill="var(--bg-surface)" stroke="var(--border-default)" strokeWidth="1.5" />
                  <text x={nd.x} y={nd.y + 4} textAnchor="middle" className="fill-[var(--fg-muted)] text-[9px] font-semibold">INTERNET</text>
                </>
              ) : (
                <>
                  <circle cx={nd.x} cy={nd.y} r={16} fill="var(--bg-surface)" stroke={nodeColor(nd)} strokeWidth="2" />
                  <text x={nd.x} y={nd.y + 3} textAnchor="middle" className="fill-[var(--fg-primary)] text-[8px] font-mono font-bold">
                    {nd.label.length > 8 ? nd.label.slice(0, 8) + "…" : nd.label}
                  </text>
                  {nd.connections > 1 && (
                    <text x={nd.x} y={nd.y + 26} textAnchor="middle" className="fill-[var(--fg-faint)] text-[7px]">
                      {nd.connections} conns
                    </text>
                  )}
                </>
              )}
            </g>
          ))}
        </g>
      </svg>

      {connections.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center">
          <p className="text-[13px] text-[var(--fg-muted)]">No network connections to display</p>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Node Inspector
 * ═══════════════════════════════════════════════════════════════════════════ */

function NodeInspector({ node, connections, onClose, navigate, toast }) {
  if (!node) return null;

  const relatedConns = connections.filter(
    (c) => c.local_ip === node.id || c.remote_ip === node.id
  );
  const uniquePeers = new Set(relatedConns.map((c) => c.local_ip === node.id ? c.remote_ip : c.local_ip));
  const totalBytes = relatedConns.reduce((s, c) => s + (c.bytes_sent || 0) + (c.bytes_recv || 0), 0);
  const classification = classifyIP(node.id);
  const ip = node.id;

  return (
    <Drawer open={!!node} onClose={onClose} title="Node Inspector" width={360}>
      <div className="space-y-5">
        {/* Header */}
        <div>
          <p className="font-mono text-[15px] font-bold text-[var(--fg-primary)]">{node.label}</p>
          <div className="mt-1 flex items-center gap-2">
            <Badge severity={node.type === "host" ? "info" : "low"} size="sm">{node.type.toUpperCase()}</Badge>
            <Badge severity={classification === "external" ? "medium" : "info"} size="sm">{classification}</Badge>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Connections</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{relatedConns.length}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Bytes</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{fmtBytes(totalBytes)}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Unique Peers</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{uniquePeers.size}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Risk Score</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{node.risk || 0}</p>
          </div>
        </div>

        {/* Recent Connections */}
        <div>
          <h4 className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-2">Recent Connections</h4>
          <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
            {relatedConns.slice(0, 10).map((c) => (
              <div key={c.id} className="flex items-center gap-2 rounded-[var(--radius-md)] px-2 py-1.5 text-[11px]">
                <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: STATE_COLORS[c.state] || "var(--fg-muted)" }} />
                <span className="font-mono text-[var(--fg-secondary)] truncate">{c.remote_ip}:{c.remote_port}</span>
                <span className="ml-auto text-[var(--fg-muted)]">{c.state}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" className="flex-1" onClick={() => { onClose(); navigate(`/alerts?search=${encodeURIComponent(ip)}`); }}>Investigate</Button>
          <Button variant="danger-ghost" size="sm" onClick={async () => {
            if (!confirm(`Block IP ${ip}?`)) return;
            try {
              await api.request("/api/alerts/suppressions", { method: "POST", body: JSON.stringify({ rule: ip, reason: "Manual block from Network Analyzer", expires_hours: 24 }) });
              toast({ title: `IP ${ip} blocked`, type: "success" });
            } catch (e) { toast({ title: "Block failed", description: e.message, type: "error" }); }
          }}>Block IP</Button>
        </div>
      </div>
    </Drawer>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection Inspector
 * ═══════════════════════════════════════════════════════════════════════════ */

function ConnectionInspector({ edge, onClose, navigate, toast }) {
  if (!edge?.connection) return null;
  const conn = edge.connection;
  const ip = conn.remote_ip;

  return (
    <Drawer open={!!edge} onClose={onClose} title="Connection Inspector" width={360}>
      <div className="space-y-5">
        {/* Header */}
        <div>
          <div className="flex items-center gap-2 font-mono text-[13px]">
            <span className="text-[var(--fg-primary)] font-semibold">{conn.local_ip}</span>
            <span className="text-[var(--fg-muted)]">→</span>
            <span className="text-[var(--fg-primary)] font-semibold">{conn.remote_ip}</span>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <Badge severity="info" size="sm">{conn.state || "TCP"}</Badge>
            {conn.remote_port && <Badge severity="low" size="sm">:{conn.remote_port}</Badge>}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Bytes Sent</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{fmtBytes(conn.bytes_sent)}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Bytes Recv</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{fmtBytes(conn.bytes_recv)}</p>
          </div>
        </div>

        {/* Details */}
        <div className="space-y-2">
          {[
            ["Process", conn.process || "—"],
            ["PID", conn.pid || "—"],
            ["Local Port", conn.local_port || "—"],
            ["Duration", fmtDuration(conn.duration_seconds)],
            ["Observed", fmtDate(conn.observed_at)],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center justify-between py-1.5 border-b border-[var(--border-subtle)] last:border-0">
              <span className="text-[12px] text-[var(--fg-muted)]">{k}</span>
              <span className="text-[12px] font-mono text-[var(--fg-primary)]">{v}</span>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" className="flex-1" onClick={() => { onClose(); navigate(`/alerts?search=${encodeURIComponent(ip)}`); }}>Investigate</Button>
          <Button variant="danger-ghost" size="sm" onClick={async () => {
            if (!confirm(`Block IP ${ip}?`)) return;
            try {
              await api.request("/api/alerts/suppressions", { method: "POST", body: JSON.stringify({ rule: ip, reason: "Manual block from Network Analyzer", expires_hours: 24 }) });
              toast({ title: `IP ${ip} blocked`, type: "success" });
            } catch (e) { toast({ title: "Block failed", description: e.message, type: "error" }); }
          }}>Block IP</Button>
        </div>
      </div>
    </Drawer>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection Table
 * ═══════════════════════════════════════════════════════════════════════════ */

function ConnectionTable({ connections, onSelect }) {
  const [sortKey, setSortKey] = useState("observed_at");
  const [sortDir, setSortDir] = useState("desc");

  const sorted = useMemo(() => {
    return [...connections].sort((a, b) => {
      const aVal = a[sortKey] ?? "";
      const bVal = b[sortKey] ?? "";
      const cmp = typeof aVal === "number" ? aVal - bVal : String(aVal).localeCompare(String(bVal));
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [connections, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  const SortHeader = ({ field, children }) => (
    <th
      onClick={() => toggleSort(field)}
      className="cursor-pointer select-none hover:text-[var(--fg-secondary)] transition-colors"
    >
      <span className="flex items-center gap-1">
        {children}
        {sortKey === field && <span className="text-[var(--fg-faint)]">{sortDir === "asc" ? "↑" : "↓"}</span>}
      </span>
    </th>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr>
            <SortHeader field="local_ip">Source</SortHeader>
            <SortHeader field="remote_ip">Destination</SortHeader>
            <SortHeader field="remote_port">Port</SortHeader>
            <SortHeader field="state">State</SortHeader>
            <SortHeader field="bytes_sent">Bytes</SortHeader>
            <SortHeader field="process">Process</SortHeader>
            <SortHeader field="observed_at">Last Seen</SortHeader>
          </tr>
        </thead>
        <tbody>
          {sorted.map((conn) => (
            <tr
              key={conn.id}
              onClick={() => onSelect?.(conn)}
              className="cursor-pointer hover:bg-[var(--bg-surface-hover)] transition-colors"
            >
              <td className="font-mono text-[12px] text-[var(--fg-secondary)]">{conn.local_ip || "—"}</td>
              <td className="font-mono text-[12px] text-[var(--fg-primary)]">{conn.remote_ip || "—"}</td>
              <td className="font-mono text-[12px]">
                <span className="text-[var(--fg-muted)]">{conn.remote_port || "—"}</span>
                {PORT_LABELS[conn.remote_port] && (
                  <span className="ml-1 text-[10px] text-[var(--fg-faint)]">{PORT_LABELS[conn.remote_port]}</span>
                )}
              </td>
              <td>
                <span className="inline-flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: STATE_COLORS[conn.state] || "var(--fg-muted)" }} />
                  <span className="text-[11px] text-[var(--fg-secondary)]">{conn.state || "—"}</span>
                </span>
              </td>
              <td className="text-[11px] text-[var(--fg-muted)]">
                {conn.bytes_sent || conn.bytes_recv ? fmtBytes((conn.bytes_sent || 0) + (conn.bytes_recv || 0)) : "—"}
              </td>
              <td className="text-[11px] text-[var(--fg-secondary)] max-w-[120px] truncate">{conn.process || "—"}</td>
              <td className="text-[11px] text-[var(--fg-muted)]">{fmtDate(conn.observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length === 0 && (
        <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No connections found</div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DNS Table
 * ═══════════════════════════════════════════════════════════════════════════ */

function DNSTable({ queries }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr>
            <th>Time</th>
            <th>Query</th>
            <th>Response</th>
            <th>Process</th>
          </tr>
        </thead>
        <tbody>
          {queries.map((q) => (
            <tr key={q.id} className="hover:bg-[var(--bg-surface-hover)] transition-colors">
              <td className="text-[11px] text-[var(--fg-muted)]">{fmtDate(q.observed_at)}</td>
              <td className="font-mono text-[12px] text-[var(--accent-cyan)]">{q.query || "—"}</td>
              <td className="font-mono text-[12px] text-[var(--fg-secondary)]">{q.response || "—"}</td>
              <td className="text-[11px] text-[var(--fg-secondary)] max-w-[120px] truncate">{q.process || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {queries.length === 0 && (
        <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No DNS queries found</div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HTTP Table
 * ═══════════════════════════════════════════════════════════════════════════ */

function HTTPTable({ requests }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead>
          <tr>
            <th>Time</th>
            <th>Method</th>
            <th>Host</th>
            <th>Status</th>
            <th>Process</th>
          </tr>
        </thead>
        <tbody>
          {requests.map((r) => (
            <tr key={r.id} className="hover:bg-[var(--bg-surface-hover)] transition-colors">
              <td className="text-[11px] text-[var(--fg-muted)]">{fmtDate(r.observed_at)}</td>
              <td>
                <span className="font-mono text-[11px] font-semibold" style={{ color: METHOD_COLORS[r.method] || "var(--fg-muted)" }}>
                  {r.method || "—"}
                </span>
              </td>
              <td className="font-mono text-[12px] text-[var(--fg-secondary)] max-w-[200px] truncate">{r.host || "—"}</td>
              <td>
                <span className="font-mono text-[11px] font-semibold" style={{ color: HTTP_STATUS_COLORS[Math.floor((r.status_code || 0) / 100)] || "var(--fg-muted)" }}>
                  {r.status_code || "—"}
                </span>
              </td>
              <td className="text-[11px] text-[var(--fg-secondary)] max-w-[120px] truncate">{r.process || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {requests.length === 0 && (
        <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No HTTP requests found</div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Analytics View
 * ═══════════════════════════════════════════════════════════════════════════ */

function AnalyticsView({ stats }) {
  if (!stats) return <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No analytics data available</div>;

  const BarList = ({ items, labelKey, countKey, color }) => {
    const max = Math.max(...items.map((i) => i[countKey] || 0), 1);
    return (
      <div className="space-y-2">
        {items.slice(0, 8).map((item) => (
          <div key={item[labelKey]} className="flex items-center gap-3">
            <span className="w-[140px] truncate text-[11px] font-mono text-[var(--fg-secondary)]" title={String(item[labelKey])}>
              {item[labelKey]}
            </span>
            <div className="flex-1 h-4 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
              <div className="h-full rounded-full transition-all duration-500" style={{ width: `${((item[countKey] || 0) / max) * 100}%`, background: color }} />
            </div>
            <span className="w-[40px] text-right text-[11px] font-semibold text-[var(--fg-muted)]">{item[countKey]}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <MetricCard label="Connections" value={stats.counts?.connections || 0} accent="cyan" />
        <MetricCard label="DNS Queries" value={stats.counts?.dns || 0} accent="violet" />
        <MetricCard label="HTTP Requests" value={stats.counts?.http || 0} accent="green" />
        <MetricCard label="Total Bandwidth" value={fmtBytes((stats.bandwidth?.bytes_sent || 0) + (stats.bandwidth?.bytes_recv || 0))} accent="blue" />
      </div>

      {/* Top IPs + Top Ports */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Top Remote IPs</CardTitle></CardHeader>
          <CardContent>
            <BarList items={stats.top_ips || []} labelKey="ip" countKey="count" color="var(--accent-cyan)" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Top Ports</CardTitle></CardHeader>
          <CardContent>
            <BarList items={(stats.top_ports || []).map((p) => ({ ...p, port: `${p.port} ${PORT_LABELS[p.port] || ""}` }))} labelKey="port" countKey="count" color="var(--accent-violet)" />
          </CardContent>
        </Card>
      </div>

      {/* Top Processes + State Distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Top Processes</CardTitle></CardHeader>
          <CardContent>
            <BarList items={stats.top_processes || []} labelKey="process" countKey="count" color="var(--status-healthy)" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Connection States</CardTitle></CardHeader>
          <CardContent>
            <BarList items={(stats.state_distribution || []).map((s) => ({ ...s, state: s.state || "UNKNOWN" }))} labelKey="state" countKey="count" color="var(--severity-medium)" />
          </CardContent>
        </Card>
      </div>

      {/* Top DNS + Top Hosts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Top DNS Queries</CardTitle></CardHeader>
          <CardContent>
            <BarList items={stats.top_dns || []} labelKey="query" countKey="count" color="var(--accent-violet)" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Top HTTP Hosts</CardTitle></CardHeader>
          <CardContent>
            <BarList items={stats.top_hosts || []} labelKey="host" countKey="count" color="var(--status-healthy)" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main Page
 * ═══════════════════════════════════════════════════════════════════════════ */

export default function NetworkAnalyzer() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [tab, setTab] = useState("topology");
  const [connections, setConnections] = useState([]);
  const [dnsQueries, setDnsQueries] = useState([]);
  const [httpRequests, setHttpRequests] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [live, setLive] = useState(true);
  const alive = useRef(true);

  const load = useCallback(async () => {
    try {
      const [st, net, dns, http] = await Promise.all([
        api.networkStats().catch(() => null),
        api.network(500),
        api.dns(500),
        api.http(500),
      ]);
      if (!alive.current) return;
      setStats(st);
      setConnections(net.items || []);
      setDnsQueries(dns.items || []);
      setHttpRequests(http.items || []);
      setError("");
    } catch (err) {
      if (alive.current) setError(err.message);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    load();
    return () => { alive.current = false; };
  }, [load]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => { if (!document.hidden) load(); }, 15000);
    return () => clearInterval(id);
  }, [live, load]);

  // Filtered data
  const filteredConnections = useMemo(() => {
    if (!filter) return connections;
    const q = filter.toLowerCase();
    return connections.filter((c) =>
      c.local_ip?.toLowerCase().includes(q) ||
      c.remote_ip?.toLowerCase().includes(q) ||
      c.process?.toLowerCase().includes(q) ||
      String(c.remote_port).includes(q) ||
      c.state?.toLowerCase().includes(q)
    );
  }, [connections, filter]);

  const filteredDns = useMemo(() => {
    if (!filter) return dnsQueries;
    const q = filter.toLowerCase();
    return dnsQueries.filter((d) =>
      d.query?.toLowerCase().includes(q) ||
      d.response?.toLowerCase().includes(q) ||
      d.process?.toLowerCase().includes(q)
    );
  }, [dnsQueries, filter]);

  const filteredHttp = useMemo(() => {
    if (!filter) return httpRequests;
    const q = filter.toLowerCase();
    return httpRequests.filter((h) =>
      h.host?.toLowerCase().includes(q) ||
      h.process?.toLowerCase().includes(q) ||
      h.method?.toLowerCase().includes(q)
    );
  }, [httpRequests, filter]);

  if (loading) return <Loading label="Loading network traffic" />;
  if (error) return <ErrorBanner message={error} onRetry={load} />;

  return (
    <div className="space-y-5 pb-10">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--fg-primary)]">Network Analyzer</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Understand what is communicating, where, and why.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setLive(!live)}
            className={`inline-flex items-center gap-1.5 rounded-[var(--radius-lg)] border px-2.5 py-1.5 text-[11px] font-semibold transition-colors ${
              live
                ? "border-[var(--status-healthy-muted)] bg-[var(--status-healthy-muted)] text-[var(--status-healthy)]"
                : "border-[var(--border-default)] bg-[var(--bg-surface)] text-[var(--fg-muted)]"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-[var(--status-healthy)] animate-pulse" : "bg-[var(--fg-muted)]"}`} />
            {live ? "LIVE" : "PAUSED"}
          </button>
        </div>
      </div>

      {/* Search + Tabs */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SearchInput
          value={filter}
          onChange={setFilter}
          placeholder="Search IP, host, domain, port, protocol..."
          className="sm:w-80"
        />
        <Tabs tabs={TABS} active={tab} onChange={setTab} />
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard label="Connections" value={connections.length} accent="cyan" />
        <MetricCard label="DNS Queries" value={dnsQueries.length} accent="violet" />
        <MetricCard label="HTTP Requests" value={httpRequests.length} accent="green" />
        <MetricCard label="Unique IPs" value={new Set(connections.map((c) => c.remote_ip).filter(Boolean)).size} accent="blue" />
      </div>

      {/* Content */}
      {tab === "topology" && (
        <NetworkTopology
          connections={filteredConnections}
          onNodeClick={setSelectedNode}
          onConnectionClick={setSelectedEdge}
        />
      )}

      {tab === "connections" && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] text-[var(--fg-muted)]">{filteredConnections.length} connections</span>
          </div>
          <ConnectionTable connections={filteredConnections} onSelect={(c) => setSelectedEdge({ connection: c })} />
        </Card>
      )}

      {tab === "dns" && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] text-[var(--fg-muted)]">{filteredDns.length} queries</span>
          </div>
          <DNSTable queries={filteredDns} />
        </Card>
      )}

      {tab === "http" && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] text-[var(--fg-muted)]">{filteredHttp.length} requests</span>
          </div>
          <HTTPTable requests={filteredHttp} />
        </Card>
      )}

      {tab === "analytics" && <AnalyticsView stats={stats} />}

      {/* Inspectors */}
      <NodeInspector node={selectedNode} connections={connections} onClose={() => setSelectedNode(null)} navigate={navigate} toast={toast} />
      <ConnectionInspector edge={selectedEdge} onClose={() => setSelectedEdge(null)} navigate={navigate} toast={toast} />
    </div>
  );
}
