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

async function blockIp(ip, toast) {
  if (!confirm(`Block IP ${ip} for 24h?`)) return false;
  try {
    const existing = await api.suppressions().catch(() => []);
    const already = Array.isArray(existing) && existing.some((s) => s.rule === ip || s.ip === ip || (s.pattern && s.pattern.includes(ip)));
    if (already) {
      toast({ title: `IP ${ip} already blocked`, type: "info" });
      return false;
    }
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    await api.request("/api/alerts/suppressions", {
      method: "POST",
      body: JSON.stringify({ rule: ip, reason: "Manual block from Network Analyzer", expires_at: expiresAt }),
    });
    toast({ title: `IP ${ip} blocked`, type: "success" });
    return true;
  } catch (e) {
    toast({ title: "Block failed", description: e.message, type: "error" });
    return false;
  }
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

  // Concentric layout: INTERNET at center, hosts in inner ring, external IPs in outer ring
  const layoutNodes = useMemo(() => {
    const n = nodes.map((nd) => ({ ...nd }));
    const W = 800, H = 400, cx = W / 2, cy = H / 2;
    const hosts = n.filter((nd) => nd.type !== "internet" && isPrivateIP(nd.id));
    const externals = n.filter((nd) => nd.type !== "internet" && !isPrivateIP(nd.id));

    n.forEach((nd) => {
      if (nd.type === "internet") { nd.x = cx; nd.y = 40; }
    });
    hosts.forEach((nd, i) => {
      const angle = (i / Math.max(hosts.length, 1)) * Math.PI * 2;
      nd.x = cx + Math.cos(angle) * 130;
      nd.y = cy + Math.sin(angle) * 110;
    });
    externals.forEach((nd, i) => {
      const angle = (i / Math.max(externals.length, 1)) * Math.PI * 2;
      nd.x = cx + Math.cos(angle) * 300;
      nd.y = cy + Math.sin(angle) * 150;
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
    <div className="relative w-full overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-inset)] transition-all duration-200" style={{ height: 420 }}>
      {/* Controls */}
      <div className="absolute right-3 top-3 z-10 flex gap-1.5">
        <button onClick={() => setTransform((t) => ({ ...t, scale: Math.min(3, t.scale * 1.2) }))} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Zoom in">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M8 3v10M3 8h10" /></svg>
        </button>
        <button onClick={() => setTransform((t) => ({ ...t, scale: Math.max(0.3, t.scale * 0.8) }))} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Zoom out">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 8h10" /></svg>
        </button>
        <button onClick={() => setTransform({ x: 0, y: 0, scale: 1 })} className="rounded-[var(--radius-md)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 p-1.5 text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors" title="Reset view">
          <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 3h10v10H3z" /></svg>
        </button>
      </div>

      {/* Legend */}
      <div className="absolute left-3 top-3 z-10 flex flex-col gap-1 rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200/90 px-2.5 py-2 text-[11px]">
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
            const bytes = edge.bytes || 0;
            const maxBytes = Math.max(...edges.map((e) => e.bytes || 0), 1);
            const width = 1 + Math.min(5, (bytes / maxBytes) * 5);
            const isUpload = (edge.connection?.bytes_sent || 0) >= (edge.connection?.bytes_recv || 0);
            const edgeColor = bytes > 0 ? (isUpload ? "var(--severity-high)" : "var(--accent-cyan)") : "var(--border-default)";
            return (
              <g key={edge.id} onClick={() => onConnectionClick?.(edge)} className="cursor-pointer">
                <line
                  x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                  stroke={edgeColor} strokeWidth={width} strokeOpacity={bytes > 0 ? 0.7 : 0.4}
                  className="transition-all hover:stroke-[var(--accent-cyan)]"
                />
                <title>{`${src.label} → ${tgt.label} (${edge.label})${bytes ? " · " + fmtBytes(bytes) : ""}`}</title>
              </g>
            );
          })}

          {/* Nodes */}
          {layoutNodes.map((nd) => {
            const color = nodeColor(nd);
            const isInternet = nd.type === "internet";
            const ringR = isInternet ? 30 : 18 + Math.min(nd.connections || 0, 10) * 1.2;
            return (
              <g key={nd.id} onClick={() => onNodeClick?.(nd)} className="cursor-pointer">
                {nd.connections > 2 && (
                  <circle cx={nd.x} cy={nd.y} r={ringR} fill="none" stroke={color} strokeOpacity="0.15" strokeWidth="2" />
                )}
                {isInternet ? (
                  <>
                    <rect x={nd.x - 38} y={nd.y - 16} width={76} height={32} rx={8} fill="var(--bg-surface)" stroke={color} strokeWidth="2" />
                    <text x={nd.x} y={nd.y + 4} textAnchor="middle" className="fill-[var(--fg-muted)] text-[11px] font-bold">INTERNET</text>
                  </>
                ) : (
                  <>
                    <circle cx={nd.x} cy={nd.y} r={18} fill="var(--bg-surface)" stroke={color} strokeWidth="2.5" />
                    <text x={nd.x} y={nd.y + 3} textAnchor="middle" className="fill-[var(--fg-primary)] text-[11px] font-mono font-bold pointer-events-none">
                      {nd.label.split(".").slice(-1)[0]}
                    </text>
                  </>
                )}
                {nd.connections > 1 && (
                  <text x={nd.x} y={nd.y + 34} textAnchor="middle" className="fill-[var(--fg-faint)] text-[12px] pointer-events-none">
                    {nd.connections} conns
                  </text>
                )}
              </g>
            );
          })}
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

  // Risk calculation: external IPs with many connections to unusual ports = higher risk
  const externalConns = relatedConns.filter((c) => c.remote_ip && classifyIP(c.remote_ip) === "external");
  const suspiciousPorts = relatedConns.filter((c) => c.remote_port && [4444, 1337, 31337, 6667, 6666, 8443, 8080].includes(c.remote_port)).length;
  const riskScore = classification === "external"
    ? Math.min(100, 30 + externalConns.length * 2 + suspiciousPorts * 15 + (totalBytes > 10 * 1024 * 1024 ? 20 : 0))
    : Math.min(60, relatedConns.length + (totalBytes > 5 * 1024 * 1024 ? 20 : 0));
  const riskColor = riskScore >= 70 ? "var(--severity-critical)" : riskScore >= 40 ? "var(--severity-high)" : riskScore >= 20 ? "var(--severity-medium)" : "var(--status-healthy)";

  return (
    <Drawer open={!!node} onClose={onClose} title="Node Inspector" width={380}>
      <div className="space-y-5">
        {/* Header */}
        <div>
          <p className="font-mono text-[15px] font-bold text-[var(--fg-primary)]">{node.label}</p>
          <div className="mt-1 flex items-center gap-2">
            <Badge severity={node.type === "host" ? "info" : "low"} size="sm">{node.type.toUpperCase()}</Badge>
            <Badge severity={classification === "external" ? "medium" : "info"} size="sm">{classification}</Badge>
          </div>
        </div>

        {/* Risk Gauge */}
        <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Risk Score</span>
            <span className="text-lg font-bold" style={{ color: riskColor }}>{riskScore}</span>
          </div>
          <div className="mt-2 h-2 rounded-full overflow-hidden" style={{ background: "var(--border-subtle)" }}>
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${riskScore}%`, background: riskColor }} />
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Connections</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{relatedConns.length}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Bytes</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{fmtBytes(totalBytes)}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Unique Peers</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{uniquePeers.size}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">External Peers</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--fg-primary)]">{externalConns.length}</p>
          </div>
        </div>

        {/* Recent Connections */}
        <div>
          <h4 className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-2">Recent Connections ({relatedConns.length})</h4>
          <div className="space-y-1.5 max-h-[220px] overflow-y-auto">
            {relatedConns.slice(0, 20).map((c) => {
              const total = (c.bytes_sent || 0) + (c.bytes_recv || 0);
              const upPct = total > 0 ? (c.bytes_sent / total) * 100 : 50;
              return (
                <div key={c.id} className="flex items-center gap-2 rounded-[var(--radius-md)] px-2 py-1.5 text-[11px] bg-[var(--bg-inset)]">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: STATE_COLORS[c.state] || "var(--fg-muted)" }} />
                  <span className="font-mono text-[var(--fg-secondary)] truncate">
                    {c.local_ip === node.id ? `→ ${c.remote_ip}:${c.remote_port || "—"}` : `${c.local_ip}:${c.local_port || "—"} →`}
                  </span>
                  <span className="ml-auto flex items-center gap-1.5 text-[11px]">
                    <span className="text-[var(--severity-high)]" title={`Sent: ${fmtBytes(c.bytes_sent)}`}>\u2191{fmtBytes(c.bytes_sent)}</span>
                    <span className="text-[var(--accent-cyan)]" title={`Recv: ${fmtBytes(c.bytes_recv)}`}>\u2193{fmtBytes(c.bytes_recv)}</span>
                  </span>
                </div>
              );
            })}
            {relatedConns.length > 20 && (
              <p className="text-center text-[11px] text-[var(--fg-faint)] py-1">+{relatedConns.length - 20} more</p>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" className="flex-1" onClick={() => {
            onClose();
            navigate(`/network?ip=${encodeURIComponent(ip)}`);
          }}>Investigate</Button>
          <Button variant="danger-ghost" size="sm" onClick={() => blockIp(ip, toast)}>Block IP</Button>
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
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Bytes Sent \u2191</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--severity-high)]">{fmtBytes(conn.bytes_sent)}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-surface-active)] p-3">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Bytes Recv \u2193</p>
            <p className="mt-0.5 text-lg font-bold text-[var(--accent-cyan)]">{fmtBytes(conn.bytes_recv)}</p>
          </div>
        </div>

        {/* Byte Flow Split Bar */}
        <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Byte Flow</span>
            <span className="text-[11px] font-medium text-[var(--fg-secondary)]">
              {conn.bytes_sent + conn.bytes_recv > 0
                ? `${Math.round((conn.bytes_sent / (conn.bytes_sent + conn.bytes_recv)) * 100)}% up`
                : "—"}
            </span>
          </div>
          <div className="flex h-3 rounded-full overflow-hidden">
            <div
              className="h-full bg-[var(--severity-high)] transition-all duration-500"
              style={{ width: `${(conn.bytes_sent / Math.max(conn.bytes_sent + conn.bytes_recv, 1)) * 100}%` }}
              title={`Sent: ${fmtBytes(conn.bytes_sent)}`}
            />
            <div
              className="h-full bg-[var(--accent-cyan)] transition-all duration-500"
              style={{ width: `${(conn.bytes_recv / Math.max(conn.bytes_sent + conn.bytes_recv, 1)) * 100}%` }}
              title={`Recv: ${fmtBytes(conn.bytes_recv)}`}
            />
          </div>
          <div className="mt-1.5 flex items-center justify-between text-[11px]">
            <span className="inline-flex items-center gap-1 text-[var(--severity-high)]">\u25A0 Upload</span>
            <span className="inline-flex items-center gap-1 text-[var(--accent-cyan)]">\u25A0 Download</span>
          </div>
          <p className="mt-1.5 text-[9px] text-[var(--fg-faint)]">Bytes are process-shared estimates (Windows exposes per-process I/O, not per-socket).</p>
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
          <Button variant="secondary" size="sm" className="flex-1" onClick={() => {
            onClose();
            navigate(`/network?ip=${encodeURIComponent(ip)}`);
          }}>Investigate</Button>
          <Button variant="danger-ghost" size="sm" onClick={() => blockIp(ip, toast)}>Block IP</Button>
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
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;

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

  const SortHeader = ({ field, children, className = "" }) => (
    <th
      onClick={() => toggleSort(field)}
      className={`px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] cursor-pointer select-none hover:text-[var(--fg-secondary)] transition-colors border-b border-[var(--border-subtle)] ${className}`}
    >
      <span className="flex items-center gap-1.5">
        {children}
        {sortKey === field && <span className="text-[var(--accent-cyan)] text-[11px]">{sortDir === "asc" ? "\u2191" : "\u2193"}</span>}
      </span>
    </th>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr>
            <SortHeader field="local_ip">Source</SortHeader>
            <SortHeader field="remote_ip">Destination</SortHeader>
            <SortHeader field="remote_port">Port</SortHeader>
            <SortHeader field="state">State</SortHeader>
            <SortHeader field="bytes_sent">Sent \u2191</SortHeader>
            <SortHeader field="bytes_recv">Recv \u2193</SortHeader>
            <SortHeader field="process">Process</SortHeader>
            <SortHeader field="observed_at">Last Seen</SortHeader>
          </tr>
        </thead>
        <tbody>
          {sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((conn) => {
            const stateColor = STATE_COLORS[conn.state] || "var(--fg-muted)";
            return (
              <tr
                key={conn.id}
                onClick={() => onSelect?.(conn)}
                className="group cursor-pointer border-b border-[var(--border-subtle)] last:border-b-0 hover:bg-[var(--bg-surface-hover)] transition-colors duration-150"
              >
                <td className="px-4 py-3 font-mono text-[12px] text-[var(--fg-muted)] group-hover:text-[var(--fg-secondary)] transition-colors">
                  {conn.local_ip || "\u2014"}
                  {conn.local_port ? <span className="text-[var(--fg-faint)]">:{conn.local_port}</span> : null}
                </td>
                <td className="px-4 py-3 font-mono text-[12px] font-medium text-[var(--fg-primary)]">
                  {conn.remote_ip || "\u2014"}
                </td>
                <td className="px-4 py-3">
                  {conn.remote_port ? (
                    <span className="inline-flex items-center gap-1.5">
                      <span className="font-mono text-[12px] font-medium text-[var(--fg-primary)]">{conn.remote_port}</span>
                      {PORT_LABELS[conn.remote_port] && (
                        <span className="inline-flex items-center rounded-full px-1.5 py-0.5 text-[11px] font-semibold tracking-wide" style={{ background: "var(--bg-surface)", color: "var(--fg-muted)", border: "1px solid var(--border-subtle)" }}>
                          {PORT_LABELS[conn.remote_port]}
                        </span>
                      )}
                    </span>
                  ) : <span className="text-[var(--fg-faint)]">\u2014</span>}
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold" style={{ background: `color-mix(in srgb, ${stateColor} 10%, transparent)`, color: stateColor }}>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: stateColor }} />
                    {conn.state || "NONE"}
                  </span>
                </td>
                <td className="px-4 py-3 text-[11px] font-mono text-[var(--severity-high)] tabular-nums font-medium">
                  {conn.bytes_sent ? fmtBytes(conn.bytes_sent) : <span className="text-[var(--fg-faint)]">—</span>}
                </td>
                <td className="px-4 py-3 text-[11px] font-mono text-[var(--accent-cyan)] tabular-nums font-medium">
                  {conn.bytes_recv ? fmtBytes(conn.bytes_recv) : <span className="text-[var(--fg-faint)]">—</span>}
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 text-[11px] text-[var(--fg-secondary)] max-w-[140px]">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)] opacity-60 shrink-0" />
                    <span className="truncate">{conn.process || "\u2014"}</span>
                  </span>
                </td>
                <td className="px-4 py-3 text-[11px] text-[var(--fg-muted)] tabular-nums">
                  {fmtDate(conn.observed_at)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {sorted.length === 0 && (
        <div className="py-16 text-center">
          <p className="text-[13px] text-[var(--fg-muted)]">No connections found</p>
          <p className="text-[11px] text-[var(--fg-faint)] mt-1">Traffic data will appear here once the collector captures connections</p>
        </div>
      )}
      {sorted.length > PAGE_SIZE && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--fg-muted)]">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, sorted.length)} of {sorted.length}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors"
            >
              Prev
            </button>
            {Array.from({ length: Math.min(10, Math.ceil(sorted.length / PAGE_SIZE)) }).map((_, i) => {
              const pageNum = page < 5 ? i : page - 5 + i;
              if (pageNum >= Math.ceil(sorted.length / PAGE_SIZE)) return null;
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={`h-7 w-7 rounded-[var(--radius-md)] text-[11px] font-medium transition-colors ${
                    pageNum === page ? "bg-[var(--accent-cyan)] text-white" : "border border-[var(--border-default)] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)]"
                  }`}
                >
                  {pageNum + 1}
                </button>
              );
            })}
            <button
              onClick={() => setPage((p) => Math.min(Math.ceil(sorted.length / PAGE_SIZE) - 1, p + 1))}
              disabled={page >= Math.ceil(sorted.length / PAGE_SIZE) - 1}
              className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DNS Table
 * ═══════════════════════════════════════════════════════════════════════════ */

function DNSTable({ queries }) {
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;
  const totalPages = Math.ceil(queries.length / PAGE_SIZE);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Time</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Query</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Response</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Process</th>
          </tr>
        </thead>
        <tbody>
          {queries.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((q) => (
            <tr key={q.id} className="group border-b border-[var(--border-subtle)] last:border-b-0 hover:bg-[var(--bg-surface-hover)] transition-colors duration-150">
              <td className="px-4 py-3 text-[11px] text-[var(--fg-muted)] tabular-nums">{fmtDate(q.observed_at)}</td>
              <td className="px-4 py-3 font-mono text-[12px] text-[var(--accent-cyan)] font-medium">{q.query || "\u2014"}</td>
              <td className="px-4 py-3 font-mono text-[12px] text-[var(--fg-secondary)]">{q.response || "\u2014"}</td>
              <td className="px-4 py-3">
                <span className="inline-flex items-center gap-1.5 text-[11px] text-[var(--fg-secondary)] max-w-[140px]">
                  <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)] opacity-60 shrink-0" />
                  <span className="truncate">{q.process || "\u2014"}</span>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {queries.length === 0 && (
        <div className="py-16 text-center">
          <p className="text-[13px] text-[var(--fg-muted)]">No DNS queries found</p>
          <p className="text-[11px] text-[var(--fg-faint)] mt-1">DNS traffic will appear here once the collector captures queries</p>
        </div>
      )}
      {queries.length > PAGE_SIZE && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--fg-muted)]">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, queries.length)} of {queries.length}
          </span>
          <div className="flex items-center gap-1">
            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors">Prev</button>
            {Array.from({ length: Math.min(10, totalPages) }).map((_, i) => {
              const pageNum = page < 5 ? i : page - 5 + i;
              if (pageNum >= totalPages) return null;
              return (
                <button key={pageNum} onClick={() => setPage(pageNum)} className={`h-7 w-7 rounded-[var(--radius-md)] text-[11px] font-medium transition-colors ${pageNum === page ? "bg-[var(--accent-cyan)] text-white" : "border border-[var(--border-default)] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)]"}`}>{pageNum + 1}</button>
              );
            })}
            <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors">Next</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HTTP Table
 * ═══════════════════════════════════════════════════════════════════════════ */

function HTTPTable({ requests }) {
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 50;
  const totalPages = Math.ceil(requests.length / PAGE_SIZE);
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Time</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Method</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Host</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Path</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Status</th>
            <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)] border-b border-[var(--border-subtle)]">Process</th>
          </tr>
        </thead>
        <tbody>
          {requests.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((r) => {
            const statusColor = HTTP_STATUS_COLORS[Math.floor((r.status_code || 0) / 100)] || "var(--fg-muted)";
            return (
              <tr key={r.id} className="group border-b border-[var(--border-subtle)] last:border-b-0 hover:bg-[var(--bg-surface-hover)] transition-colors duration-150">
                <td className="px-4 py-3 text-[11px] text-[var(--fg-muted)] tabular-nums">{fmtDate(r.observed_at)}</td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[11px] font-bold" style={{ background: `color-mix(in srgb, ${METHOD_COLORS[r.method] || "var(--fg-muted)"} 12%, transparent)`, color: METHOD_COLORS[r.method] || "var(--fg-muted)" }}>
                    {r.method || "\u2014"}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-[12px] text-[var(--fg-secondary)] max-w-[200px] truncate">{r.host || "\u2014"}</td>
                <td className="px-4 py-3 font-mono text-[11px] text-[var(--fg-muted)] max-w-[180px] truncate">{r.path || "/"}</td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-bold" style={{ color: statusColor }}>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: statusColor }} />
                    {r.status_code || "\u2014"}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1.5 text-[11px] text-[var(--fg-secondary)] max-w-[140px]">
                    <span className="h-1 w-1 rounded-full bg-[var(--accent-cyan)] opacity-60 shrink-0" />
                    <span className="truncate">{r.process || "\u2014"}</span>
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {requests.length === 0 && (
        <div className="py-16 text-center">
          <p className="text-[13px] text-[var(--fg-muted)]">No HTTP requests found</p>
          <p className="text-[11px] text-[var(--fg-faint)] mt-1">HTTP traffic will appear here once the collector captures requests</p>
        </div>
      )}
      {requests.length > PAGE_SIZE && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-[var(--border-subtle)]">
          <span className="text-[11px] text-[var(--fg-muted)]">
            Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, requests.length)} of {requests.length}
          </span>
          <div className="flex items-center gap-1">
            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors">Prev</button>
            {Array.from({ length: Math.min(10, totalPages) }).map((_, i) => {
              const pageNum = page < 5 ? i : page - 5 + i;
              if (pageNum >= totalPages) return null;
              return (
                <button key={pageNum} onClick={() => setPage(pageNum)} className={`h-7 w-7 rounded-[var(--radius-md)] text-[11px] font-medium transition-colors ${pageNum === page ? "bg-[var(--accent-cyan)] text-white" : "border border-[var(--border-default)] text-[var(--fg-secondary)] hover:bg-[var(--bg-surface-hover)]"}`}>{pageNum + 1}</button>
              );
            })}
            <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="rounded-[var(--radius-md)] border border-[var(--border-default)] px-2.5 py-1 text-[11px] font-medium text-[var(--fg-secondary)] disabled:opacity-40 hover:bg-[var(--bg-surface-hover)] transition-colors">Next</button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Analytics View
 * ═══════════════════════════════════════════════════════════════════════════ */

function AnalyticsView({ stats, connections }) {
  if (!stats) return <div className="py-12 text-center text-[13px] text-[var(--fg-muted)]">No analytics data available</div>;

  // Protocol distribution for donut
  const protocolMap = {};
  (connections || []).forEach((c) => {
    const label = PORT_LABELS[c.remote_port] || (c.remote_port ? `:${c.remote_port}` : "other");
    protocolMap[label] = (protocolMap[label] || 0) + 1;
  });
  const protocolData = Object.entries(protocolMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const protoColors = ["var(--accent-cyan)", "var(--accent-violet)", "var(--status-healthy)", "var(--severity-medium)", "var(--severity-high)", "var(--fg-muted)"];
  const totalProto = protocolData.reduce((s, [, v]) => s + v, 0) || 1;
  let cumAngle = 0;
  const donutSegments = protocolData.map(([label, count], i) => {
    const frac = count / totalProto;
    const seg = { label, count, color: protoColors[i % protoColors.length], start: cumAngle, end: cumAngle + frac * 360 };
    cumAngle += frac * 360;
    return seg;
  });

  // Time series: bucket connections by hour
  const timeMap = {};
  (connections || []).forEach((c) => {
    if (!c.observed_at) return;
    const d = new Date(c.observed_at);
    const key = `${d.getHours()}:00`;
    timeMap[key] = (timeMap[key] || 0) + 1;
  });
  const hours = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, "0") + ":00");
  const maxCount = Math.max(...Object.values(timeMap), 1);

  // Top talkers by total bytes (remote IP)
  const talkerMap = {};
  (connections || []).forEach((c) => {
    if (!c.remote_ip) return;
    const key = c.remote_ip;
    if (!talkerMap[key]) talkerMap[key] = { ip: key, sent: 0, recv: 0, count: 0 };
    talkerMap[key].sent += c.bytes_sent || 0;
    talkerMap[key].recv += c.bytes_recv || 0;
    talkerMap[key].count += 1;
  });
  const topTalkers = Object.values(talkerMap)
    .map((t) => ({ ...t, total: t.sent + t.recv }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 8);

  // Per-process bandwidth
  const procMap = {};
  (connections || []).forEach((c) => {
    const key = c.process || "unknown";
    if (!procMap[key]) procMap[key] = { process: key, sent: 0, recv: 0, count: 0 };
    procMap[key].sent += c.bytes_sent || 0;
    procMap[key].recv += c.bytes_recv || 0;
    procMap[key].count += 1;
  });
  const topProcessesBytes = Object.values(procMap)
    .map((t) => ({ ...t, total: t.sent + t.recv }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 8);

  // Bandwidth time series (sent vs recv by hour)
  const bwMap = {};
  (connections || []).forEach((c) => {
    if (!c.observed_at) return;
    const d = new Date(c.observed_at);
    const key = `${d.getHours()}:00`;
    if (!bwMap[key]) bwMap[key] = { sent: 0, recv: 0 };
    bwMap[key].sent += c.bytes_sent || 0;
    bwMap[key].recv += c.bytes_recv || 0;
  });
  const maxBw = Math.max(...hours.map((h) => (bwMap[h]?.sent || 0) + (bwMap[h]?.recv || 0)), 1);

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

      {/* Protocol Distribution + Time Series */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Donut: Protocol Distribution */}
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Protocol Distribution</h3>
          <div className="mt-4 flex items-center gap-5">
            <svg viewBox="0 0 36 36" className="h-[140px] w-[140px] -rotate-90">
              {donutSegments.map((seg, i) => {
                const r = 15.5;
                const circ = 2 * Math.PI * r;
                const dash = ((seg.end - seg.start) / 360) * circ;
                const offset = (seg.start / 360) * circ;
                return (
                  <circle key={i} cx="18" cy="18" r={r} fill="none" stroke={seg.color} strokeWidth="4" strokeDasharray={`${dash} ${circ - dash}`} strokeDashoffset={-offset} />
                );
              })}
            </svg>
            <div className="flex-1 space-y-1.5">
              {donutSegments.map((seg, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px]">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: seg.color }} />
                  <span className="text-[var(--fg-secondary)]">{seg.label}</span>
                  <span className="ml-auto font-semibold text-[var(--fg-muted)]">{seg.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Time Series: Connections by Hour */}
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Connections by Hour</h3>
          <div className="mt-4 flex items-end gap-1 h-[120px]">
            {hours.map((h) => {
              const count = timeMap[h] || 0;
              return (
                <div key={h} className="flex-1 flex flex-col items-center justify-end group relative">
                  <div
                    className="w-full rounded-t-[var(--radius-sm)] bg-gradient-to-t from-[var(--accent-cyan)]/40 to-[var(--accent-cyan)] transition-all duration-300 group-hover:from-[var(--accent-violet)]/40 group-hover:to-[var(--accent-violet)]"
                    style={{ height: `${(count / maxCount) * 100}%`, minHeight: count > 0 ? "3px" : "0" }}
                    title={`${h}: ${count} connections`}
                  />
                  <span className="absolute -bottom-4 text-[12px] text-[var(--fg-faint)] opacity-0 group-hover:opacity-100 transition-opacity">{h.slice(0, 2)}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bandwidth Time Series: Sent vs Recv */}
      <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
        <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Bandwidth by Hour (Sent vs Recv)</h3>
        <div className="mt-4 flex items-end gap-1 h-[120px]">
          {hours.map((h) => {
            const sent = bwMap[h]?.sent || 0;
            const recv = bwMap[h]?.recv || 0;
            const total = sent + recv;
            return (
              <div key={h} className="flex-1 flex flex-col items-center justify-end group relative">
                <div className="w-full flex flex-col-reverse rounded-t-[var(--radius-sm)] overflow-hidden" style={{ height: `${(total / maxBw) * 100}%`, minHeight: total > 0 ? "3px" : "0" }}>
                  <div className="w-full bg-[var(--severity-high)] transition-all duration-300 group-hover:opacity-80" style={{ height: `${sent / Math.max(total, 1) * 100}%` }} title={`Sent: ${fmtBytes(sent)}`} />
                  <div className="w-full bg-[var(--accent-cyan)] transition-all duration-300 group-hover:opacity-80" style={{ height: `${recv / Math.max(total, 1) * 100}%` }} title={`Recv: ${fmtBytes(recv)}`} />
                </div>
                <span className="absolute -bottom-4 text-[12px] text-[var(--fg-faint)] opacity-0 group-hover:opacity-100 transition-opacity">{h.slice(0, 2)}</span>
              </div>
            );
          })}
        </div>
        <div className="mt-5 flex items-center gap-4 text-[11px]">
          <span className="inline-flex items-center gap-1.5 text-[var(--severity-high)]"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: "var(--severity-high)" }} /> Upload (Sent)</span>
          <span className="inline-flex items-center gap-1.5 text-[var(--accent-cyan)]"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: "var(--accent-cyan)" }} /> Download (Recv)</span>
        </div>
      </div>

      {/* Top Talkers by Bandwidth + Per-Process Bandwidth */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top Talkers by Bandwidth</h3>
          <div className="mt-4 space-y-2">
            {topTalkers.map((t) => {
              const total = t.total || 1;
              const sentPct = (t.sent / total) * 100;
              return (
                <div key={t.ip} className="flex items-center gap-3">
                  <span className="w-[120px] truncate text-[11px] font-mono text-[var(--fg-secondary)]" title={t.ip}>{t.ip}</span>
                  <div className="flex-1 h-4 rounded-full overflow-hidden flex">
                    <div className="h-full bg-[var(--severity-high)]" style={{ width: `${sentPct}%` }} title={`Sent: ${fmtBytes(t.sent)}`} />
                    <div className="h-full bg-[var(--accent-cyan)]" style={{ width: `${100 - sentPct}%` }} title={`Recv: ${fmtBytes(t.recv)}`} />
                  </div>
                  <span className="w-[52px] text-right text-[11px] font-semibold text-[var(--fg-muted)]">{fmtBytes(t.total)}</span>
                </div>
              );
            })}
            {topTalkers.length === 0 && <p className="text-[11px] text-[var(--fg-faint)]">No bandwidth data</p>}
          </div>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Bandwidth by Process</h3>
          <div className="mt-4 space-y-2">
            {topProcessesBytes.map((t) => {
              const total = t.total || 1;
              const sentPct = (t.sent / total) * 100;
              return (
                <div key={t.process} className="flex items-center gap-3">
                  <span className="w-[120px] truncate text-[11px] font-mono text-[var(--fg-secondary)]" title={t.process}>{t.process}</span>
                  <div className="flex-1 h-4 rounded-full overflow-hidden flex">
                    <div className="h-full bg-[var(--severity-high)]" style={{ width: `${sentPct}%` }} title={`Sent: ${fmtBytes(t.sent)}`} />
                    <div className="h-full bg-[var(--accent-cyan)]" style={{ width: `${100 - sentPct}%` }} title={`Recv: ${fmtBytes(t.recv)}`} />
                  </div>
                  <span className="w-[52px] text-right text-[11px] font-semibold text-[var(--fg-muted)]">{fmtBytes(t.total)}</span>
                </div>
              );
            })}
            {topProcessesBytes.length === 0 && <p className="text-[11px] text-[var(--fg-faint)]">No bandwidth data</p>}
          </div>
        </div>
      </div>

      {/* Top IPs + Top Ports */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top Remote IPs</h3>
          <div className="mt-4">
            <BarList items={stats.top_ips || []} labelKey="ip" countKey="count" color="var(--accent-cyan)" />
          </div>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top Ports</h3>
          <div className="mt-4">
            <BarList items={(stats.top_ports || []).map((p) => ({ ...p, port: `${p.port} ${PORT_LABELS[p.port] || ""}` }))} labelKey="port" countKey="count" color="var(--accent-violet)" />
          </div>
        </div>
      </div>

      {/* Top Processes + State Distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top Processes</h3>
          <div className="mt-4">
            <BarList items={stats.top_processes || []} labelKey="process" countKey="count" color="var(--status-healthy)" />
          </div>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Connection States</h3>
          <div className="mt-4">
            <BarList items={(stats.state_distribution || []).map((s) => ({ ...s, state: s.state || "UNKNOWN" }))} labelKey="state" countKey="count" color="var(--severity-medium)" />
          </div>
        </div>
      </div>

      {/* Top DNS + Top Hosts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top DNS Queries</h3>
          <div className="mt-4">
            <BarList items={stats.top_dns || []} labelKey="query" countKey="count" color="var(--accent-violet)" />
          </div>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
          <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">Top HTTP Hosts</h3>
          <div className="mt-4">
            <BarList items={stats.top_hosts || []} labelKey="host" countKey="count" color="var(--status-healthy)" />
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IP Investigation View (stays within Network Analyzer)
 * ═══════════════════════════════════════════════════════════════════════════ */

function IPInvestigation({ ip, connections, dnsQueries, httpRequests, onClose, navigate, toast }) {
  const relatedConns = useMemo(() => connections.filter((c) => c.local_ip === ip || c.remote_ip === ip), [connections, ip]);
  const relatedDns = useMemo(() => dnsQueries.filter((d) => d.response === ip || d.query?.includes(ip)), [dnsQueries, ip]);
  const relatedHttp = useMemo(() => httpRequests.filter((h) => h.host === ip || h.host?.includes(ip)), [httpRequests, ip]);
  const classification = classifyIP(ip);
  const totalBytes = relatedConns.reduce((s, c) => s + (c.bytes_sent || 0) + (c.bytes_recv || 0), 0);
  const externalConns = relatedConns.filter((c) => c.remote_ip && classifyIP(c.remote_ip) === "external");
  const localConns = relatedConns.filter((c) => c.local_ip === ip);
  const uniquePeers = new Set(relatedConns.map((c) => c.local_ip === ip ? c.remote_ip : c.local_ip));
  const riskScore = classification === "external"
    ? Math.min(100, 35 + externalConns.length * 3 + (totalBytes > 10 * 1024 * 1024 ? 20 : 0))
    : Math.min(60, relatedConns.length + (totalBytes > 5 * 1024 * 1024 ? 15 : 0));
  const riskColor = riskScore >= 70 ? "var(--severity-critical)" : riskScore >= 40 ? "var(--severity-high)" : riskScore >= 20 ? "var(--severity-medium)" : "var(--status-healthy)";

  const tabs = [
    { id: "connections", label: `Connections (${relatedConns.length})` },
    { id: "dns", label: `DNS (${relatedDns.length})` },
    { id: "http", label: `HTTP (${relatedHttp.length})` },
  ];
  const [activeTab, setActiveTab] = useState("connections");
  const [geo, setGeo] = useState(null);

  useEffect(() => {
    if (classification === "external") {
      api.ipGeo(ip).then(setGeo).catch(() => {});
    }
  }, [ip, classification]);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <button onClick={onClose} className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[var(--fg-muted)] hover:text-[var(--fg-primary)] transition-colors">
          <span className="text-[14px]">\u2190</span> Back to Network
        </button>
        <Button variant="danger-ghost" size="sm" onClick={async () => {
          if (!confirm(`Block IP ${ip}?`)) return;
          blockIp(ip, toast);
        }}>Block IP</Button>
        <Button variant="secondary" size="sm" disabled title="Packet capture requires the ETW/WFP collector (not enabled)">PCAP</Button>
      </div>

      <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[20px] font-bold text-[var(--fg-primary)]">{ip}</p>
            <div className="mt-1.5 flex items-center gap-2">
              <Badge severity={classification === "external" ? "medium" : "info"} size="sm">{classification.toUpperCase()}</Badge>
              <Badge severity="low" size="sm">{uniquePeers.size} peers</Badge>
              {geo?.org && geo.org !== "Unknown" && <Badge severity="info" size="sm">{geo.org}</Badge>}
            </div>
            {geo && classification === "external" && (
              <p className="mt-1.5 text-[11px] text-[var(--fg-muted)]">
                IPv{geo.version} {geo.private ? "· private" : "· public"} · heuristic org match
              </p>
            )}
          </div>
          {/* Risk Gauge */}
          <div className="text-center">
            <div className="relative h-[72px] w-[72px]">
              <svg viewBox="0 0 36 36" className="h-full w-full -rotate-90">
                <circle cx="18" cy="18" r="15.5" fill="none" stroke="var(--border-subtle)" strokeWidth="3" />
                <circle cx="18" cy="18" r="15.5" fill="none" stroke={riskColor} strokeWidth="3" strokeDasharray={`${(riskScore / 100) * 97.4} 97.4`} strokeLinecap="round" />
              </svg>
              <span className="absolute inset-0 flex items-center justify-center text-[16px] font-bold" style={{ color: riskColor }}>{riskScore}</span>
            </div>
            <p className="mt-1 text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Risk*</p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Connections</p>
            <p className="mt-0.5 text-[17px] font-bold text-[var(--fg-primary)]">{relatedConns.length}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Total Bytes</p>
            <p className="mt-0.5 text-[17px] font-bold text-[var(--fg-primary)]">{fmtBytes(totalBytes)}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Outbound</p>
            <p className="mt-0.5 text-[17px] font-bold text-[var(--fg-primary)]">{localConns.length}</p>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3 text-center">
            <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Unique Peers</p>
            <p className="mt-0.5 text-[17px] font-bold text-[var(--fg-primary)]">{uniquePeers.size}</p>
          </div>
        </div>
      </div>

      <p className="text-[10px] text-[var(--fg-faint)] -mt-2">
        *Risk is a heuristic score (connection count, bytes, external exposure). Not yet tied to ML anomaly scores or threat intelligence.
      </p>

      <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />

      {activeTab === "connections" && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <ConnectionTable connections={relatedConns} onSelect={(c) => setSelectedEdge({ connection: c })} />
        </div>
      )}
      {activeTab === "dns" && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <DNSTable queries={relatedDns} />
        </div>
      )}
      {activeTab === "http" && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <HTTPTable requests={relatedHttp} />
        </div>
      )}
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
  const [direction, setDirection] = useState("all");
  const [timeRange, setTimeRange] = useState("all");
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [live, setLive] = useState(true);
  const [investigateIp, setInvestigateIp] = useState(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    try {
      const since = timeRange === "all" ? null
        : new Date(Date.now() - parseInt(timeRange) * 60 * 60 * 1000).toISOString();
      const [st, net, dns, http] = await Promise.all([
        api.networkStats().catch(() => null),
        api.network(2000, { since, direction: direction === "all" ? undefined : direction }),
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
  }, [direction, timeRange]);

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

  // Read ?ip= query param to open IP investigation
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ip = params.get("ip");
    if (ip && connections.some((c) => c.local_ip === ip || c.remote_ip === ip)) {
      setInvestigateIp(ip);
    }
  }, [connections]);

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

  if (investigateIp) {
    return (
      <IPInvestigation
        ip={investigateIp}
        connections={connections}
        dnsQueries={dnsQueries}
        httpRequests={httpRequests}
        onClose={() => { setInvestigateIp(null); navigate("/network"); }}
        navigate={navigate}
        toast={toast}
      />
    );
  }

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
        <div className="flex items-center gap-2">
          <select
            value={direction}
            onChange={(e) => setDirection(e.target.value)}
            className="rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 px-2.5 py-1.5 text-[11px] font-medium text-[var(--fg-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/30"
          >
            <option value="all">All Directions</option>
            <option value="outbound">Outbound ↑</option>
            <option value="inbound">Inbound ↓</option>
          </select>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 px-2.5 py-1.5 text-[11px] font-medium text-[var(--fg-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/30"
          >
            <option value="all">All Time</option>
            <option value="1">Last 1h</option>
            <option value="6">Last 6h</option>
            <option value="24">Last 24h</option>
          </select>
          <button
            onClick={() => {
              const data = connections.map((c) => ({
                local: `${c.local_ip}:${c.local_port}`, remote: `${c.remote_ip}:${c.remote_port}`,
                state: c.state, sent: c.bytes_sent, recv: c.bytes_recv, process: c.process, org: c.org || "", observed: c.observed_at,
              }));
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url; a.download = `network-connections-${Date.now()}.json`;
              a.click(); URL.revokeObjectURL(url);
              toast({ title: `Exported ${data.length} connections`, type: "success" });
            }}
            className="inline-flex items-center gap-1.5 rounded-[var(--radius-lg)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 px-2.5 py-1.5 text-[11px] font-semibold text-[var(--fg-secondary)] hover:text-[var(--fg-primary)] transition-colors"
            title="Export filtered connections as JSON"
          >
            <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="M8 2v8M4 10l4 4 4-4M3 14h10" /></svg>
            Export
          </button>
          <Tabs tabs={TABS} active={tab} onChange={setTab} />
        </div>
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
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] font-medium text-[var(--fg-secondary)]">
              <span className="font-semibold text-[var(--fg-primary)]">{filteredConnections.length}</span> connections
              {filter && <span className="text-[var(--fg-muted)]"> matching "{filter}"</span>}
            </span>
            <span className="text-[11px] text-[var(--fg-faint)] uppercase tracking-wider">Click row to inspect</span>
          </div>
          <ConnectionTable connections={filteredConnections} onSelect={(c) => setSelectedEdge({ connection: c })} />
        </div>
      )}

      {tab === "dns" && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] font-medium text-[var(--fg-secondary)]">
              <span className="font-semibold text-[var(--fg-primary)]">{filteredDns.length}</span> DNS queries
            </span>
          </div>
          <DNSTable queries={filteredDns} />
        </div>
      )}

      {tab === "http" && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-card)] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border-subtle)]">
            <span className="text-[12px] font-medium text-[var(--fg-secondary)]">
              <span className="font-semibold text-[var(--fg-primary)]">{filteredHttp.length}</span> HTTP requests
            </span>
          </div>
          <HTTPTable requests={filteredHttp} />
        </div>
      )}

      {tab === "analytics" && <AnalyticsView stats={stats} connections={connections} />}

      {/* Inspectors */}
      <NodeInspector node={selectedNode} connections={connections} onClose={() => setSelectedNode(null)} navigate={navigate} toast={toast} />
      <ConnectionInspector edge={selectedEdge} onClose={() => setSelectedEdge(null)} navigate={navigate} toast={toast} />
    </div>
  );
}
