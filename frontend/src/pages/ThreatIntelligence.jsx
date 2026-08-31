import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";

const TI_SOURCES = [
  {
    id: "findip",
    name: "FindIP",
    category: "IP Reputation",
    color: "#22c55e",
    icon: "\uD83D\uDD12",
    description: "IP reputation with threat detection, VPN/proxy/Tor identification, and risk scoring",
    capabilities: ["IP reputation", "Threat detection", "VPN/Proxy/Tor detection", "Risk scoring", "Geolocation"],
    indicators: ["IPv4", "IPv6"],
    status: "active",
  },
  {
    id: "ipdetails",
    name: "IPDetails.io",
    category: "IP Intelligence",
    color: "#3b82f6",
    icon: "\uD83D\uDCCA",
    description: "IP geolocation, WHOIS, ASN, and threat intelligence",
    capabilities: ["Geolocation", "WHOIS/ASN", "Threat detection", "Hosting detection", "Risk scoring"],
    indicators: ["IPv4", "IPv6"],
    status: "active",
  },
  {
    id: "isbadip",
    name: "isbadip",
    category: "IP/Domain Reputation",
    color: "#ef4444",
    icon: "\u26D4",
    description: "IP and domain reputation from public threat feeds and local attack telemetry",
    capabilities: ["IP reputation", "Domain reputation", "Blocklist feeds", "Attack telemetry", "Honeypot data"],
    indicators: ["IPv4", "IPv6", "Domain"],
    status: "active",
  },
  {
    id: "ffraud",
    name: "FFraud",
    category: "IP Fraud Intelligence",
    color: "#f97316",
    icon: "\uD83D\uDEAB",
    description: "750K+ confirmed malicious IPs with fraud scoring and threat categories",
    capabilities: ["Fraud scoring", "C2/Botnet detection", "Phishing detection", "Brute-force detection", "Category tagging"],
    indicators: ["IPv4", "IPv6"],
    status: "active",
  },
  {
    id: "abuseipdb",
    name: "AbuseIPDB",
    category: "Community IP Reputation",
    color: "#eab308",
    icon: "\uD83D\uDEA8",
    description: "Community-driven IP reputation database with abuse confidence scoring",
    capabilities: ["IP reputation", "Subnet reporting", "Country blocking", "Whitelist management"],
    indicators: ["IPv4", "IPv6"],
    status: "active",
  },
  {
    id: "alienvault_otx",
    name: "AlienVault OTX",
    category: "Pulse Intelligence",
    color: "#8b5cf6",
    icon: "\uD83D\uDD2D",
    description: "Open threat intelligence community with pulses, IOCs, and threat actor profiles",
    capabilities: ["Pulse subscriptions", "IOC extraction", "Threat actor tracking", "YARA rules"],
    indicators: ["IP", "Domain", "Hash", "URL", "CVE"],
    status: "active",
  },
  {
    id: "shodan",
    name: "Shodan",
    category: "Internet Device Search",
    color: "#14b8a6",
    icon: "\uD83C\uDF10",
    description: "Search engine for internet-connected devices, services, and banners",
    capabilities: ["Device discovery", "Banner analysis", "Vulnerability detection", "Network monitoring"],
    indicators: ["IP", "Domain", "ASN"],
    status: "active",
  },
  {
    id: "threatfox",
    name: "ThreatFox",
    category: "Malware IOC Sharing",
    color: "#ec4899",
    icon: "\u2622\uFE0F",
    description: "Malware IOC sharing platform by abuse.ch",
    capabilities: ["Malware IOC sharing", "Threat actor tracking", "YARA rules", "Payload analysis"],
    indicators: ["IP", "Domain", "URL", "Hash"],
    status: "active",
  },
  {
    id: "urlhaus",
    name: "URLhaus",
    category: "Malicious URL Tracking",
    color: "#a855f7",
    icon: "\uD83D\uDD17",
    description: "Malicious URL sharing and tracking project by abuse.ch",
    capabilities: ["URL reputation", "Malware distribution tracking", "Download analysis", "Tagging"],
    indicators: ["URL", "Domain", "IP"],
    status: "active",
  },
];

function SourceCard({ source, isExpanded, onToggle, feedState }) {
  const status = feedState?.status || source.status || "active";
  const lastSync = feedState?.lastSync;
  const iocCount = feedState?.ioc_count || 0;

  return (
    <div className="relative overflow-hidden rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] transition-all duration-200 hover:border-[var(--border-strong)]">
      <button
        onClick={onToggle}
        className="w-full px-5 py-4 text-left transition-colors hover:bg-white/[0.02]"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex h-10 w-10 items-center justify-center rounded-lg text-[18px]"
              style={{ background: `${source.color}12` }}
            >
              {source.icon}
            </div>
            <div>
              <h3 className="text-[13px] font-semibold text-[var(--fg-primary)]">{source.name}</h3>
              <p className="text-[11px] text-[var(--fg-muted)]">{source.category}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {iocCount > 0 && (
              <span className="text-[11px] font-medium tabular-nums text-[var(--fg-muted)]" style={{ fontFeatureSettings: '"tnum"' }}>
                {iocCount.toLocaleString()} IOCs
              </span>
            )}
            <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-medium ${
              status === "active" || status === "connected"
                ? "bg-emerald-500/10 text-emerald-500"
                : status === "error"
                  ? "bg-red-500/10 text-red-500"
                  : "bg-zinc-500/10 text-zinc-400"
            }`}>
              <span className={`h-1.5 w-1.5 rounded-full ${
                status === "active" || status === "connected"
                  ? "bg-emerald-500"
                  : status === "error"
                    ? "bg-red-500"
                    : "bg-zinc-400"
              }`} />
              {status === "active" || status === "connected" ? "Active" : status === "error" ? "Error" : "Standby"}
            </span>
            <svg
              width="14"
              height="14"
              viewBox="0 0 16 16"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              className={`text-[var(--fg-muted)] transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}
            >
              <path d="M4 6l4 4 4-4" />
            </svg>
          </div>
        </div>
      </button>

      {isExpanded && (
        <div className="border-t border-[var(--border-subtle)] px-5 pb-5 space-y-4">
          <p className="text-[12px] text-[var(--fg-secondary)] leading-relaxed pt-4">
            {source.description}
          </p>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">IOCs Indexed</p>
              <p className="mt-1 text-[16px] font-bold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>
                {iocCount.toLocaleString()}
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Last Sync</p>
              <p className="mt-1 text-[12px] font-medium text-[var(--fg-primary)]">
                {lastSync || "Active"}
              </p>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Indicator Types</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {source.indicators.slice(0, 3).map((ind) => (
                  <span key={ind} className="rounded px-1.5 py-0.5 text-[9px] font-mono font-medium text-[var(--fg-secondary)] bg-[var(--bg-surface)]">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Status</p>
              <p className="mt-1 text-[12px] font-medium text-emerald-500">Operational</p>
            </div>
          </div>

          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Capabilities</p>
            <div className="flex flex-wrap gap-1.5">
              {source.capabilities.map((cap) => (
                <span key={cap} className="rounded-md border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-2 py-0.5 text-[10px] font-medium text-[var(--fg-secondary)]">
                  {cap}
                </span>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2 pt-3 border-t border-[var(--border-subtle)]">
            <button className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--bg-inset)] px-3 py-1.5 text-[11px] font-medium text-[var(--fg-secondary)] transition-all hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]">
              Configure
            </button>
            <button className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--bg-inset)] px-3 py-1.5 text-[11px] font-medium text-[var(--fg-secondary)] transition-all hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]">
              Test Connection
            </button>
            <button className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--bg-inset)] px-3 py-1.5 text-[11px] font-medium text-[var(--fg-secondary)] transition-all hover:bg-[var(--bg-surface-hover)] hover:text-[var(--fg-primary)]">
              View Logs
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatIntelligence() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");
  const [expandedSource, setExpandedSource] = useState(null);
  const [feedStates, setFeedStates] = useState({});
  const [loadingFeeds, setLoadingFeeds] = useState(true);

  useEffect(() => {
    const loadFeeds = async () => {
      try {
        const data = await api.intelFeeds().catch(() => ({ feeds: [] }));
        const states = {};
        for (const feed of data.feeds || []) {
          states[feed.name?.toLowerCase().replace(/\s+/g, "_")] = {
            status: feed.last_error ? "error" : feed.last_success_at ? "connected" : "active",
            lastSync: feed.last_success_at ? formatTimeAgo(feed.last_success_at) : null,
            ioc_count: feed.ioc_count || 0,
          };
        }
        setFeedStates(states);
      } catch {
        // defaults
      } finally {
        setLoadingFeeds(false);
      }
    };
    loadFeeds();
    const iv = setInterval(loadFeeds, 30000);
    return () => clearInterval(iv);
  }, []);

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return;
    setSearching(true);
    setError("");
    try {
      const data = await api.intelLookup(query.trim());
      setResult(data);
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setSearching(false);
    }
  }, [query]);

  const handleKeyDown = useCallback((e) => {
    if (e.key === "Enter") handleSearch();
  }, [handleSearch]);

  const stats = useMemo(() => {
    const active = TI_SOURCES.filter((s) => {
      const st = feedStates[s.id]?.status || s.status;
      return st === "active" || st === "connected";
    }).length;
    const totalIocs = Object.values(feedStates).reduce((sum, f) => sum + (f.ioc_count || 0), 0);
    return { active, total: TI_SOURCES.length, totalIocs };
  }, [feedStates]);

  return (
    <div className="space-y-6 pb-10 pt-1">
      <header>
        <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">Intelligence</p>
        <h1 className="mt-1 text-page-title text-[var(--fg-primary)]">Threat Intelligence</h1>
        <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">
          Indicator enrichment, reputation analysis, and IOC management
        </p>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Active Sources</p>
          <p className="mt-1 text-[24px] font-bold tabular-nums text-[var(--accent-cyan)]" style={{ fontFeatureSettings: '"tnum"' }}>
            {stats.active}<span className="text-[14px] text-[var(--fg-muted)]">/{stats.total}</span>
          </p>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">IOCs Indexed</p>
          <p className="mt-1 text-[24px] font-bold tabular-nums text-[var(--fg-primary)]" style={{ fontFeatureSettings: '"tnum"' }}>
            {stats.totalIocs.toLocaleString()}
          </p>
        </div>
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">Last Refresh</p>
          <p className="mt-1 text-[14px] font-medium text-[var(--fg-primary)]">
            {new Date().toLocaleTimeString()}
          </p>
        </div>
      </div>

      {/* Search */}
      <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--fg-faint)]">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
              </svg>
            </span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Enter IP address, domain, hash, or URL..."
              className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--bg-inset)] py-2.5 pl-10 pr-3 text-[13px] text-[var(--fg-primary)] placeholder:text-[var(--fg-faint)] transition-colors focus:border-[var(--accent-cyan)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-cyan)]/20"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={searching || !query.trim()}
            className="rounded-lg bg-[var(--accent-cyan)] px-5 py-2.5 text-[13px] font-semibold text-white transition-all hover:brightness-110 disabled:opacity-40"
          >
            {searching ? "Analyzing..." : "Analyze"}
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Results */}
      {result && (
        <div className="rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-[14px] font-bold text-[var(--fg-primary)]">Indicator Analysis</h2>
              <p className="text-[11px] text-[var(--fg-muted)] mt-0.5">Enriched from {stats.active} active sources</p>
            </div>
            <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold ${
              result.category === "malicious"
                ? "bg-red-500/10 text-red-500"
                : result.category === "suspicious"
                  ? "bg-amber-500/10 text-amber-500"
                  : "bg-emerald-500/10 text-emerald-500"
            }`}>
              {result.category === "malicious" ? "\u26A0\uFE0F" : result.category === "suspicious" ? "\u26A0" : "\u2705"}
              {(result.category || "unknown").toUpperCase()}
            </span>
          </div>

          <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
            <p className="font-mono text-[14px] font-semibold text-[var(--fg-primary)]">{result.indicator || query}</p>
          </div>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: "Confidence", value: `${Math.round((result.confidence || 0) * 100)}%`, color: result.confidence > 0.7 ? "var(--severity-critical)" : "var(--fg-primary)" },
              { label: "Category", value: (result.category || "unknown").charAt(0).toUpperCase() + (result.category || "unknown").slice(1), color: "var(--fg-primary)" },
              { label: "Sources", value: result.sources?.length || 0, color: "var(--accent-cyan)" },
              { label: "Label", value: result.label || "No data", color: "var(--fg-secondary)" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)]">{s.label}</p>
                <p className="mt-1 text-[13px] font-semibold truncate" style={{ color: s.color }}>
                  {s.value}
                </p>
              </div>
            ))}
          </div>

          {result.sources?.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Data Sources</p>
              <div className="flex flex-wrap gap-1.5">
                {result.sources.map((src) => (
                  <span key={src} className="rounded-md bg-[var(--accent-cyan)]/10 px-2 py-0.5 text-[10px] font-medium text-[var(--accent-cyan)]">
                    {src}
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.details && (
            <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-[var(--fg-muted)] mb-2">Raw Intelligence</p>
              <pre className="text-[11px] font-mono text-[var(--fg-secondary)] whitespace-pre-wrap max-h-40 overflow-y-auto">
                {typeof result.details === "string" ? result.details : JSON.stringify(result.details, null, 2)}
              </pre>
            </div>
          )}

          <div className="flex gap-2 pt-2 border-t border-[var(--border-subtle)]">
            <button
              onClick={() => api.intelMarkMalicious(query.trim()).then(() => alert("Indicator marked as malicious"))}
              className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-[11px] font-semibold text-red-500 transition-all hover:bg-red-500/20"
            >
              Mark Malicious
            </button>
            <button className="rounded-lg border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--border-strong)] hover:text-[var(--fg-primary)]">
              Add to Watchlist
            </button>
            <button className="rounded-lg border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--border-strong)] hover:text-[var(--fg-primary)]">
              Create Detection Rule
            </button>
          </div>
        </div>
      )}

      {/* Sources */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-[16px] font-bold text-[var(--fg-primary)]">Intelligence Sources</h2>
            <p className="text-[12px] text-[var(--fg-muted)]">{TI_SOURCES.length} providers integrated</p>
          </div>
          <button className="rounded-lg border border-[var(--border-default)] px-3 py-1.5 text-[11px] font-semibold text-[var(--fg-muted)] transition-all hover:border-[var(--accent-cyan)]/40 hover:text-[var(--accent-cyan)]">
            + Add Provider
          </button>
        </div>

        {loadingFeeds ? (
          <Loading label="Loading feed status" />
        ) : (
          <div className="space-y-2">
            {TI_SOURCES.map((source) => (
              <SourceCard
                key={source.id}
                source={source}
                isExpanded={expandedSource === source.id}
                onToggle={() => setExpandedSource(expandedSource === source.id ? null : source.id)}
                feedState={feedStates[source.id]}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function formatTimeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default memo(ThreatIntelligence);
