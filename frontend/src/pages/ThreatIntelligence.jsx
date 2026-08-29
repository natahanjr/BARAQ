import { memo, useCallback, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button, SearchInput } from "../components/ui/index.js";

function ThreatIntelligence() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");

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

  return (
    <div className="space-y-5 pb-10">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Search indicators, check reputation, and manage watchlists"
      />

      {/* Search */}
      <Card>
        <div className="flex items-center gap-3">
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Search IP, domain, hash, or URL..."
            className="flex-1"
            debounce={0}
          />
          <Button onClick={handleSearch} loading={searching} size="md">
            Lookup
          </Button>
        </div>
      </Card>

      {/* Error */}
      {error && <ErrorBanner message={error} />}

      {/* Results */}
      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Indicator Lookup</CardTitle>
            <Badge severity={result.reputation === "malicious" ? "critical" : result.reputation === "suspicious" ? "high" : "info"} size="sm">
              {result.type?.toUpperCase() || "INDICATOR"}
            </Badge>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                <p className="font-mono text-[14px] font-semibold text-[var(--fg-primary)]">{result.indicator || query}</p>
              </div>
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Reputation</p>
                  <p className="mt-0.5 text-[14px] font-semibold text-[var(--fg-primary)] capitalize">{result.reputation || "unknown"}</p>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Risk Score</p>
                  <p className="mt-0.5 text-[14px] font-semibold text-[var(--fg-primary)]">{result.risk_score ?? 0}</p>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">First Seen</p>
                  <p className="mt-0.5 text-[14px] font-semibold text-[var(--fg-primary)]">
                    {result.first_seen ? new Date(result.first_seen).toLocaleDateString() : "\u2014"}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Last Seen</p>
                  <p className="mt-0.5 text-[14px] font-semibold text-[var(--fg-primary)]">
                    {result.last_seen ? new Date(result.last_seen).toLocaleDateString() : "\u2014"}
                  </p>
                </div>
              </div>
              {result.details && (
                <div className="rounded-[var(--radius-lg)] border border-[var(--border-subtle)] bg-[var(--bg-inset)] p-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)] mb-2">Details</p>
                  <pre className="text-[12px] font-mono text-[var(--fg-secondary)] whitespace-pre-wrap">{typeof result.details === "string" ? result.details : JSON.stringify(result.details, null, 2)}</pre>
                </div>
              )}
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={() => api.intelMarkMalicious(query.trim()).then(() => alert("Marked as malicious"))}>Mark Malicious</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Feed Status */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {[
          { name: "AbuseIPDB", status: "connected", lastSync: "2 min ago" },
          { name: "AlienVault OTX", status: "connected", lastSync: "5 min ago" },
          { name: "VirusTotal", status: "connected", lastSync: "1 min ago" },
        ].map((feed) => (
          <Card key={feed.name} hover>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[13px] font-semibold text-[var(--fg-primary)]">{feed.name}</p>
                <p className="text-[11px] text-[var(--fg-muted)]">Last sync: {feed.lastSync}</p>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-semibold bg-[var(--status-healthy-muted)] text-[var(--status-healthy)]">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--status-healthy)]" />
                {feed.status}
              </span>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

export default memo(ThreatIntelligence);
