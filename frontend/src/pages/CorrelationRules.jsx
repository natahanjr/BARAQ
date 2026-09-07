import { useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, CardHeader, CardTitle, CardContent, Badge, Button } from "../components/ui/index.js";

function CorrelationRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get("/api/correlations/rules");
        setRules(res.rules || []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner message={error} />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Correlation Rules"
        subtitle={`${rules.length} detection rules loaded`}
      />

      <div className="grid gap-4">
        {rules.map((rule, i) => (
          <Card key={rule.id || i}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{rule.name || rule.id}</CardTitle>
                <Badge severity={rule.enabled ? "info" : "low"} size="sm">
                  {rule.enabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-[var(--fg-secondary)]">
                {rule.description || "No description"}
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {rule.severity && (
                  <Badge severity={rule.severity} size="sm">
                    {rule.severity}
                  </Badge>
                )}
                {rule.mitre_id && (
                  <span className="rounded-md bg-[var(--bg-inset)] px-2 py-1 font-mono text-[10px] text-[var(--fg-secondary)]">
                    {rule.mitre_id}
                  </span>
                )}
                {rule.chain_length && (
                  <span className="rounded-md bg-[var(--bg-inset)] px-2 py-1 text-[10px] text-[var(--fg-secondary)]">
                    Chain: {rule.chain_length} steps
                  </span>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export default CorrelationRules;
