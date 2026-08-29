import { useState, useEffect, useCallback } from "react";
import { api } from "../api.js";

export function useBackendStatus() {
  const [status, setStatus] = useState(null);
  const [online, setOnline] = useState(null);
  const [orgOptions, setOrgOptions] = useState([]);

  const fetchStatus = useCallback(async () => {
    try {
      const health = await api.get("/api/health");
      setOnline(health?.status === "ok" || health?.status === "healthy");
    } catch {
      setOnline(false);
    }
    try {
      const sys = await api.get("/api/system/status");
      setStatus(sys);
    } catch {
      setStatus(null);
    }
    try {
      if (api.getOrgs) {
        const orgs = await api.getOrgs();
        setOrgOptions(Array.isArray(orgs) ? orgs : []);
      }
    } catch {
      setOrgOptions([]);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const id = setInterval(fetchStatus, 30000);
    return () => clearInterval(id);
  }, [fetchStatus]);

  // Compute counts from status data
  const activeAlerts = status?.active_alerts ?? status?.alerts?.active ?? 0;
  const criticalAlerts = status?.critical_alerts ?? status?.alerts?.critical ?? 0;
  const openIncidents = status?.open_incidents ?? status?.incidents?.open ?? 0;
  const criticalIncidents = status?.critical_incidents ?? status?.incidents?.critical ?? 0;

  return {
    status,
    online,
    activeAlerts,
    criticalAlerts,
    openIncidents,
    criticalIncidents,
    orgOptions,
    refresh: fetchStatus,
  };
}
