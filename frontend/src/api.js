const BASE = import.meta.env.DEV ? "" : "";
const API_KEY = import.meta.env.VITE_API_KEY || "sentinel-dev-admin";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || body.message || detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  get: (path) => request(path),
  post: (path, body) =>
    request(path, { method: "POST", body: JSON.stringify(body ?? {}) }),
  patch: (path, body) =>
    request(path, { method: "PATCH", body: JSON.stringify(body ?? {}) }),

  summary: () => request("/api/dashboard/summary"),
  timeline: (hours = 24) => request(`/api/dashboard/timeline?hours=${hours}`),
  threatCategories: () => request("/api/dashboard/threat-categories"),
  severityDistribution: () => request("/api/dashboard/severity-distribution"),
  attackStats: () => request("/api/dashboard/attack-stats"),
  topAttackers: (limit = 5) => request(`/api/dashboard/top-attackers?limit=${limit}`),
  userBehavior: (limit = 8) => request(`/api/dashboard/user-behavior?limit=${limit}`),
  detectionMethods: () => request("/api/dashboard/detection-methods"),
  riskDistribution: () => request("/api/dashboard/risk-distribution"),

  evaluationRun: () => request("/api/evaluation/run?with_ml=true", { method: "POST" }),
  evaluationResults: (limit = 50) => request(`/api/evaluation/results?limit=${limit}`),
  evaluationLatest: () => request("/api/evaluation/latest"),

  alerts: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/alerts?${qs.toString()}`);
  },
  alert: (id) => request(`/api/alerts/${id}`),
  setAlertStatus: (id, status) => request(`/api/alerts/${id}/status`, { method: "PATCH", body: JSON.stringify({ status }) }),
  addAlertNote: (id, note) => request(`/api/alerts/${id}/notes`, { method: "POST", body: JSON.stringify({ note }) }),

  events: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/events?${qs.toString()}`);
  },
  processes: (limit = 200) => request(`/api/processes?limit=${limit}`),
  network: (limit = 200) => request(`/api/network?limit=${limit}`),
  eventStatistics: () => request("/api/events/statistics"),

  investigate: (alertId) => request(`/api/investigation/alert/${alertId}`),

  assistantChat: (message) => request("/api/assistant/chat", { method: "POST", body: JSON.stringify({ message }) }),
  assistantHistory: () => request("/api/assistant/history"),
  assistantExplain: (alertId) =>
    request("/api/assistant/explain", { method: "POST", body: JSON.stringify({ alert_id: alertId }) }),
  assistantSummarize: () => request("/api/assistant/summarize", { method: "POST" }),

  generateReport: (reportType, format) =>
    request("/api/reports/generate", { method: "POST", body: JSON.stringify({ report_type: reportType, format }) }),
  listReports: () => request("/api/reports/list"),

  systemStatus: () => request("/api/system/status"),
  collect: () => request("/api/system/collect", { method: "POST" }),
  mlStatus: () => request("/api/system/ml/status"),
  mlTrain: () => request("/api/system/ml/train", { method: "POST" }),
  mlAnalyze: () => request("/api/system/ml/analyze", { method: "POST" }),
};
