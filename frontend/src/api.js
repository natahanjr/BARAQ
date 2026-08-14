const BASE = import.meta.env.DEV ? "" : "";
const API_KEY = import.meta.env.VITE_API_KEY || "baraq-dev-admin";

// The session token is kept in memory only; persistence happens server-side
// via an httpOnly cookie so XSS can never read it (CWE-312 mitigation).
let sessionToken = null;

// Admin org filter ("" = all organizations). Analysts are always locked to
// their own org by the backend, so this is only ever attached for admins.
const ORG_KEY = "baraq-org-filter";

export const authStore = {
  get token() {
    return sessionToken;
  },
  set(token) {
    sessionToken = token || null;
  },
  user: null,
  get org() {
    try {
      return localStorage.getItem(ORG_KEY) || "";
    } catch {
      return "";
    }
  },
  set org(value) {
    try {
      if (value) localStorage.setItem(ORG_KEY, value);
      else localStorage.removeItem(ORG_KEY);
    } catch {
      /* private mode etc. */
    }
  },
};

export const isAdmin = () => authStore.user?.role === "admin";

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  else headers["X-API-Key"] = API_KEY;

  // Multi-tenant: admins can narrow their view to one organization; the
  // backend ignores this header for non-admin callers.
  if (isAdmin() && authStore.org) headers["X-Org"] = authStore.org;

  // Double-submit CSRF token: the backend requires X-CSRF-Token to match the
  // baraq_csrf cookie on state-changing requests authenticated via the
  // session cookie (browser flow). Not needed for Bearer/API-key callers but
  // harmless, and keeps the cookie-authenticated path working after reloads.
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const csrf = document.cookie
      .split("; ")
      .find((c) => c.startsWith("baraq_csrf="));
    if (csrf) headers["X-CSRF-Token"] = decodeURIComponent(csrf.split("=")[1]);
  }

  const res = await fetch(`${BASE}${path}`, { ...options, headers, credentials: "include" });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("baraq:logout"));
  }
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

  login: (username, password) => request("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  register: (body) => request("/api/auth/register", { method: "POST", body: JSON.stringify(body) }),
  approveUser: (id) => request(`/api/auth/users/${id}/approve`, { method: "POST" }),
  rejectUser: (id) => request(`/api/auth/users/${id}/reject`, { method: "POST" }),
  changePassword: (currentPassword, newPassword) =>
    request("/api/auth/settings/change-password", { method: "POST", body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) }),
  renameAccount: (currentPassword, newUsername) =>
    request("/api/auth/settings/rename", { method: "POST", body: JSON.stringify({ current_password: currentPassword, new_username: newUsername }) }),
  mfaVerify: (challenge, code) => request("/api/auth/mfa/verify", { method: "POST", body: JSON.stringify({ challenge, code }) }),
  mfaSetup: () => request("/api/auth/mfa/setup", { method: "POST" }),
  mfaConfirm: (code) => request("/api/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisable: (code) => request("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code }) }),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  me: () => request("/api/auth/me"),
  users: () => request("/api/auth/users"),
  createUser: (body) => request("/api/auth/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id, body) => request(`/api/auth/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteUser: (id) => request(`/api/auth/users/${id}`, { method: "DELETE" }),
  audit: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/auth/audit?${qs.toString()}`);
  },
  clearAudit: () => request("/api/auth/audit/clear", { method: "POST" }),

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
  takeAction: (id, action, target = "") =>
    request(`/api/alerts/${id}/actions`, { method: "POST", body: JSON.stringify({ action, target }) }),
  fixAlert: (id) => api.takeAction(id, "fix"),
  clearAlerts: () => request("/api/alerts/clear", { method: "POST" }),

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
  endpoints: () => request("/api/endpoints"),
  sendCommand: (agentId, action, target, note = "") =>
    request(`/api/endpoints/${agentId}/commands`, { method: "POST", body: JSON.stringify({ action, target, note }) }),
  listCommands: (limit = 50) => request(`/api/commands?limit=${limit}`),
  listAgentCommands: (agentId, limit = 50) => request(`/api/endpoints/${agentId}/commands?limit=${limit}`),

  assistantChat: (message) => request("/api/assistant/chat", { method: "POST", body: JSON.stringify({ message }) }),
  assistantHistory: () => request("/api/assistant/history"),
  assistantClearHistory: () => request("/api/assistant/history", { method: "DELETE" }),
  assistantExplain: (alertId) =>
    request("/api/assistant/explain", { method: "POST", body: JSON.stringify({ alert_id: alertId }) }),
  assistantSummarize: () => request("/api/assistant/summarize", { method: "POST" }),
  assistantEntityExplain: (kind, name) =>
    request("/api/assistant/explain-entity", { method: "POST", body: JSON.stringify({ kind, name }) }),

  generateReport: (reportType, format) =>
    request("/api/reports/generate", { method: "POST", body: JSON.stringify({ report_type: reportType, format }) }),
  listReports: () => request("/api/reports/list"),

  systemStatus: () => request("/api/system/status"),
  collect: () => request("/api/system/collect", { method: "POST" }),
  dataQuality: () => request("/api/system/data-quality"),
  dataQualityHistory: () => request("/api/system/data-quality/history"),
  dataQualityRepair: (body) =>
    request("/api/system/data-quality/repair", {
      method: "POST",
      body: JSON.stringify(body ?? { reason: "manual" }),
    }),

  entities: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/entities?${qs.toString()}`);
  },
  entityStatus: () => request("/api/entities/status"),
  entityGraph: (kind, name, depth = 1) =>
    request(
      `/api/entities/graph?center_kind=${encodeURIComponent(kind)}&center_name=${encodeURIComponent(name)}&depth=${depth}`,
    ),
  entityOverview: (depth = 1) => request(`/api/entities/graph?depth=${depth}`),
  entityProfile: (kind, name, depth = 1) =>
    request(
      `/api/entities/${encodeURIComponent(kind)}/${encodeURIComponent(name)}?depth=${depth}`,
    ),
  syncEntities: () => request("/api/entities/sync", { method: "POST" }),

  incidents: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/incidents?${qs.toString()}`);
  },
  incident: (id) => request(`/api/incidents/${id}`),
  createIncident: (body) => request("/api/incidents", { method: "POST", body: JSON.stringify(body) }),
  updateIncident: (id, body) => request(`/api/incidents/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  linkIncidentAlerts: (id, alertIds) =>
    request(`/api/incidents/${id}/alerts`, { method: "POST", body: JSON.stringify({ alert_ids: alertIds }) }),
  addIncidentComment: (id, body, kind = "comment") =>
    request(`/api/incidents/${id}/comments`, { method: "POST", body: JSON.stringify({ body, kind }) }),
  intelLookup: (indicator, refresh = false) =>
    request(`/api/intel/lookup?${refresh ? "refresh=true" : ""}`, { method: "POST", body: JSON.stringify({ indicator }) }),
  intelAlert: (id, refresh = false) =>
    request(`/api/intel/alert/${id}?${refresh ? "refresh=true" : ""}`),
  intelMarkMalicious: (indicator) =>
    request("/api/intel/save", { method: "POST", body: JSON.stringify({ indicator }) }),
  mlStatus: () => request("/api/system/ml/status"),
  mlExplainAlert: (alertId, timeout = 60000) =>
    request(`/api/system/ml/explain/alert/${alertId}`, { signal: AbortSignal.timeout(timeout) }),
  mlExplainEvent: (eventId) => request(`/api/system/ml/explain/event/${eventId}`),
  mlTrain: (opts = {}) => {
    const qs = new URLSearchParams();
    if (opts.force) qs.set("force", "true");
    if (opts.sync !== false) qs.set("async_mode", "false");
    return request(`/api/system/ml/train?${qs.toString()}`, { method: "POST" });
  },
  mlAnalyze: () => request("/api/system/ml/analyze", { method: "POST" }),
};
