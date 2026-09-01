const BASE = import.meta.env.DEV ? "" : "";
const API_KEY = import.meta.env.VITE_API_KEY || "";

// The session token is kept in memory only; persistence happens server-side
// via an httpOnly cookie so XSS can never read it (CWE-312 mitigation).
let sessionToken = null;

// Admin org filter ("" = all organizations). Analysts are always locked to
// their own org by the backend, so this is only ever attached for admins.
const ORG_KEY = "baraq-org-filter";

// Demo/test separation: seeded demo telemetry is excluded from every
// production view by default. Flipping the demo switch on appends
// include_demo=1 so the console explicitly shows demo data.
const DEMO_KEY = "baraq-demo-mode";

export const demoStore = {
  get enabled() {
    try {
      return localStorage.getItem(DEMO_KEY) === "1";
    } catch {
      return false;
    }
  },
  set enabled(value) {
    try {
      if (value) localStorage.setItem(DEMO_KEY, "1");
      else localStorage.removeItem(DEMO_KEY);
    } catch {
      /* private mode etc. */
    }
  },
};

// Append include_demo=1 to a params object when the console runs in demo
// mode; production stays clean unless the analyst opted in.
function demoParams(params = {}) {
  return demoStore.enabled ? { ...params, include_demo: 1 } : params;
}

// "&include_demo=1" suffix for URLs that already carry other params.
function qsSuffix(params = {}) {
  const qs = new URLSearchParams(demoParams(params)).toString();
  return qs ? `&${qs}` : "";
}

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
  if (res.status === 429) {
    let retryAfter = 5;
    try {
      const body = await res.json();
      retryAfter = body.retry_after_seconds || 5;
    } catch { /* ignore */ }
    throw new Error(`Rate limited. Retry after ${retryAfter}s`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (Array.isArray(body.detail)) {
        detail = body.detail
          .map((d) => d.msg || d.loc?.join(".") || JSON.stringify(d))
          .join("; ");
      } else {
        detail = body.detail || body.message || detail;
      }
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
  del: (path) => request(path, { method: "DELETE" }),

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

  summary: () => request("/api/dashboard/summary?" + new URLSearchParams(demoParams()).toString()),
  timeline: (hours = 24) =>
    request(`/api/dashboard/timeline?hours=${hours}` + qsSuffix(demoParams())),
  threatCategories: () => request("/api/dashboard/threat-categories" + qsSuffix(demoParams())),
  severityDistribution: () => request("/api/dashboard/severity-distribution" + qsSuffix(demoParams())),
  attackStats: () => request("/api/dashboard/attack-stats" + qsSuffix(demoParams())),
  topAttackers: (limit = 5) =>
    request(`/api/dashboard/top-attackers?limit=${limit}` + qsSuffix(demoParams())),
  userBehavior: (limit = 8) =>
    request(`/api/dashboard/user-behavior?limit=${limit}` + qsSuffix(demoParams())),
  detectionMethods: () => request("/api/dashboard/detection-methods" + qsSuffix(demoParams())),
  riskDistribution: () => request("/api/dashboard/risk-distribution" + qsSuffix(demoParams())),

  // Detections (v2 detector catalog)
  detections: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(demoParams(params)).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/detections?${qs.toString()}`);
  },
  detectionDetail: (id) => request(`/api/detections/${id}`),
  detectors: () => request("/api/detectors"),
  detectorDetail: (id) => request(`/api/detectors/${id}`),

  evaluationRun: () => request("/api/evaluation/run?with_ml=true", { method: "POST" }),
  evaluationFullDB: () => request("/api/evaluation/full-db?use_ml=true", { method: "POST" }),
  evaluationResults: (limit = 50) => request(`/api/evaluation/results?limit=${limit}`),
  evaluationLatest: () => request("/api/evaluation/latest"),

  alerts: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(demoParams(params)).forEach(([k, v]) => {
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
  fpAnalysis: () => request("/api/alerts/fp-analysis"),
  clusters: () => request("/api/alerts/clusters"),
  alertGroups: () => request("/api/alerts/groups"),
  alertVerdict: (id) => request(`/api/alerts/${id}/verdict`),
  submitAlertVerdict: (id, body) =>
    request(`/api/alerts/${id}/verdict`, { method: "POST", body: JSON.stringify(body) }),
  listSuppressions: () => request("/api/alerts/suppressions/list"),
  createSuppression: (body) =>
    request("/api/alerts/suppressions", { method: "POST", body: JSON.stringify(body) }),
  deleteSuppression: (id) =>
    request(`/api/alerts/suppressions/${id}`, { method: "DELETE" }),

  events: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(demoParams(params)).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/events?${qs.toString()}`);
  },
  processes: (limit = 200) => request(`/api/processes?limit=${limit}`),
  network: (limit = 500, opts = {}) => {
    const p = new URLSearchParams({ limit });
    if (opts.since) p.set("since", opts.since);
    if (opts.direction) p.set("direction", opts.direction);
    if (opts.remote_ip) p.set("remote_ip", opts.remote_ip);
    return request(`/api/network?${p.toString()}`);
  },
  dns: (limit = 200, process = null) => {
    const p = new URLSearchParams({ limit });
    if (process) p.set("process", process);
    return request(`/api/dns?${p.toString()}`);
  },
  http: (limit = 200, host = null, method = null) => {
    const p = new URLSearchParams({ limit });
    if (host) p.set("host", host);
    if (method) p.set("method", method);
    return request(`/api/http?${p.toString()}`);
  },
  networkStats: () => request("/api/network/stats"),
  ipGeo: (ip) => request(`/api/network/geo?ip=${encodeURIComponent(ip)}`),
  suppressions: () => request("/api/alerts/suppressions/list"),
  eventStatistics: () => request("/api/events/statistics"),

  datasetStatus: () => request("/api/telemetry/dataset"),
  datasetStats: () => request("/api/telemetry/dataset/stats"),
  datasetExports: (limit = 20) => request(`/api/telemetry/dataset/exports?limit=${limit}`),
  datasetExportDetail: (id) => request(`/api/telemetry/dataset/exports/${id}`),
  datasetManifest: () => request("/api/telemetry/dataset/manifest"),
  datasetStart: () => request("/api/telemetry/dataset/start", { method: "POST" }),
  datasetPause: () => request("/api/telemetry/dataset/pause", { method: "POST" }),
  datasetResume: () => request("/api/telemetry/dataset/resume", { method: "POST" }),
  datasetExportNow: () => request("/api/telemetry/dataset/export", { method: "POST" }),
  datasetUpdateConfig: (body) =>
    request("/api/telemetry/dataset/config", { method: "POST", body: JSON.stringify(body) }),
  datasetDownload: async (fileId) => {
    const headers = {};
    if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
    else headers["X-API-Key"] = API_KEY;
    const res = await fetch(`${BASE}/api/telemetry/dataset/download/${fileId}`, {
      headers,
      credentials: "include",
    });
    if (!res.ok) throw new Error(`${res.status}: ${res.statusText}`);
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const name = (cd.match(/filename="?([^";]+)"?/) || [])[1] || `part_${fileId}.csv`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  },

  investigate: (alertId) => request(`/api/investigation/alert/${alertId}`),
  processTree: (params) =>
    request(`/api/investigation/process-tree?${new URLSearchParams(params).toString()}`),
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
  healthCheck: () => fetch("/api/health", { cache: "no-store", headers: { "Cache-Control": "no-cache" } }).then((r) => { if (!r.ok) throw new Error("unreachable"); return r.json(); }),
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
    Object.entries(demoParams(params)).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/incidents?${qs.toString()}`);
  },
  incident: (id) => request(`/api/incidents/${id}`),
  incidentInvestigation: (id) => request(`/api/incidents/${id}/investigation`),
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
  intelFeeds: () => request("/api/intel/feeds"),
  intelRefreshFeeds: () => request("/api/intel/feeds/refresh", { method: "POST" }),
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
  mlRobustness: () => request("/api/system/ml/robustness"),
  mlOnlineLearning: () => request("/api/system/ml/online-learning"),
  mlTemporalBias: (hours = 24) => request(`/api/system/ml/temporal-bias?hours=${hours}`),
  mlFederated: () => request("/api/system/ml/federated"),
  mlCommunityRules: () => request("/api/system/ml/community-rules"),
  mlRemediation: () => request("/api/system/ml/remediation"),
  mlComparison: () => request("/api/system/ml/comparison"),
  mlRetention: () => request("/api/system/ml/retention"),
  mlEnsemble: () => request("/api/system/ml/ensemble"),

  rbaEntities: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(demoParams(params)).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    });
    return request(`/api/rba/entities?${qs.toString()}`);
  },
  rbaEntity: (kind, name, timelineLimit = 100) =>
    request(
      `/api/rba/entities/${encodeURIComponent(kind)}/${encodeURIComponent(name)}?timeline_limit=${timelineLimit}` +
        qsSuffix(demoParams()),
    ),
  rbaRules: () => request("/api/rba/rules"),
  rbaDecay: () => request("/api/rba/decay", { method: "POST" }),
  rbaSync: (hours = 24) => request(`/api/rba/sync?hours=${hours}`, { method: "POST" }),
  rbaTuning: () => request("/api/rba/tuning"),
  rbaSetTuning: (body) => request("/api/rba/tuning", { method: "PUT", body: JSON.stringify(body) }),

  search: (query, opts = {}) => {
    const body = { query, ...(opts.earliest ? { earliest: opts.earliest } : {}), ...(opts.latest ? { latest: opts.latest } : {}) };
    if (opts.limit) body.limit = opts.limit;
    if (demoStore.enabled) body.include_demo = 1;
    return request("/api/search", { method: "POST", body: JSON.stringify(body) });
  },
  searchSuggest: (q) => request(`/api/search/suggest?q=${encodeURIComponent(q)}`),

  automationPlaybooks: () => request("/api/automation/playbooks"),
  automationCreatePlaybook: (body) => request("/api/automation/playbooks", { method: "POST", body: JSON.stringify(body) }),
  automationUpdatePlaybook: (id, body) => request(`/api/automation/playbooks/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  automationDeletePlaybook: (id) => request(`/api/automation/playbooks/${id}`, { method: "DELETE" }),
  automationTestPlaybook: (id, alertId) => request(`/api/automation/playbooks/${id}/test?alert_id=${alertId}`, { method: "POST" }),
  automationRunPlaybook: (id, alertId) => request(`/api/automation/playbooks/${id}/run?alert_id=${alertId}`, { method: "POST" }),
  automationRuns: (limit = 50, alertId) =>
    request(`/api/automation/runs?limit=${limit}${alertId ? `&alert_id=${alertId}` : ""}`),
  automationPreview: (alertId) => request(`/api/automation/preview?alert_id=${alertId}`),

  savedSearches: () => request("/api/saved/searches"),
  saveSearch: (body) => request("/api/saved/searches", { method: "POST", body: JSON.stringify(body) }),
  updateSavedSearch: (id, body) => request(`/api/saved/searches/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteSavedSearch: (id) => request(`/api/saved/searches/${id}`, { method: "DELETE" }),
  runSavedSearch: (id) => request(`/api/saved/searches/${id}/run` + qsSuffix(demoParams()), { method: "POST" }),
  dashboards: () => request("/api/saved/dashboards"),
  createDashboard: (body) => request("/api/saved/dashboards", { method: "POST", body: JSON.stringify(body) }),
  updateDashboard: (id, body) => request(`/api/saved/dashboards/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteDashboard: (id) => request(`/api/saved/dashboards/${id}`, { method: "DELETE" }),
  renderDashboard: (id) => request(`/api/saved/dashboards/${id}/render` + qsSuffix(demoParams())),

  exportTypes: () => request("/api/export/types"),
  exportData: (dataType, params = {}) => {
    const qs = new URLSearchParams({ format: params.format || "csv", limit: params.limit || 10000 });
    if (params.since) qs.set("since", params.since);
    if (params.severity) qs.set("severity", params.severity);
    if (params.status) qs.set("status", params.status);
    if (params.search) qs.set("search", params.search);
    if (params.offset) qs.set("offset", params.offset);
    return `/api/export/${dataType}?${qs.toString()}`;
  },
};