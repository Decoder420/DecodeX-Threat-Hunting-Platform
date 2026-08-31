import axios from "axios";
import { clearSession, getStoredToken } from "./auth";

// 1. Export it exactly once right here at the top
export const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "";

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use(
  (config) => {
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// If a token is invalid/expired, clear session and reload — except for
// login/logout, which are expected to return 401 in some cases.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response && error.response.status;
    const url = (error.config && error.config.url) || "";
    const isAuthEndpoint =
      url.includes("/auth/login") || url.includes("/auth/logout");

    if (status === 401 && !isAuthEndpoint) {
      clearSession();
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) => api.post("/auth/login", { username, password });

export const logout = () => api.post("/auth/logout", {});

export const getMe = () => api.get("/auth/me");

export const getDashboard = (range = "24h") =>
  api.get("/dashboard", {
    params: { range },
  });

export const getAlertContext = (alertId) =>
  api.get(`/alert_context/${alertId}`);

export const getAdminData = () => api.get("/admin/data");

export const toggleFeed = (feedId) =>
  api.post(`/admin/feed/${feedId}/toggle`);

export const listYaraRules = () => api.get("/admin/rules");

export const getRuleContent = (file) =>
  api.get("/admin/rules/content", {
    params: { file },
  });

export const saveYaraRule = (file, content) =>
  api.post("/admin/rules/save", {
    file,
    content,
  });

export const createYaraRule = (file, content = "") =>
  api.post("/admin/rules/create", {
    file,
    content,
  });

export const uploadYaraRules = (fileList) => {
  const form = new FormData();
  Array.from(fileList || []).forEach((file) => {
    form.append("files", file);
  });
  return api.post("/admin/rules/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
};

export const addSuppression = (indicator) =>
  api.post("/admin/suppressions/add", {
    indicator,
  });

export const syncFeeds = () => api.post("/admin/feeds/sync");

export const uploadLogFile = (file) => {
  const form = new FormData();
  form.append("file", file);
  return api.post("/ingest/upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
};

export const deleteAlert = (alertId) => api.delete(`/alerts/${alertId}`);

export const purgeAlerts = (payload = {}) => api.post("/alerts/purge", payload);

export const purgeEvents = (payload = {}) => api.post("/events/purge", payload);

export const getDatabaseMaintenance = () => api.get("/database/maintenance");

export const vacuumDatabase = () => api.post("/database/vacuum");



export const executeSoarAction = (action, target) =>
  api.post("/soar/action", {
    action,
    target,
  });

export const updateAlertCase = (alertId, payload) =>
  api.post(`/alerts/${alertId}/case`, payload);

export const listUsers = () => api.get("/admin/users");

export const createUser = (payload) => api.post("/admin/users", payload);

export const updateUserRole = (userId, role) =>
  api.post(`/admin/users/${userId}/role`, { role });

export const deactivateUser = (userId) =>
  api.post(`/admin/users/${userId}/deactivate`);

export const activateUser = (userId) =>
  api.post(`/admin/users/${userId}/activate`);

export const resetUserPassword = (userId, password) =>
  api.post(`/admin/users/${userId}/reset_password`, { password });

// --- Detection Engineering & Sigma Rule Studio APIs ---
export const listSigmaRules = () => api.get("/sigma/rules");
export const validateSigmaRule = (yaml) => api.post("/sigma/rules/validate", { yaml });
export const testSigmaRule = (payload) => api.post("/sigma/rules/test", payload);
export const saveSigmaRule = (yaml) => api.post("/sigma/rules/save", { yaml });
export const getMitreMatrix = () => api.get("/sigma/mitre-matrix");

// --- Webhooks & Continuous DAST Scheduling APIs ---
export const listWebhooks = () => api.get("/webhooks");
export const createWebhook = (payload) => api.post("/webhooks", payload);
export const updateWebhook = (id, payload) => api.put(`/webhooks/${id}`, payload);
export const deleteWebhook = (id) => api.delete(`/webhooks/${id}`);
export const testWebhook = (id) => api.post(`/webhooks/${id}/test`);
export const setTargetSchedule = (targetId, payload) => api.post(`/web-targets/${targetId}/schedule`, payload);

// --- OWASP ZAP & OpenAPI Scanner APIs ---
export const getZapStatus = () => api.get("/scanner/zap/status");
export const importTargetOpenApi = (targetId, payload) => api.post(`/web-targets/${targetId}/import-openapi`, payload);
export const startZapDaemon = () => api.post("/scanner/zap/daemon/start");
export const stopZapDaemon = () => api.post("/scanner/zap/daemon/stop");

export default api;