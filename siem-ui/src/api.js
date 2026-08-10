import axios from "axios";

const API_BASE_URL = "https://f462-2401-4900-8844-5426-997a-c83e-.ngrok-free.app";

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// If a token is invalid/expired, the backend returns 401 — clear it and
// send the user back to login rather than silently failing every call.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

export const getDashboard = (range = "24h") =>
  api.get("/dashboard", {
    params: { range },
  });

export const getAlertContext = (alertId) =>
  api.get(`/alert_context/${alertId}`);

export const getAdminData = () =>
  api.get("/admin/data");

export const toggleFeed = (feedId) =>
  api.post(`/admin/feed/${feedId}/toggle`);

export const listYaraRules = () =>
  api.get("/admin/rules");

export const getRuleContent = (file) =>
  api.get("/admin/rules/content", {
    params: { file },
  });

export const saveYaraRule = (file, content) =>
  api.post("/admin/rules/save", {
    file,
    content,
  });

export const addSuppression = (indicator) =>
  api.post("/admin/suppressions/add", {
    indicator,
  });

export const syncFeeds = () =>
  api.post("/admin/feeds/sync");

export const executeSoarAction = (action, target) =>
  api.post("/soar/action", {
    action,
    target,
  });

export default api;
