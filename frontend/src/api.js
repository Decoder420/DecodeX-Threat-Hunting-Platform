import axios from "axios";

const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL || "http://127.0.0.1:5000";

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

export const syncFeeds = () =>
  api.post("/admin/feeds/sync");

export const executeSoarAction = (action, target) =>
  api.post("/soar/action", {
    action,
    target,
  });

export const updateAlertCase = (alertId, payload) =>
  api.post(`/alerts/${alertId}/case`, payload);

export default api;
