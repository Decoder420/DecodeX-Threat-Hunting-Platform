import api from "./api";

/** Clean Web Application Security API helpers. */
export const webApi = {
  getOverview: () => api.get("/web/overview"),
  getTargets: () => api.get("/web-targets"),
  getTarget: (id) => api.get(`/web-targets/${id}`),
  createTarget: (payload) => api.post("/web-targets", payload),
  updateTarget: (id, payload) => api.patch(`/web-targets/${id}`, payload),
  authorizeTarget: (id) =>
    api.post(`/web-targets/${id}/authorize`, { confirm: true }),
  disableTarget: (id) => api.delete(`/web-targets/${id}`),

  getScans: (params) => api.get("/web-scans", { params }),
  createScan: (payload) => api.post("/web-scans", payload),
  getScan: (id) => api.get(`/web-scans/${id}`),
  getScanProgress: (id) => api.get(`/web-scans/${id}/progress`),
  cancelScan: (id) => api.post(`/web-scans/${id}/cancel`),
  getScanFindings: (id) => api.get(`/web-scans/${id}/findings`),
  compareScans: (id, otherId) => api.get(`/web-scans/${id}/compare/${otherId}`),
  getScanReport: (id, format = "json") =>
    api.get(`/web-scans/${id}/report`, {
      params: { format },
      responseType: format === "csv" || format === "pdf" ? "blob" : "json",
    }),


  getFindings: (params) => api.get("/web-findings", { params }),
  getFinding: (id) => api.get(`/web-findings/${id}`),
  updateFinding: (id, payload) => api.patch(`/web-findings/${id}`, payload),
  createCaseFromFinding: (id, payload = {}) =>
    api.post(`/web-findings/${id}/case`, payload),

  getAttackSurface: (params) => api.get("/web/attack-surface", { params }),
  getTargetAttackSurface: (id) => api.get(`/web-targets/${id}/attack-surface`),
  getScanTree: (id) => api.get(`/web-scans/${id}/tree`),
  getScanEvents: (id, params) => api.get(`/web-scans/${id}/events`, { params }),
  resumeScan: (id) => api.post(`/web-scans/${id}/resume`),
  markFalsePositive: (id) => api.post(`/web-findings/${id}/false-positive`),
  suppressFinding: (id) => api.post(`/web-findings/${id}/suppress`),
  getScannerHealth: () => api.get("/webscan/health"),
  getScannerStatus: () => api.get("/web/scanner/status"),
  getEngines: () => api.get("/web/scanner/engines"),
};

export default webApi;
