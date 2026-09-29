import axios from "axios";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8000/api/v1";

const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const authAPI = {
  login: (username: string, password: string) =>
    api.post("/auth/login", new URLSearchParams({ username, password })),
  getMe: () => api.get("/auth/me"),
};

export const dashboardAPI = {
  getSummary: () => api.get("/dashboard/summary"),
  getThreatMap: () => api.get("/dashboard/threat-map"),
  getMitreMatrix: () => api.get("/dashboard/mitre-matrix"),
  getTimeline: (hours: number = 24) => api.get(`/dashboard/timeline?hours=${hours}`),
};

export const alertsAPI = {
  list: (params?: any) => api.get("/alerts", { params }),
  get: (id: string) => api.get(`/alerts/${id}`),
  acknowledge: (id: string) => api.post(`/alerts/${id}/acknowledge`),
  markFalsePositive: (id: string, reason: string) =>
    api.post(`/alerts/${id}/false-positive`, null, { params: { reason } }),
  escalate: (id: string) => api.post(`/alerts/${id}/escalate`),
};

export const incidentsAPI = {
  list: (params?: any) => api.get("/incidents", { params }),
  get: (id: string) => api.get(`/incidents/${id}`),
  getReport: (id: string, type: string = "technical") =>
    api.get(`/incidents/${id}/report?report_type=${type}`),
  getTimeline: (id: string) => api.get(`/incidents/${id}/timeline`),
  getPlaybook: (id: string) => api.get(`/incidents/${id}/playbook`),
  updateStatus: (id: string, status: string) =>
    api.patch(`/incidents/${id}/status`, null, { params: { status } }),
};

export const investigationAPI = {
  query: (query: string, context: any = {}) =>
    api.post("/investigations/query", { query, context }),
  getAttackPath: (entityType: string, entityValue: string) =>
    api.get(`/investigations/attack-path/${entityType}/${entityValue}`),
};

export const threatIntelAPI = {
  lookupIOC: (value: string, type: string) =>
    api.post("/threat-intel/lookup", { value, type }),
  search: (query: string) =>
    api.post("/threat-intel/search", { query }),
};

export default api;
