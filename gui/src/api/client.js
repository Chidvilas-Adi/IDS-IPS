import axios from 'axios';
import toast from 'react-hot-toast';
import useAuthStore from '../store/authStore';

const BASE_URL = process.env.REACT_APP_API_URL || '';

const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: attach JWT
apiClient.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Flag to prevent multiple simultaneous refresh attempts
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Response interceptor: handle 401 with token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return apiClient(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = useAuthStore.getState().getRefreshToken();

      if (!refreshToken) {
        useAuthStore.getState().logout();
        window.location.href = '/login';
        return Promise.reject(error);
      }

      try {
        const response = await axios.post(`${BASE_URL}/api/auth/refresh`, {
          refresh_token: refreshToken,
        });

        const { access_token, refresh_token: newRefresh } = response.data;
        useAuthStore.getState().login(
          access_token,
          newRefresh || refreshToken,
          useAuthStore.getState().user
        );

        processQueue(null, access_token);
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        useAuthStore.getState().logout();
        toast.error('Session expired. Please log in again.');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    // Handle other errors
    if (error.response?.status === 403) {
      toast.error('Access denied: insufficient permissions.');
    } else if (error.response?.status >= 500) {
      toast.error(`Server error: ${error.response?.data?.detail || 'Internal server error'}`);
    } else if (!error.response) {
      toast.error('Network error: cannot reach API server.');
    }

    return Promise.reject(error);
  }
);

// Convenience methods
export const api = {
  // Auth
  login: (username, password) =>
    apiClient.post('/api/auth/login', { username, password }),
  logout: () => apiClient.post('/api/auth/logout'),

  // Stats
  getStats: () => apiClient.get('/api/stats/overview'),
  getAlertsByHour: () => apiClient.get('/api/stats/alerts/timeseries'),
  getSeverityDistribution: () => apiClient.get('/api/stats/severity-distribution'),
  getProtocolBreakdown: () => apiClient.get('/api/stats/protocol-breakdown'),
  getTopAttackers: () => apiClient.get('/api/stats/top-attackers'),
  getEngineHealth: () => apiClient.get('/health'),

  // Alerts
  getAlerts: (params) => apiClient.get('/api/alerts', { params }),
  getAlert: (id) => apiClient.get(`/api/alerts/${id}`),
  acknowledgeAlert: (id) => apiClient.patch(`/api/alerts/${id}/status`, { status: 'acknowledged' }),
  markFalsePositive: (id) => apiClient.patch(`/api/alerts/${id}/status`, { status: 'false_positive' }),
  assignAlert: (id, user) => apiClient.post(`/api/alerts/${id}/assign`, { assigned_to: user }),
  exportAlerts: (params) => apiClient.get('/api/alerts/export/csv', { params, responseType: 'blob' }),

  // Block IP
  blockIP: (ip, reason, duration_minutes = 60) =>
    apiClient.post('/api/threats/blocked-ips', { ip_address: ip, reason, duration_minutes }),
  unblockIP: (id) => apiClient.delete(`/api/threats/blocked-ips/${id}`),

  // Rules
  getRules: (type) => apiClient.get('/api/rules', { params: { type } }),
  createRule: (rule) => apiClient.post('/api/rules', rule),
  updateRule: (id, rule) => apiClient.put(`/api/rules/${id}`, rule),
  deleteRule: (id) => apiClient.delete(`/api/rules/${id}`),
  toggleRule: (id, enabled) => apiClient.patch(`/api/rules/${id}/toggle`, { enabled }),
  importSnortRules: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return apiClient.post('/api/rules/import/snort', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  testRule: (packet) => apiClient.post('/api/rules/test', { packet }),

  // Playbooks
  getPlaybooks: () => apiClient.get('/api/playbooks'),
  getPlaybook: (id) => apiClient.get(`/api/playbooks/${id}`),
  createPlaybook: (pb) => apiClient.post('/api/playbooks', pb),
  updatePlaybook: (id, pb) => apiClient.put(`/api/playbooks/${id}`, pb),
  deletePlaybook: (id) => apiClient.delete(`/api/playbooks/${id}`),
  executePlaybook: (id, context) => apiClient.post(`/api/playbooks/${id}/execute`, context),
  getPlaybookHistory: (id) => apiClient.get(`/api/playbooks/${id}/history`),

  // Threat Intel
  getIOCStats: () => apiClient.get('/api/threat-intel/stats'),
  searchIOC: (query) => apiClient.get('/api/threat-intel/search', { params: { q: query } }),
  getIOCs: (type, params) => apiClient.get(`/api/threat-intel/iocs/${type}`, { params }),
  pollFeed: (feedId) => apiClient.post(`/api/threat-intel/feeds/${feedId}/poll`),
  getFeeds: () => apiClient.get('/api/threat-intel/feeds'),
  lookupReputation: (ip) => apiClient.get(`/api/threat-intel/reputation/${ip}`),
  getGeoRules: () => apiClient.get('/api/rules/geo'),
  getIOCMap: () => apiClient.get('/api/threat-intel/map'),

  // Sessions
  getSessions: (params) => apiClient.get('/api/sessions', { params }),
  getSession: (id) => apiClient.get(`/api/sessions/${id}`),
  killSession: (id) => apiClient.post(`/api/sessions/${id}/kill`),

  // Forensics
  getPackets: (params) => apiClient.get('/api/forensics/packets', { params }),
  getDNSLogs: (params) => apiClient.get('/api/forensics/dns', { params }),
  getHTTPLogs: (params) => apiClient.get('/api/forensics/http', { params }),
  getTLSLogs: (params) => apiClient.get('/api/forensics/tls', { params }),
  downloadPCAP: (alertId) =>
    apiClient.get(`/api/forensics/pcap/${alertId}`, { responseType: 'blob' }),

  // Network Topology
  getTopologyNodes: (params) => apiClient.get('/api/topology/nodes', { params }),
  getTopologyEdges: (params) => apiClient.get('/api/topology/edges', { params }),

  // Compliance
  getComplianceChecks: (framework) =>
    apiClient.get('/api/compliance/checks', { params: { framework } }),
  runComplianceChecks: () => apiClient.post('/api/compliance/checks/run'),
  getAuditLogs: (params) => apiClient.get('/api/compliance/audit-logs', { params }),
  getReports: () => apiClient.get('/api/compliance/reports'),
  generateReport: (framework) =>
    apiClient.post('/api/compliance/reports/generate', { framework }),
  downloadReport: (id) =>
    apiClient.get(`/api/compliance/reports/${id}/download`, { responseType: 'blob' }),

  // NoSQL Explorer
  getCollections: () => apiClient.get('/api/nosql/collections'),
  getDocuments: (collection, params) =>
    apiClient.get(`/api/nosql/collections/${collection}/documents`, { params }),
  queryCollection: (collection, filter) =>
    apiClient.post(`/api/nosql/collections/${collection}/query`, { filter }),
  getSessionGraph: (id) => apiClient.get(`/api/nosql/session-graphs/${id}`),
  getCanaryLogs: () => apiClient.get('/api/nosql/canary-logs'),
};

export default apiClient;
