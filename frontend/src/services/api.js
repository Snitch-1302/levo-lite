import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
});

// Dashboard data
export const fetchDashboardData = async () => {
  try {
    const response = await api.get('/dashboard');
    return response.data;
  } catch (error) {
    // Fallback to mock data if API is not available
    return getMockDashboardData();
  }
};

// Discovery endpoints
export const fetchDiscoveryData = async () => {
  try {
    const response = await api.get('/discovery/endpoints');
    return response.data;
  } catch (error) {
    return getMockDiscoveryData();
  }
};

// Vulnerability data
export const fetchVulnerabilityData = async () => {
  try {
    const response = await api.get('/vulnerability/report');
    return response.data;
  } catch (error) {
    return getMockVulnerabilityData();
  }
};

// Sensitive data
export const fetchSensitiveData = async () => {
  try {
    const response = await api.get('/sensitive/report');
    return response.data;
  } catch (error) {
    return getMockSensitiveData();
  }
};

// Policy data
export const fetchPolicyData = async () => {
  try {
    const response = await api.get('/policy/report');
    return response.data;
  } catch (error) {
    return getMockPolicyData();
  }
};

// Reports
export const fetchReports = async () => {
  try {
    const response = await api.get('/reports');
    return response.data;
  } catch (error) {
    return getMockReportsData();
  }
};

// Export functions
export const exportReport = async (type, format = 'json') => {
  try {
    const response = await api.get(`/export/${type}`, {
      params: { format },
      responseType: 'blob',
    });
    
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `${type}_report.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch (error) {
    console.error('Export failed:', error);
  }
};

// Mock data for development
const getMockDashboardData = () => ({
  summary: {
    total_endpoints: 24,
    vulnerabilities: 8,
    critical_issues: 2,
    high_issues: 3,
    medium_issues: 2,
    low_issues: 1,
    policy_violations: 5,
    pii_exposures: 12,
    overall_status: 'WARNING'
  },
  recent_activity: [
    {
      id: 1,
      type: 'vulnerability',
      severity: 'critical',
      endpoint: '/api/users/{id}',
      description: 'IDOR vulnerability detected',
      timestamp: new Date().toISOString()
    },
    {
      id: 2,
      type: 'policy',
      severity: 'high',
      endpoint: '/api/admin/users',
      description: 'Policy violation: Unauthenticated admin access',
      timestamp: new Date(Date.now() - 3600000).toISOString()
    }
  ],
  charts: {
    vulnerabilities_by_severity: [
      { name: 'Critical', value: 2, color: '#ef4444' },
      { name: 'High', value: 3, color: '#f97316' },
      { name: 'Medium', value: 2, color: '#eab308' },
      { name: 'Low', value: 1, color: '#3b82f6' }
    ],
    endpoints_by_method: [
      { name: 'GET', value: 12, color: '#22c55e' },
      { name: 'POST', value: 8, color: '#3b82f6' },
      { name: 'PUT', value: 3, color: '#f59e0b' },
      { name: 'DELETE', value: 1, color: '#ef4444' }
    ]
  }
});

const getMockDiscoveryData = () => ({
  endpoints: [
    {
      id: 1,
      path: '/api/users',
      method: 'GET',
      status_code: 200,
      auth_required: true,
      sensitive_data: false,
      last_seen: new Date().toISOString(),
      call_count: 156
    },
    {
      id: 2,
      path: '/api/users/{id}',
      method: 'GET',
      status_code: 200,
      auth_required: true,
      sensitive_data: true,
      last_seen: new Date(Date.now() - 1800000).toISOString(),
      call_count: 89
    },
    {
      id: 3,
      path: '/api/admin/users',
      method: 'GET',
      status_code: 200,
      auth_required: false,
      sensitive_data: true,
      last_seen: new Date(Date.now() - 3600000).toISOString(),
      call_count: 23
    }
  ],
  summary: {
    total_endpoints: 24,
    authenticated: 18,
    unauthenticated: 6,
    with_sensitive_data: 8,
    methods: {
      GET: 12,
      POST: 8,
      PUT: 3,
      DELETE: 1
    }
  }
});

const getMockVulnerabilityData = () => ({
  vulnerabilities: [
    {
      id: 1,
      name: 'IDOR Vulnerability',
      severity: 'critical',
      endpoint: '/api/users/{id}',
      description: 'Users can access other users\' data by changing the ID parameter',
      cwe: 'CWE-639',
      evidence: 'Successfully accessed user 123 data with user 456 token',
      recommendation: 'Implement proper authorization checks',
      status: 'open'
    },
    {
      id: 2,
      name: 'Missing Authentication',
      severity: 'high',
      endpoint: '/api/admin/users',
      description: 'Admin endpoint accessible without authentication',
      cwe: 'CWE-306',
      evidence: 'Accessed admin endpoint without authentication token',
      recommendation: 'Add authentication middleware',
      status: 'open'
    }
  ],
  summary: {
    total: 8,
    critical: 2,
    high: 3,
    medium: 2,
    low: 1,
    open: 6,
    fixed: 2
  }
});

const getMockSensitiveData = () => ({
  matches: [
    {
      id: 1,
      data_type: 'email',
      field_name: 'email',
      location: 'request_body',
      endpoint: '/api/users',
      exposure_risk: 'high',
      value: 'user@example.com',
      masked: false
    },
    {
      id: 2,
      data_type: 'password',
      field_name: 'password',
      location: 'request_body',
      endpoint: '/api/auth/login',
      exposure_risk: 'critical',
      value: 'plaintext_password',
      masked: false
    }
  ],
  summary: {
    total_matches: 12,
    critical: 3,
    high: 5,
    medium: 3,
    low: 1,
    data_types: {
      email: 4,
      password: 2,
      phone: 3,
      ssn: 1,
      credit_card: 2
    }
  }
});

const getMockPolicyData = () => ({
  evaluations: [
    {
      id: 1,
      rule_name: 'No Plaintext Passwords',
      severity: 'critical',
      endpoint: '/api/auth/login',
      description: 'Password transmitted in plaintext',
      evidence: 'Found password field in request body',
      timestamp: new Date().toISOString()
    },
    {
      id: 2,
      rule_name: 'Require Authentication',
      severity: 'high',
      endpoint: '/api/admin/users',
      description: 'Admin endpoint accessible without authentication',
      evidence: 'No Authorization header found',
      timestamp: new Date(Date.now() - 3600000).toISOString()
    }
  ],
  summary: {
    total_violations: 5,
    critical: 2,
    high: 2,
    medium: 1,
    low: 0,
    rules_evaluated: 8,
    rules_passed: 3
  }
});

const getMockReportsData = () => ({
  reports: [
    {
      id: 1,
      name: 'Security Analysis Report',
      type: 'comprehensive',
      generated_at: new Date().toISOString(),
      status: 'completed',
      file_size: '2.3 MB'
    },
    {
      id: 2,
      name: 'Vulnerability Scan Report',
      type: 'vulnerability',
      generated_at: new Date(Date.now() - 86400000).toISOString(),
      status: 'completed',
      file_size: '1.1 MB'
    }
  ]
});

export default api; 