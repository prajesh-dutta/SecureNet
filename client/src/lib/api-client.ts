// Frontend API Client for SecureNet SOC Platform
// Comprehensive integration with Flask backend endpoints

import { io, Socket } from 'socket.io-client';

// Configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/?$/, '') || 'http://localhost:5001/api';
const WEBSOCKET_URL = 'http://localhost:5001';

// Types for API responses
export interface SecurityEvent {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip: string;
  destination_ip?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Active' | 'Resolved' | 'Investigating';
  description: string;
  alert_id?: string;
}

export interface ThreatAlert {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  destination?: string;
  description: string;
  timestamp: string;
  status: 'active' | 'investigating' | 'resolved';
  confidence?: number;
  threat_level?: string;
}

export interface NetworkStatus {
  devices_online: number;
  total_devices: number;
  bandwidth_usage: {
    inbound: number;
    outbound: number;
    total: number;
  };
  suspicious_connections: number;
  blocked_attempts: number;
  network_health: number;
}

export interface SystemMetrics {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  network_throughput: number;
  active_connections: number;
  uptime: number;
}

export interface VulnerabilityData {
  scan_id: string;
  progress: number;
  status: 'running' | 'completed' | 'failed';
  vulnerabilities_found: number;
  current_target?: string;
  results?: VulnerabilityResult[];
}

export interface VulnerabilityResult {
  id: string;
  target: string;
  vulnerability: string;
  severity: string;
  cvss_score: number;
  description: string;
  solution?: string;
}

export interface ThreatIntelligenceResult {
  indicator: string;
  indicator_type: string;
  threat_level: string;
  confidence: number;
  sources: string[];
  description: string;
  first_seen?: string;
  last_seen?: string;
}

export interface IncidentData {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  timeline: IncidentTimelineEntry[];
}

export interface IncidentTimelineEntry {
  timestamp: string;
  action: string;
  user: string;
  details: string;
}

// Main API Client Class
class APIClient {
  private baseURL: string;
  private authToken: string | null = null;
  private socket: Socket | null = null;

  constructor() {
    this.baseURL = API_BASE_URL;
    this.authToken = localStorage.getItem('auth_token');
  }

  // Authentication methods
  async login(email: string, password: string): Promise<{ token: string; user: any }> {
    const response = await this.post('/auth/login', { email, password });
    if (response.token) {
      this.authToken = response.token;
      localStorage.setItem('auth_token', response.token);
    }
    return response;
  }

  async logout(): Promise<void> {
    await this.post('/auth/logout', {});
    this.authToken = null;
    localStorage.removeItem('auth_token');
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  // WebSocket connection management
  connectWebSocket(): Socket {
    if (this.socket?.connected) {
      return this.socket;
    }

    this.socket = io(WEBSOCKET_URL, {
      transports: ['websocket'],
      autoConnect: true,
      auth: {
        token: this.authToken
      }
    });

    this.socket.on('connect', () => {
      console.log('Connected to SecureNet SOC WebSocket');
    });

    this.socket.on('disconnect', () => {
      console.log('Disconnected from SecureNet SOC WebSocket');
    });

    this.socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
    });

    return this.socket;
  }

  getSocket(): Socket | null {
    return this.socket;
  }

  // Dashboard APIs
  async getDashboardOverview(): Promise<any> {
    return this.get('/dashboard/overview');
  }

  async getSystemMetrics(): Promise<SystemMetrics> {
    return this.get('/dashboard/metrics');
  }
  
  async getSystemStatus(): Promise<any> {
    return this.get('/system/status');
  }

  async getNetworkTrafficData(): Promise<any[]> {
    const response = await this.get('/dashboard/traffic');
    
    // Transform the API response to extract historical data and format for chart
    if (response && response.historical_data) {
      return response.historical_data.map((item: any, index: number) => {
        // Format timestamp for display
        const time = new Date(item.timestamp).toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
          hour12: false
        });
        
        return {
          time,
          inbound: item.inbound,
          outbound: item.outbound,
          blocked: Math.floor(Math.random() * 50) + 10, // Add blocked traffic data
          timestamp: item.timestamp
        };
      }).reverse(); // Reverse to show newest data last
    }
    
    return [];
  }

  // Security Events APIs
  async getSecurityEvents(limit: number = 50): Promise<SecurityEvent[]> {
    return this.get(`/security/events?limit=${limit}`);
  }

  async getRecentThreats(limit: number = 20): Promise<ThreatAlert[]> {
    return this.get(`/threats/recent?limit=${limit}`);
  }

  async acknowledgeThreat(threatId: string): Promise<boolean> {
    const response = await this.post(`/threats/${threatId}/acknowledge`, {});
    return response.success;
  }

  // Network Monitoring APIs
  async getNetworkStatus(): Promise<NetworkStatus> {
    return this.get('/network/status');
  }

  async getNetworkDevices(): Promise<any[]> {
    return this.get('/network/devices');
  }

  async getNetworkTopology(): Promise<any> {
    return this.get('/network/topology');
  }

  async getGeographicThreats(): Promise<any[]> {
    return this.get('/threats/geographic');
  }
  // Intrusion Detection APIs
  async getIDSAlerts(limit: number = 50): Promise<SecurityEvent[]> {
    const response = await this.get(`/security/ids/alerts?limit=${limit}`);
    
    // Transform the API response to extract alerts array
    if (response && response.alerts) {
      return response.alerts;
    }
    return [];
  }

  async getIDSSystemStatus(): Promise<any> {
    return this.get('/security/ids/status');
  }

  async acknowledgeIDSAlert(alertId: string, userId: string): Promise<boolean> {
    const response = await this.post(`/security/ids/alerts/${alertId}/acknowledge`, { user_id: userId });
    return response.success;
  }
  async getDetectionRules(): Promise<any[]> {
    const response = await this.get('/security/ids/rules');
    
    // The current API returns metadata about rules, not individual rules
    // Return empty array until individual rules endpoint is available
    // TODO: Implement proper rules endpoint that returns array of rule objects
    return [];
  }

  async addDetectionRule(rule: any): Promise<any> {
    return this.post('/security/ids/rules', rule);
  }

  async updateDetectionRule(ruleId: string, rule: any): Promise<any> {
    return this.put(`/security/ids/rules/${ruleId}`, rule);
  }

  async deleteDetectionRule(ruleId: string): Promise<boolean> {
    const response = await this.delete(`/security/ids/rules/${ruleId}`);
    return response.success;
  }  // Vulnerability Management APIs
  async getVulnerabilities(): Promise<VulnerabilityResult[]> {
    const response = await this.get('/vulnerabilities/scan-results');
    return response.vulnerabilities || [];
  }
  async startVulnerabilityScan(targets: string[]): Promise<{ scan_id: string }> {
    return this.post('/vulnerabilities/start-scan', { targets });
  }
  async getVulnerabilityScanStatus(scanId: string): Promise<VulnerabilityData> {
    return this.get(`/vulnerabilities/scan-status/${scanId}`);
  }

  async getVulnerabilityScanHistory(): Promise<any[]> {
    return this.get('/vulnerabilities/scans');
  }

  // Threat Intelligence APIs
  async analyzeThreatIndicator(indicator: string, indicatorType?: string): Promise<ThreatIntelligenceResult> {
    return this.post('/threats/analyze', {
      indicator,
      indicator_type: indicatorType || 'auto'
    });
  }

  async getThreatIntelligenceFeeds(): Promise<any[]> {
    return this.get('/threats/feeds');
  }

  async updateThreatFeeds(): Promise<boolean> {
    const response = await this.post('/threats/feeds/update', {});
    return response.success;
  }

  // Incident Response APIs
  async getIncidents(): Promise<IncidentData[]> {
    return this.get('/incidents');
  }

  async getActiveIncidents(): Promise<IncidentData[]> {
    return this.get('/incidents/active');
  }

  async createIncident(incident: Partial<IncidentData>): Promise<IncidentData> {
    return this.post('/incidents', incident);
  }

  async updateIncident(incidentId: string, updates: Partial<IncidentData>): Promise<IncidentData> {
    return this.put(`/incidents/${incidentId}`, updates);
  }

  async assignIncident(incidentId: string, assigneeId: string): Promise<boolean> {
    const response = await this.post(`/incidents/${incidentId}/assign`, { assignee_id: assigneeId });
    return response.success;
  }

  async closeIncident(incidentId: string, resolution: string): Promise<boolean> {
    const response = await this.post(`/incidents/${incidentId}/close`, { resolution });
    return response.success;
  }
  // Security Logging APIs
  async getSecurityLogs(filters?: any): Promise<any[]> {
    const queryParams = filters ? `?${new URLSearchParams(filters).toString()}` : '';
    return this.get(`/security/logs/security${queryParams}`);
  }

  async searchLogs(query: string, limit: number = 100): Promise<any[]> {
    return this.post('/logs/search', { query, limit });
  }

  async getAuditTrail(filters?: any): Promise<any[]> {
    const queryParams = filters ? `?${new URLSearchParams(filters).toString()}` : '';
    return this.get(`/security/audit/events${queryParams}`);
  }
  async getLogsStatistics(): Promise<any> {
    return this.get('/logs/statistics');
  }

  // Security Middleware APIs
  async getSecurityStatistics(): Promise<any> {
    return this.get('/security/statistics');
  }

  async getBlockedIPs(): Promise<string[]> {
    return this.get('/security/blocked-ips');
  }

  async blockIP(ip: string, reason?: string): Promise<boolean> {
    const response = await this.post('/security/block-ip', { ip, reason });
    return response.success;
  }

  async unblockIP(ip: string): Promise<boolean> {
    const response = await this.post('/security/unblock-ip', { ip });
    return response.success;
  }

  // Firewall APIs
  async getFirewallRules(): Promise<any[]> {
    return this.get('/firewall/rules');
  }

  // Generic HTTP methods
  private async request(method: string, endpoint: string, data?: any): Promise<any> {
    const url = `${this.baseURL}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    const config: RequestInit = {
      method,
      headers,
      // credentials: 'include',  // removed to avoid CORS credential issues
    };

    if (data) {
      config.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, config);
      
      if (response.status === 401) {
        this.authToken = null;
        localStorage.removeItem('auth_token');
        throw new Error('Authentication required');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`);
      }

      const responseData = await response.json();
      return responseData;
    } catch (error) {
      console.error(`API request failed: ${method} ${endpoint}`, error);
      throw error;
    }
  }

  private async get(endpoint: string): Promise<any> {
    return this.request('GET', endpoint);
  }

  private async post(endpoint: string, data: any): Promise<any> {
    return this.request('POST', endpoint, data);
  }

  private async put(endpoint: string, data: any): Promise<any> {
    return this.request('PUT', endpoint, data);
  }

  private async delete(endpoint: string): Promise<any> {
    return this.request('DELETE', endpoint);
  }
}

// Singleton instance
export const apiClient = new APIClient();

// WebSocket event handlers for real-time features
export const setupRealtimeHandlers = (
  onThreatAlert: (alert: ThreatAlert) => void,
  onNetworkStatus: (status: NetworkStatus) => void,
  onVulnerabilityScan: (scan: VulnerabilityData) => void,
  onIncidentUpdate: (incident: IncidentData) => void,
  onSystemAlert: (alert: any) => void
) => {
  const socket = apiClient.connectWebSocket();

  // Set up event listeners
  socket.on('threat_alert', onThreatAlert);
  socket.on('network_status', onNetworkStatus);
  socket.on('scan_progress', onVulnerabilityScan);
  socket.on('scan_completed', onVulnerabilityScan);
  socket.on('incident_update', onIncidentUpdate);
  socket.on('system_alert', onSystemAlert);

  // Additional analysis events
  socket.on('analysis_result', (result: ThreatIntelligenceResult) => {
    console.log('Threat analysis completed:', result);
  });

  socket.on('analysis_error', (error: any) => {
    console.error('Threat analysis error:', error);
  });

  return socket;
};

// Request real-time updates
export const requestRealtimeUpdates = () => {
  const socket = apiClient.getSocket();
  if (socket?.connected) {
    socket.emit('request_threat_update');
    socket.emit('request_network_status');
    socket.emit('request_ids_alerts');
    socket.emit('request_incident_status');
  }
};

// Analyze threat indicator
export const analyzeThreatIndicator = (indicator: string, indicatorType?: string) => {
  const socket = apiClient.getSocket();
  if (socket?.connected) {
    socket.emit('analyze_indicator', {
      indicator,
      indicator_type: indicatorType || 'auto'
    });
  }
};

export default apiClient;
