import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Alert, AlertDescription } from '../ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '../ui/progress';
import { 
  AlertTriangle, 
  Shield, 
  Activity, 
  Network, 
  Search, 
  Play, 
  Pause,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Eye
} from 'lucide-react';
import { 
  apiClient, 
  setupRealtimeHandlers, 
  requestRealtimeUpdates, 
  analyzeThreatIndicator
} from '@/lib/api-client';
import { io, type Socket } from 'socket.io-client';
import { formatBytes, formatBytesToMbps } from '@/utils/format';

interface ThreatAlert {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  destination?: string;
  description: string;
  timestamp: string;
  status: 'active' | 'investigating' | 'resolved';
}

interface NetworkStatus {
  devices_online: number;
  total_devices: number;
  bandwidth_usage: {
    inbound: number;
    outbound: number;
    total: number;
  };
  suspicious_connections: number;
  blocked_attempts: number;
}

interface VulnerabilityScan {
  scan_id: string;
  progress: number;
  status: 'running' | 'completed' | 'failed';
  vulnerabilities_found: number;
  current_target?: string;
}

export function RealtimeSOCDashboard() {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [activeScan, setActiveScan] = useState<VulnerabilityScan | null>(null);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [monitoringEnabled, setMonitoringEnabled] = useState(true);
  const [indicatorToAnalyze, setIndicatorToAnalyze] = useState('');
  
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Initialize WebSocket connection
    const newSocket = io('http://localhost:5001', {
      transports: ['websocket'],
      autoConnect: true
    });

    newSocket.on('connect', () => {
      console.log('Connected to SecureNet SOC');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('Disconnected from SecureNet SOC');
      setConnected(false);
    });

    // Real-time threat alerts
    newSocket.on('threat_alert', (alert: ThreatAlert) => {
      setThreats(prev => [alert, ...prev.slice(0, 19)]); // Keep last 20 alerts
    });

    // Network status updates
    newSocket.on('network_status', (status: NetworkStatus) => {
      setNetworkStatus(status);
    });

    // Vulnerability scan progress
    newSocket.on('scan_progress', (scan: VulnerabilityScan) => {
      setActiveScan(scan);
    });

    newSocket.on('scan_completed', (result: any) => {
      setActiveScan(prev => prev ? { ...prev, status: 'completed', progress: 100 } : null);
    });

    // Threat analysis results
    newSocket.on('analysis_result', (result: any) => {
      setAnalysisResult(result);
      setAnalysisLoading(false);
    });

    newSocket.on('analysis_started', (data: any) => {
      setAnalysisLoading(true);
      setAnalysisResult(null);
    });

    newSocket.on('analysis_error', (error: any) => {
      setAnalysisLoading(false);
      console.error('Analysis error:', error);
    });

    setSocket(newSocket);
    socketRef.current = newSocket;

    // Request initial data
    newSocket.emit('request_threat_update');
    newSocket.emit('request_network_status');

    return () => {
      newSocket.close();
    };
  }, []);

  useEffect(() => {
    // Auto-refresh data every 30 seconds
    const interval = setInterval(() => {
      if (socket && connected && monitoringEnabled) {
        socket.emit('request_threat_update');
        socket.emit('request_network_status');
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [socket, connected, monitoringEnabled]);

  const handleAnalyzeIndicator = () => {
    if (socket && indicatorToAnalyze.trim()) {
      socket.emit('analyze_indicator', {
        indicator: indicatorToAnalyze.trim(),
        indicator_type: 'auto'
      });
      setIndicatorToAnalyze('');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const getThreatTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'malware': return <AlertTriangle className="h-4 w-4" />;
      case 'intrusion': return <Shield className="h-4 w-4" />;
      case 'ddos': return <Activity className="h-4 w-4" />;
      case 'phishing': return <Eye className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className={`h-3 w-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-sm font-medium">
            {connected ? 'Connected to SOC' : 'Disconnected'}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setMonitoringEnabled(!monitoringEnabled)}
          >
            {monitoringEnabled ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            {monitoringEnabled ? 'Pause' : 'Resume'} Monitoring
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (socket) {
                socket.emit('request_threat_update');
                socket.emit('request_network_status');
              }
            }}
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Main Dashboard Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Live Threats</TabsTrigger>
          <TabsTrigger value="network">Network Monitor</TabsTrigger>
          <TabsTrigger value="analysis">Threat Analysis</TabsTrigger>
          <TabsTrigger value="scans">Vulnerability Scans</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Active Threats */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {threats.filter(t => t.status === 'active').length}
                </div>
                <p className="text-xs text-muted-foreground">
                  {threats.filter(t => t.severity === 'critical').length} critical
                </p>
              </CardContent>
            </Card>

            {/* Network Health */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Network Health</CardTitle>
                <Network className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {networkStatus ? Math.round((networkStatus.devices_online / networkStatus.total_devices) * 100) : 0}%
                </div>
                <p className="text-xs text-muted-foreground">
                  {networkStatus?.devices_online || 0} of {networkStatus?.total_devices || 0} devices online
                </p>
              </CardContent>
            </Card>

            {/* Bandwidth Usage */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Bandwidth</CardTitle>
                <TrendingUp className="h-4 w-4 text-green-500" />
              </CardHeader>              <CardContent>
                <div className="text-2xl font-bold">
                  {networkStatus ? formatBytesToMbps(networkStatus.bandwidth_usage.total) : '0 Mbps'}
                </div>
                <p className="text-xs text-muted-foreground">
                  ↑ {networkStatus ? formatBytes(networkStatus.bandwidth_usage.outbound) : '0 B'} ↓ {networkStatus ? formatBytes(networkStatus.bandwidth_usage.inbound) : '0 B'}
                </p>
              </CardContent>
            </Card>

            {/* Blocked Attempts */}
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Blocked Attempts</CardTitle>
                <Shield className="h-4 w-4 text-orange-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {networkStatus?.blocked_attempts || 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  Last 24 hours
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Recent Threats */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Threat Activity</CardTitle>
              <CardDescription>Latest security events and alerts</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {threats.slice(0, 5).map((threat) => (
                  <div key={threat.id} className="flex items-center justify-between p-2 border rounded">
                    <div className="flex items-center space-x-2">
                      {getThreatTypeIcon(threat.type)}
                      <div>
                        <p className="text-sm font-medium">{threat.description}</p>
                        <p className="text-xs text-muted-foreground">
                          {threat.source} • {new Date(threat.timestamp).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                    <Badge variant={getSeverityColor(threat.severity) as any}>
                      {threat.severity}
                    </Badge>
                  </div>
                ))}
                {threats.length === 0 && (
                  <p className="text-muted-foreground text-center py-4">No recent threats detected</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Live Threat Feed</CardTitle>
              <CardDescription>Real-time security threats and incidents</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {threats.map((threat) => (
                  <div key={threat.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        {getThreatTypeIcon(threat.type)}
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <p className="font-medium">{threat.type}</p>
                            <Badge variant={getSeverityColor(threat.severity) as any}>
                              {threat.severity}
                            </Badge>
                            <Badge variant="outline">{threat.status}</Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {threat.description}
                          </p>
                          <div className="flex items-center space-x-4 mt-2 text-xs text-muted-foreground">
                            <span>Source: {threat.source}</span>
                            {threat.destination && <span>Destination: {threat.destination}</span>}
                            <span>Time: {new Date(threat.timestamp).toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
                {threats.length === 0 && (
                  <div className="text-center py-8">
                    <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No threats detected</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network" className="space-y-4">
          {networkStatus && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Network Overview</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>Devices Online</span>
                      <span>{networkStatus.devices_online}/{networkStatus.total_devices}</span>
                    </div>
                    <Progress 
                      value={(networkStatus.devices_online / networkStatus.total_devices) * 100} 
                      className="mt-1"
                    />
                  </div>                  <div>
                    <div className="flex justify-between text-sm">
                      <span>Bandwidth Usage</span>
                      <span>{formatBytesToMbps(networkStatus.bandwidth_usage.total)}</span>
                    </div>
                    <Progress 
                      value={Math.min((networkStatus.bandwidth_usage.total / (1024 * 1024 * 1024)) * 100, 100)} 
                      className="mt-1"
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Security Metrics</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between">
                    <span className="text-sm">Suspicious Connections</span>
                    <span className="text-sm font-medium">{networkStatus.suspicious_connections}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm">Blocked Attempts</span>
                    <span className="text-sm font-medium">{networkStatus.blocked_attempts}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm">Firewall Status</span>
                    <Badge variant="default">Active</Badge>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="analysis" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence Analysis</CardTitle>
              <CardDescription>Analyze indicators using multiple threat intelligence sources</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex space-x-2 mb-4">
                <input
                  type="text"
                  placeholder="Enter IP, URL, domain, or file hash..."
                  value={indicatorToAnalyze}
                  onChange={(e) => setIndicatorToAnalyze(e.target.value)}
                  className="flex-1 px-3 py-2 border rounded-md"
                />
                <Button 
                  onClick={handleAnalyzeIndicator}
                  disabled={!indicatorToAnalyze.trim() || analysisLoading}
                >
                  <Search className="h-4 w-4 mr-2" />
                  Analyze
                </Button>
              </div>

              {analysisLoading && (
                <div className="text-center py-4">
                  <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">Analyzing indicator...</p>
                </div>
              )}

              {analysisResult && (
                <div className="border rounded-lg p-4">
                  <h4 className="font-medium mb-2">Analysis Results</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-muted-foreground">Indicator</p>
                      <p className="font-mono">{analysisResult.indicator}</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Threat Level</p>
                      <Badge variant={getSeverityColor(analysisResult.threat_level) as any}>
                        {analysisResult.threat_level}
                      </Badge>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Confidence</p>
                      <p>{analysisResult.confidence}%</p>
                    </div>
                    <div>
                      <p className="text-sm text-muted-foreground">Sources</p>
                      <p>{analysisResult.sources?.length || 0} sources checked</p>
                    </div>
                  </div>
                  {analysisResult.description && (
                    <div className="mt-4">
                      <p className="text-sm text-muted-foreground">Description</p>
                      <p className="text-sm">{analysisResult.description}</p>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scans" className="space-y-4">
          {activeScan && (
            <Card>
              <CardHeader>
                <CardTitle>Active Vulnerability Scan</CardTitle>
                <CardDescription>Scan ID: {activeScan.scan_id}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm mb-1">
                      <span>Progress</span>
                      <span>{activeScan.progress}%</span>
                    </div>
                    <Progress value={activeScan.progress} />
                  </div>
                  {activeScan.current_target && (
                    <p className="text-sm text-muted-foreground">
                      Scanning: {activeScan.current_target}
                    </p>
                  )}
                  <div className="flex justify-between">
                    <span className="text-sm">Status</span>
                    <Badge variant={activeScan.status === 'completed' ? 'default' : 'secondary'}>
                      {activeScan.status}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm">Vulnerabilities Found</span>
                    <span className="text-sm font-medium">{activeScan.vulnerabilities_found}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>    </div>
  );
}
