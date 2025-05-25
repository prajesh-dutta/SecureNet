import React, { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  AlertTriangle,
  Shield,
  Search,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  Server,
  Network,
  Eye,
  Download,
  Filter
} from 'lucide-react';
import { apiClient, type VulnerabilityResult, type VulnerabilityData } from '@/lib/api-client';

// Local interface extending API client types
interface Vulnerability extends VulnerabilityResult {
  // Additional fields that might be available locally
  cve_id?: string;
  title?: string;
  affected_host?: string;
  affected_service?: string;
  port?: number;
  protocol?: string;
  status?: 'open' | 'in_progress' | 'fixed' | 'false_positive' | 'accepted_risk';
  first_detected?: string;
  last_seen?: string;
  remediation?: string;
  references?: string[];
  tags?: string[];
  risk_score?: number;
  exploitability?: string;
  patch_available?: boolean;
}

interface ScanStatus {
  scan_id: string;
  target: string;
  scan_type: string;
  start_time: string;
  end_time?: string;
  status: 'running' | 'completed' | 'failed';
  vulnerabilities_found: number;
  progress: number;
  scanner: string;
  profile: string;
}

interface VulnerabilityStats {
  total_open: number;
  recent_vulnerabilities: number;
  by_severity: Record<string, number>;
  risk_score: number;
}

export default function AdvancedVulnerabilities() {
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [searchTerm, setSearchTerm] = useState('');
  const [scanTargets, setScanTargets] = useState('');
  const [scanProfile, setScanProfile] = useState('standard');
  const [activeScan, setActiveScan] = useState<ScanStatus | null>(null);
  // Fetch vulnerabilities
  const { data: vulnerabilities = [], isLoading: vulnLoading, refetch: refetchVulns } = useQuery({
    queryKey: ['vulnerabilities', selectedSeverity],
    queryFn: () => apiClient.getVulnerabilities(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch vulnerability statistics
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['vulnerability-stats'],
    queryFn: () => apiClient.getSecurityStatistics(),
    refetchInterval: 60000, // Refresh every minute
  });
  // Start vulnerability scan mutation
  const startScanMutation = useMutation({
    mutationFn: async ({ targets, profile }: { targets: string[], profile: string }) => {
      return apiClient.startVulnerabilityScan(targets);
    },
    onSuccess: (data) => {
      setActiveScan({
        scan_id: data.scan_id,
        target: scanTargets,
        scan_type: 'vulnerability',
        start_time: new Date().toISOString(),
        status: 'running',
        vulnerabilities_found: 0,
        progress: 0,
        scanner: 'nmap',
        profile: scanProfile
      });
    },
  });

  // Update vulnerability status mutation
  const updateStatusMutation = useMutation({
    mutationFn: async ({ vulnId, status, notes }: { vulnId: string, status: string, notes?: string }) => {
      // For now, return a mock success - actual API endpoint would be implemented later
      return { success: true };
    },
    onSuccess: () => {
      refetchVulns();
    },
  });
  // Poll for scan status
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (activeScan && activeScan.status === 'running') {
      interval = setInterval(async () => {
        try {
          const scanStatus = await apiClient.getVulnerabilityScanStatus(activeScan.scan_id);
          setActiveScan(scanStatus as any); // Type assertion for compatibility
          
          if (scanStatus.status === 'completed' || scanStatus.status === 'failed') {
            refetchVulns();
          }
        } catch (error) {
          console.error('Error polling scan status:', error);
        }
      }, 2000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeScan, refetchVulns]);

  const handleStartScan = () => {
    const targets = scanTargets.split(',').map(t => t.trim()).filter(t => t);
    if (targets.length > 0) {
      startScanMutation.mutate({ targets, profile: scanProfile });
      setScanTargets('');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      case 'info': return 'outline';
      default: return 'outline';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'destructive';
      case 'in_progress': return 'default';
      case 'fixed': return 'secondary';
      case 'false_positive': return 'outline';
      case 'accepted_risk': return 'secondary';
      default: return 'outline';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open': return <XCircle className="h-4 w-4" />;
      case 'in_progress': return <Clock className="h-4 w-4" />;
      case 'fixed': return <CheckCircle className="h-4 w-4" />;
      case 'false_positive': return <Eye className="h-4 w-4" />;
      case 'accepted_risk': return <Shield className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };
  const filteredVulnerabilities = vulnerabilities.filter((vuln: Vulnerability) => {
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        vuln.title?.toLowerCase().includes(searchLower) ||
        vuln.description.toLowerCase().includes(searchLower) ||
        vuln.affected_host?.toLowerCase().includes(searchLower) ||
        vuln.cve_id?.toLowerCase().includes(searchLower)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Vulnerability Management</h1>
          <p className="text-muted-foreground">
            Advanced vulnerability scanning and remediation tracking
          </p>
        </div>
        <Button onClick={() => refetchVulns()} variant="outline">
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Statistics Cards */}
      {!statsLoading && stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Open Vulnerabilities</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_open}</div>
              <p className="text-xs text-muted-foreground">
                {stats.recent_vulnerabilities} discovered this week
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
              <XCircle className="h-4 w-4 text-red-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.by_severity?.critical || 0}</div>
              <p className="text-xs text-muted-foreground">
                Require immediate attention
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">High Severity</CardTitle>
              <AlertTriangle className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.by_severity?.high || 0}</div>
              <p className="text-xs text-muted-foreground">
                High impact vulnerabilities
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
              <TrendingUp className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.risk_score}/100</div>
              <p className="text-xs text-muted-foreground">
                Overall security posture
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Active Scan Status */}
      {activeScan && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Play className="h-5 w-5" />
              <span>Active Vulnerability Scan</span>
            </CardTitle>
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
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Target:</span>
                  <p className="font-medium">{activeScan.target}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>
                  <Badge variant={activeScan.status === 'completed' ? 'default' : 'secondary'}>
                    {activeScan.status}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Profile:</span>
                  <p className="font-medium">{activeScan.profile}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Found:</span>
                  <p className="font-medium">{activeScan.vulnerabilities_found} vulnerabilities</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="scanner">Vulnerability Scanner</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardHeader>
              <CardTitle>Filter Vulnerabilities</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex space-x-4">
                <div className="flex-1">
                  <Input
                    placeholder="Search vulnerabilities..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="All Severities" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All Severities</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Vulnerabilities Table */}
          <Card>
            <CardHeader>
              <CardTitle>Discovered Vulnerabilities</CardTitle>
              <CardDescription>
                {filteredVulnerabilities.length} vulnerabilities found
              </CardDescription>
            </CardHeader>
            <CardContent>
              {vulnLoading ? (
                <div className="space-y-2">
                  {[...Array(5)].map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : filteredVulnerabilities.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Affected Host</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>CVSS</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulnerabilities.map((vuln: Vulnerability) => (
                      <TableRow key={vuln.id}>                        <TableCell>
                          <div>
                            <p className="font-medium">{vuln.title || 'Unknown Vulnerability'}</p>
                            {vuln.cve_id && (
                              <p className="text-sm text-muted-foreground">{vuln.cve_id}</p>
                            )}
                            <p className="text-sm text-muted-foreground truncate max-w-md">
                              {vuln.description}
                            </p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={getSeverityColor(vuln.severity) as any}>
                            {vuln.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div>
                            <p className="font-medium">{vuln.affected_host || 'Unknown Host'}</p>
                            {vuln.affected_service && (
                              <p className="text-sm text-muted-foreground">
                                {vuln.affected_service}
                                {vuln.port && `:${vuln.port}`}
                              </p>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-1">
                            {getStatusIcon(vuln.status || 'open')}
                            <Badge variant={getStatusColor(vuln.status || 'open') as any}>
                              {(vuln.status || 'open').replace('_', ' ')}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className="font-medium">{vuln.cvss_score}</span>
                        </TableCell>                        <TableCell>
                          <Select
                            value={vuln.status || 'open'}
                            onValueChange={(status) =>
                              updateStatusMutation.mutate({
                                vulnId: vuln.id,
                                status,
                                notes: `Status updated to ${status}`
                              })
                            }
                          >
                            <SelectTrigger className="w-32">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="open">Open</SelectItem>
                              <SelectItem value="in_progress">In Progress</SelectItem>
                              <SelectItem value="fixed">Fixed</SelectItem>
                              <SelectItem value="false_positive">False Positive</SelectItem>
                              <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                            </SelectContent>
                          </Select>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No vulnerabilities found</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scanner" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Start Vulnerability Scan</CardTitle>
              <CardDescription>
                Configure and launch vulnerability scans against network targets
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium">Scan Targets</label>
                <Input
                  placeholder="Enter IP addresses or ranges (comma-separated)"
                  value={scanTargets}
                  onChange={(e) => setScanTargets(e.target.value)}
                />
                <p className="text-sm text-muted-foreground mt-1">
                  Example: 192.168.1.1, 192.168.1.0/24, 10.0.0.1-10.0.0.100
                </p>
              </div>
              
              <div>
                <label className="text-sm font-medium">Scan Profile</label>
                <Select value={scanProfile} onValueChange={setScanProfile}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="standard">Standard (Balanced speed and coverage)</SelectItem>
                    <SelectItem value="aggressive">Aggressive (Comprehensive but slower)</SelectItem>
                    <SelectItem value="stealth">Stealth (Slow but low detection)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <Button
                onClick={handleStartScan}
                disabled={!scanTargets.trim() || startScanMutation.isPending}
                className="w-full"
              >
                {startScanMutation.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 mr-2" />
                )}
                Start Vulnerability Scan
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Vulnerability Reports</CardTitle>
              <CardDescription>
                Generate and download vulnerability assessment reports
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Button variant="outline" className="w-full justify-start">
                  <Download className="h-4 w-4 mr-2" />
                  Download Executive Summary
                </Button>
                <Button variant="outline" className="w-full justify-start">
                  <Download className="h-4 w-4 mr-2" />
                  Download Technical Report
                </Button>
                <Button variant="outline" className="w-full justify-start">
                  <Download className="h-4 w-4 mr-2" />
                  Download Remediation Plan
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
