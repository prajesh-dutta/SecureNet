import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  AlertTriangle,
  Shield,
  Search,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Settings,
  Plus,
  Edit,
  Trash2,
  Eye,
  Activity,
  TrendingUp,
  Server,
  Network,
  Filter
} from 'lucide-react';
import { apiClient, type SecurityEvent } from '@/lib/api-client';

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  pattern: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  enabled: boolean;
  created_at: string;
  last_triggered?: string;
  trigger_count: number;
}

interface IDSSystemStatus {
  status: 'Online' | 'Offline' | 'Maintenance';
  uptime: number;
  processed_packets: number;
  blocked_packets: number;
  alerts_generated: number;
  rules_active: number;
  cpu_usage: number;
  memory_usage: number;
}

export default function IDS() {
  const [activeTab, setActiveTab] = useState('alerts');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null);  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    pattern: '',
    severity: 'Medium' as 'Critical' | 'High' | 'Medium' | 'Low',
    enabled: true
  });

  const queryClient = useQueryClient();

  // Fetch IDS alerts
  const { data: alerts = [], isLoading: alertsLoading, refetch: refetchAlerts } = useQuery({
    queryKey: ['ids-alerts', selectedSeverity, selectedStatus],
    queryFn: () => apiClient.getIDSAlerts(100),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Fetch IDS system status
  const { data: systemStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['ids-status'],
    queryFn: () => apiClient.getIDSSystemStatus(),
    refetchInterval: 15000, // Refresh every 15 seconds
  });

  // Fetch detection rules
  const { data: rules = [], isLoading: rulesLoading, refetch: refetchRules } = useQuery({
    queryKey: ['detection-rules'],
    queryFn: () => apiClient.getDetectionRules(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Acknowledge alert mutation
  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => apiClient.acknowledgeIDSAlert(alertId, 'current-user'),
    onSuccess: () => {
      refetchAlerts();
    },
  });

  // Add/Update rule mutation
  const ruleMutation = useMutation({
    mutationFn: (rule: any) => {
      if (editingRule) {
        return apiClient.updateDetectionRule(editingRule.id, rule);
      }
      return apiClient.addDetectionRule(rule);
    },
    onSuccess: () => {
      refetchRules();
      setIsRuleDialogOpen(false);
      setEditingRule(null);
      setNewRule({
        name: '',
        description: '',
        pattern: '',
        severity: 'Medium',
        enabled: true
      });
    },
  });

  // Delete rule mutation
  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => apiClient.deleteDetectionRule(ruleId),
    onSuccess: () => {
      refetchRules();
    },
  });

  // Filter alerts based on search term and severity
  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = !searchTerm || 
      alert.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.event_type?.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = !selectedSeverity || selectedSeverity === 'all' || alert.severity === selectedSeverity;
    const matchesStatus = !selectedStatus || selectedStatus === 'all' || alert.status === selectedStatus;
    
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'active': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'investigating': return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'resolved': return <CheckCircle className="h-4 w-4 text-green-500" />;
      default: return <XCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const handleEditRule = (rule: DetectionRule) => {
    setEditingRule(rule);
    setNewRule({
      name: rule.name,
      description: rule.description,
      pattern: rule.pattern,
      severity: rule.severity,
      enabled: rule.enabled
    });
    setIsRuleDialogOpen(true);
  };

  const handleSaveRule = () => {
    ruleMutation.mutate(newRule);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Intrusion Detection System</h1>
          <p className="text-muted-foreground">
            Monitor and detect malicious activities in real-time
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refetchAlerts();
              refetchRules();
            }}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* System Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statusLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 bg-background-tertiary/40" />
          ))
        ) : (
          <>
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">System Status</p>
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${systemStatus?.status === 'Online' ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span className="text-2xl font-bold">{systemStatus?.status || 'Offline'}</span>
                    </div>
                  </div>
                  <Shield className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Active Alerts</p>
                    <p className="text-2xl font-bold">{alerts.filter(a => a.status === 'Active').length}</p>
                    <p className="text-xs text-muted-foreground">
                      {alerts.filter(a => a.severity === 'Critical').length} critical
                    </p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Blocked Packets</p>
                    <p className="text-2xl font-bold">{systemStatus?.blocked_packets?.toLocaleString() || '0'}</p>
                    <p className="text-xs text-muted-foreground">
                      {((systemStatus?.blocked_packets || 0) / (systemStatus?.processed_packets || 1) * 100).toFixed(2)}% blocked
                    </p>
                  </div>
                  <Network className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Active Rules</p>
                    <p className="text-2xl font-bold">{systemStatus?.rules_active || 0}</p>
                    <p className="text-xs text-muted-foreground">
                      {rules.filter(r => r.enabled).length} enabled
                    </p>
                  </div>
                  <Settings className="h-8 w-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="alerts">Security Alerts</TabsTrigger>
          <TabsTrigger value="rules">Detection Rules</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="alerts" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardHeader>
              <CardTitle>Filter Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex space-x-4">
                <div className="flex-1">
                  <Input
                    placeholder="Search alerts..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full"
                  />
                </div>
                <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="All Severities" />
                  </SelectTrigger>                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="Critical">Critical</SelectItem>
                    <SelectItem value="High">High</SelectItem>
                    <SelectItem value="Medium">Medium</SelectItem>
                    <SelectItem value="Low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={selectedStatus} onValueChange={setSelectedStatus}>
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="All Statuses" />
                  </SelectTrigger>                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="Active">Active</SelectItem>
                    <SelectItem value="Investigating">Investigating</SelectItem>
                    <SelectItem value="Resolved">Resolved</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Alerts Table */}
          <Card>
            <CardHeader>
              <CardTitle>Security Alerts ({filteredAlerts.length})</CardTitle>
              <CardDescription>
                Real-time intrusion detection alerts and security events
              </CardDescription>
            </CardHeader>
            <CardContent>
              {alertsLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Event Type</TableHead>
                      <TableHead>Source IP</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAlerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>
                          <Badge className={`${getSeverityColor(alert.severity)} text-white`}>
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium">{alert.event_type}</TableCell>
                        <TableCell className="font-mono text-sm">{alert.source_ip}</TableCell>
                        <TableCell className="font-mono text-sm">{alert.destination_ip || '-'}</TableCell>
                        <TableCell className="max-w-xs truncate">{alert.description}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {getStatusIcon(alert.status)}
                            <span className="text-sm">{alert.status}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(alert.timestamp).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => acknowledgeMutation.mutate(alert.id)}
                              disabled={alert.status === 'Resolved'}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Eye className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="space-y-4">
          {/* Rules Management */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Detection Rules</CardTitle>
                  <CardDescription>
                    Manage custom detection patterns and rules
                  </CardDescription>
                </div>
                <Dialog open={isRuleDialogOpen} onOpenChange={setIsRuleDialogOpen}>
                  <DialogTrigger asChild>
                    <Button onClick={() => setEditingRule(null)}>
                      <Plus className="h-4 w-4 mr-2" />
                      Add Rule
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="sm:max-w-[525px]">
                    <DialogHeader>
                      <DialogTitle>{editingRule ? 'Edit' : 'Add'} Detection Rule</DialogTitle>
                      <DialogDescription>
                        {editingRule ? 'Update' : 'Create'} a detection rule to identify security threats.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="name" className="text-right">
                          Name
                        </Label>
                        <Input
                          id="name"
                          value={newRule.name}
                          onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                          className="col-span-3"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="description" className="text-right">
                          Description
                        </Label>
                        <Textarea
                          id="description"
                          value={newRule.description}
                          onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                          className="col-span-3"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="pattern" className="text-right">
                          Pattern
                        </Label>
                        <Textarea
                          id="pattern"
                          value={newRule.pattern}
                          onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                          className="col-span-3"
                          placeholder="e.g., /malicious_pattern/i"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="severity" className="text-right">
                          Severity
                        </Label>
                        <Select value={newRule.severity} onValueChange={(value: any) => setNewRule({ ...newRule, severity: value })}>
                          <SelectTrigger className="col-span-3">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Critical">Critical</SelectItem>
                            <SelectItem value="High">High</SelectItem>
                            <SelectItem value="Medium">Medium</SelectItem>
                            <SelectItem value="Low">Low</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <DialogFooter>
                      <Button onClick={handleSaveRule} disabled={ruleMutation.isPending}>
                        {ruleMutation.isPending ? 'Saving...' : 'Save Rule'}
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              {rulesLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Triggers</TableHead>
                      <TableHead>Last Triggered</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule: DetectionRule) => (
                      <TableRow key={rule.id}>
                        <TableCell className="font-medium">{rule.name}</TableCell>
                        <TableCell className="max-w-xs truncate">{rule.description}</TableCell>
                        <TableCell>
                          <Badge className={`${getSeverityColor(rule.severity)} text-white`}>
                            {rule.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={rule.enabled ? 'default' : 'secondary'}>
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </Badge>
                        </TableCell>
                        <TableCell>{rule.trigger_count}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : 'Never'}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleEditRule(rule)}
                            >
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => deleteRuleMutation.mutate(rule.id)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          {/* Analytics Dashboard */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Alert Trends</CardTitle>
                <CardDescription>Security alert frequency over time</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <TrendingUp className="h-8 w-8 mr-2" />
                  Alert trend chart coming soon
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Top Attack Sources</CardTitle>
                <CardDescription>Most frequent attack source IPs</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <Server className="h-8 w-8 mr-2" />
                  Attack source analysis coming soon
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Performance</CardTitle>
                <CardDescription>IDS system resource utilization</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>CPU Usage</span>
                      <span>{systemStatus?.cpu_usage || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-600 h-2 rounded-full" 
                        style={{ width: `${systemStatus?.cpu_usage || 0}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>Memory Usage</span>
                      <span>{systemStatus?.memory_usage || 0}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-green-600 h-2 rounded-full" 
                        style={{ width: `${systemStatus?.memory_usage || 0}%` }}
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Rule Effectiveness</CardTitle>
                <CardDescription>Detection rule performance metrics</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <Activity className="h-8 w-8 mr-2" />
                  Rule effectiveness metrics coming soon
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
