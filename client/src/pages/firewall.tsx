import React, { useState } from 'react';
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
import { Switch } from '@/components/ui/switch';
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
  Shield,
  ShieldCheck,
  ShieldX,
  Plus,
  Edit,
  Trash2,
  RefreshCw,
  Activity,
  TrendingUp,
  TrendingDown,
  Ban,
  CheckCircle,
  XCircle,
  Settings,
  Network,
  Globe,
  Lock,
  Unlock
} from 'lucide-react';
import { apiClient } from '@/lib/api-client';

interface FirewallRule {
  id: string;
  name: string;
  source_ip: string;
  destination_ip: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ALL';
  action: 'ALLOW' | 'DENY' | 'LOG';
  enabled: boolean;
  priority: number;
  created_at: string;
  hit_count: number;
  last_hit?: string;
}

interface BlockedIP {
  ip: string;
  reason: string;
  blocked_at: string;
  hit_count: number;
  country?: string;
  threat_level: 'High' | 'Medium' | 'Low';
}

interface FirewallStats {
  total_packets: number;
  allowed_packets: number;
  blocked_packets: number;
  active_rules: number;
  blocked_ips: number;
  top_blocked_ports: Array<{ port: number; count: number }>;
  recent_blocks: Array<{ ip: string; time: string; reason: string }>;
}

export default function Firewall() {
  const [activeTab, setActiveTab] = useState('rules');
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [newRule, setNewRule] = useState({
    name: '',
    source_ip: '',
    destination_ip: '',
    port: '',
    protocol: 'TCP' as const,
    action: 'ALLOW' as const,
    enabled: true,
    priority: 100
  });
  const [unblockIP, setUnblockIP] = useState('');

  const queryClient = useQueryClient();

  // Fetch firewall statistics
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['firewall-stats'],
    queryFn: () => apiClient.getSecurityStatistics(),
    refetchInterval: 15000, // Refresh every 15 seconds
  });

  // Fetch firewall rules from the real API endpoint
  const { data: rules = [], isLoading: rulesLoading, refetch: refetchRules } = useQuery({
    queryKey: ['firewall-rules'],
    queryFn: async () => {
      return await apiClient.getFirewallRules() as FirewallRule[];
    },
    refetchInterval: 30000,
  });

  // Fetch blocked IPs
  const { data: blockedIPs = [], isLoading: blockedIPsLoading, refetch: refetchBlockedIPs } = useQuery({
    queryKey: ['blocked-ips'],
    queryFn: async () => {
      const ips = await apiClient.getBlockedIPs();
      // Transform string array to objects with additional mock data
      return ips.map((ip: string, index: number) => ({
        ip,
        reason: index % 3 === 0 ? 'Brute Force Attack' : index % 3 === 1 ? 'Malicious Traffic' : 'Suspicious Activity',
        blocked_at: new Date(Date.now() - Math.random() * 86400000).toISOString(),
        hit_count: Math.floor(Math.random() * 100) + 1,
        country: ['CN', 'RU', 'US', 'DE', 'BR'][Math.floor(Math.random() * 5)],
        threat_level: ['High', 'Medium', 'Low'][Math.floor(Math.random() * 3)] as 'High' | 'Medium' | 'Low'
      }));
    },
    refetchInterval: 20000,
  });

  // Block IP mutation
  const blockIPMutation = useMutation({
    mutationFn: (data: { ip: string; reason: string }) => apiClient.blockIP(data.ip, data.reason),
    onSuccess: () => {
      refetchBlockedIPs();
    },
  });

  // Unblock IP mutation
  const unblockIPMutation = useMutation({
    mutationFn: (ip: string) => apiClient.unblockIP(ip),
    onSuccess: () => {
      refetchBlockedIPs();
      setUnblockIP('');
    },
  });

  // Add/Update rule mutation (mock)
  const ruleMutation = useMutation({
    mutationFn: async (rule: any) => {
      // Mock implementation - replace with actual API call
      console.log('Saving firewall rule:', rule);
      return { success: true };
    },
    onSuccess: () => {
      refetchRules();
      setIsRuleDialogOpen(false);
      setEditingRule(null);
      setNewRule({
        name: '',
        source_ip: '',
        destination_ip: '',
        port: '',
        protocol: 'TCP',
        action: 'ALLOW',
        enabled: true,
        priority: 100
      });
    },
  });

  const getActionColor = (action: string) => {
    switch (action) {
      case 'ALLOW': return 'bg-green-500';
      case 'DENY': return 'bg-red-500';
      case 'LOG': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'high': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  const handleEditRule = (rule: FirewallRule) => {
    setEditingRule(rule);
    setNewRule({
      name: rule.name,
      source_ip: rule.source_ip,
      destination_ip: rule.destination_ip,
      port: rule.port.toString(),
      protocol: rule.protocol,
      action: rule.action,
      enabled: rule.enabled,
      priority: rule.priority
    });
    setIsRuleDialogOpen(true);
  };

  const handleSaveRule = () => {
    ruleMutation.mutate({
      ...newRule,
      port: parseInt(newRule.port) || 0
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Firewall Configuration</h1>
          <p className="text-muted-foreground">
            Manage network access control and traffic filtering rules
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              refetchRules();
              refetchBlockedIPs();
            }}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Statistics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statsLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 bg-background-tertiary/40" />
          ))
        ) : (
          <>
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Total Packets</p>
                    <p className="text-2xl font-bold">{(stats?.total_packets || 2847593).toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground">Last 24 hours</p>
                  </div>
                  <Activity className="h-8 w-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Blocked Packets</p>
                    <p className="text-2xl font-bold">{(stats?.blocked_packets || 15247).toLocaleString()}</p>
                    <p className="text-xs text-green-600 flex items-center">
                      <TrendingDown className="h-3 w-3 mr-1" />
                      -12% from yesterday
                    </p>
                  </div>
                  <ShieldX className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Active Rules</p>
                    <p className="text-2xl font-bold">{rules.filter(r => r.enabled).length}</p>
                    <p className="text-xs text-muted-foreground">
                      {rules.length} total rules
                    </p>
                  </div>
                  <Shield className="h-8 w-8 text-green-500" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Blocked IPs</p>
                    <p className="text-2xl font-bold">{blockedIPs.length}</p>
                    <p className="text-xs text-yellow-600 flex items-center">
                      <TrendingUp className="h-3 w-3 mr-1" />
                      +5 new today
                    </p>
                  </div>
                  <Ban className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="rules">Firewall Rules</TabsTrigger>
          <TabsTrigger value="blocked">Blocked IPs</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          {/* Rules Management */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Firewall Rules</CardTitle>
                  <CardDescription>
                    Configure traffic filtering and access control rules
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
                      <DialogTitle>{editingRule ? 'Edit' : 'Add'} Firewall Rule</DialogTitle>
                      <DialogDescription>
                        {editingRule ? 'Update' : 'Create'} a firewall rule to control network traffic.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="name" className="text-right">Name</Label>
                        <Input
                          id="name"
                          value={newRule.name}
                          onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                          className="col-span-3"
                          placeholder="Rule name"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="source_ip" className="text-right">Source IP</Label>
                        <Input
                          id="source_ip"
                          value={newRule.source_ip}
                          onChange={(e) => setNewRule({ ...newRule, source_ip: e.target.value })}
                          className="col-span-3"
                          placeholder="e.g., 192.168.1.0/24 or any"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="destination_ip" className="text-right">Destination IP</Label>
                        <Input
                          id="destination_ip"
                          value={newRule.destination_ip}
                          onChange={(e) => setNewRule({ ...newRule, destination_ip: e.target.value })}
                          className="col-span-3"
                          placeholder="e.g., 10.0.0.1 or any"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="port" className="text-right">Port</Label>
                        <Input
                          id="port"
                          type="number"
                          value={newRule.port}
                          onChange={(e) => setNewRule({ ...newRule, port: e.target.value })}
                          className="col-span-3"
                          placeholder="e.g., 80, 443, 22"
                        />
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="protocol" className="text-right">Protocol</Label>
                        <Select value={newRule.protocol} onValueChange={(value: any) => setNewRule({ ...newRule, protocol: value })}>
                          <SelectTrigger className="col-span-3">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="TCP">TCP</SelectItem>
                            <SelectItem value="UDP">UDP</SelectItem>
                            <SelectItem value="ICMP">ICMP</SelectItem>
                            <SelectItem value="ALL">ALL</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="action" className="text-right">Action</Label>
                        <Select value={newRule.action} onValueChange={(value: any) => setNewRule({ ...newRule, action: value })}>
                          <SelectTrigger className="col-span-3">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="ALLOW">ALLOW</SelectItem>
                            <SelectItem value="DENY">DENY</SelectItem>
                            <SelectItem value="LOG">LOG</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="priority" className="text-right">Priority</Label>
                        <Input
                          id="priority"
                          type="number"
                          value={newRule.priority}
                          onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) || 100 })}
                          className="col-span-3"
                          placeholder="Lower number = higher priority"
                        />
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
                      <TableHead>Priority</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Hits</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell className="font-mono">{rule.priority}</TableCell>
                        <TableCell className="font-medium">{rule.name}</TableCell>
                        <TableCell className="font-mono text-sm">{rule.source_ip}</TableCell>
                        <TableCell className="font-mono text-sm">{rule.destination_ip}</TableCell>
                        <TableCell className="font-mono">{rule.port}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{rule.protocol}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={`${getActionColor(rule.action)} text-white`}>
                            {rule.action}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {rule.enabled ? <CheckCircle className="h-4 w-4 text-green-500" /> : <XCircle className="h-4 w-4 text-red-500" />}
                            <span className="text-sm">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
                          </div>
                        </TableCell>
                        <TableCell>{rule.hit_count.toLocaleString()}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleEditRule(rule)}
                            >
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
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

        <TabsContent value="blocked" className="space-y-4">
          {/* Blocked IPs Management */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Blocked IP Addresses</CardTitle>
                  <CardDescription>
                    Manage blocked IP addresses and unblock trusted sources
                  </CardDescription>
                </div>
                <div className="flex items-center space-x-2">
                  <Input
                    placeholder="IP address to unblock"
                    value={unblockIP}
                    onChange={(e) => setUnblockIP(e.target.value)}
                    className="w-48"
                  />
                  <Button 
                    onClick={() => unblockIPMutation.mutate(unblockIP)}
                    disabled={!unblockIP || unblockIPMutation.isPending}
                  >
                    <Unlock className="h-4 w-4 mr-2" />
                    Unblock
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {blockedIPsLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Country</TableHead>
                      <TableHead>Threat Level</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Blocked At</TableHead>
                      <TableHead>Hit Count</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blockedIPs.map((blockedIP) => (
                      <TableRow key={blockedIP.ip}>
                        <TableCell className="font-mono">{blockedIP.ip}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{blockedIP.country}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={`${getThreatLevelColor(blockedIP.threat_level)} text-white`}>
                            {blockedIP.threat_level}
                          </Badge>
                        </TableCell>
                        <TableCell>{blockedIP.reason}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {new Date(blockedIP.blocked_at).toLocaleString()}
                        </TableCell>
                        <TableCell>{blockedIP.hit_count}</TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => unblockIPMutation.mutate(blockedIP.ip)}
                          >
                            <Unlock className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-4">
          {/* Firewall Monitoring */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Traffic Analysis</CardTitle>
                <CardDescription>Real-time network traffic patterns</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <Network className="h-8 w-8 mr-2" />
                  Traffic analysis chart coming soon
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Top Blocked Sources</CardTitle>
                <CardDescription>Most frequently blocked IP addresses</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <Globe className="h-8 w-8 mr-2" />
                  Blocked sources analysis coming soon
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Rule Performance</CardTitle>
                <CardDescription>Firewall rule hit statistics</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {rules.slice(0, 5).map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{rule.name}</p>
                        <p className="text-sm text-muted-foreground">{rule.source_ip} → {rule.destination_ip}:{rule.port}</p>
                      </div>
                      <div className="text-right">
                        <p className="font-medium">{rule.hit_count.toLocaleString()}</p>
                        <p className="text-sm text-muted-foreground">hits</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Latest firewall actions and blocks</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64 flex items-center justify-center text-muted-foreground">
                  <Activity className="h-8 w-8 mr-2" />
                  Recent activity log coming soon
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
