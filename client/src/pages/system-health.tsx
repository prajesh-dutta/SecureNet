import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar
} from 'recharts';
import {
  Activity,
  Cpu,
  HardDrive,
  MemoryStick,
  Network,
  Server,
  Thermometer,
  Zap,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  TrendingDown,
  Clock,
  Wifi,
  Database,
  Shield,
  Monitor
} from 'lucide-react';
import { apiClient, type SystemMetrics } from '@/lib/api-client';

interface SystemService {
  name: string;
  status: 'running' | 'stopped' | 'error';
  uptime: number;
  cpu_usage: number;
  memory_usage: number;
  restart_count: number;
  last_restart?: string;
}

interface NetworkInterface {
  name: string;
  status: 'up' | 'down';
  ip_address: string;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  errors: number;
}

interface DiskInfo {
  device: string;
  mount_point: string;
  total_space: number;
  used_space: number;
  free_space: number;
  usage_percentage: number;
  filesystem: string;
}

export default function SystemHealth() {
  const [activeTab, setActiveTab] = useState('overview');

  // Fetch system metrics
  const { data: metrics, isLoading: metricsLoading, refetch: refetchMetrics } = useQuery({
    queryKey: ['system-metrics'],
    queryFn: () => apiClient.getSystemMetrics(),
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Fetch network status
  const { data: networkStatus, isLoading: networkLoading } = useQuery({
    queryKey: ['network-status'],
    queryFn: () => apiClient.getNetworkStatus(),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Mock system services data
  const { data: services = [], isLoading: servicesLoading } = useQuery({
    queryKey: ['system-services'],
    queryFn: async () => {
      // Mock services data - replace with actual API call
      return [
        {
          name: 'nginx',
          status: 'running' as const,
          uptime: 2847593,
          cpu_usage: 2.1,
          memory_usage: 45.2,
          restart_count: 3,
          last_restart: '2024-01-15T10:30:00Z'
        },
        {
          name: 'mysql',
          status: 'running' as const,
          uptime: 2847593,
          cpu_usage: 8.5,
          memory_usage: 234.7,
          restart_count: 1,
          last_restart: '2024-01-14T09:15:00Z'
        },
        {
          name: 'redis',
          status: 'running' as const,
          uptime: 2847593,
          cpu_usage: 1.2,
          memory_usage: 89.3,
          restart_count: 0
        },
        {
          name: 'elasticsearch',
          status: 'error' as const,
          uptime: 0,
          cpu_usage: 0,
          memory_usage: 0,
          restart_count: 12,
          last_restart: '2024-01-16T08:45:00Z'
        }
      ] as SystemService[];
    },
    refetchInterval: 15000,
  });

  // Mock disk information
  const { data: diskInfo = [], isLoading: diskLoading } = useQuery({
    queryKey: ['disk-info'],
    queryFn: async () => {
      // Mock disk data - replace with actual API call
      return [
        {
          device: '/dev/sda1',
          mount_point: '/',
          total_space: 500000000000, // 500GB
          used_space: 350000000000,  // 350GB
          free_space: 150000000000,  // 150GB
          usage_percentage: 70,
          filesystem: 'ext4'
        },
        {
          device: '/dev/sda2',
          mount_point: '/var/log',
          total_space: 100000000000, // 100GB
          used_space: 25000000000,   // 25GB
          free_space: 75000000000,   // 75GB
          usage_percentage: 25,
          filesystem: 'ext4'
        }
      ] as DiskInfo[];
    },
    refetchInterval: 30000,
  });

  // Mock network interfaces
  const { data: networkInterfaces = [], isLoading: interfacesLoading } = useQuery({
    queryKey: ['network-interfaces'],
    queryFn: async () => {
      // Mock network interfaces - replace with actual API call
      return [
        {
          name: 'eth0',
          status: 'up' as const,
          ip_address: '192.168.1.100',
          bytes_sent: 1048576000,
          bytes_received: 2097152000,
          packets_sent: 1000000,
          packets_received: 1500000,
          errors: 0
        },
        {
          name: 'eth1',
          status: 'up' as const,
          ip_address: '10.0.0.50',
          bytes_sent: 524288000,
          bytes_received: 1048576000,
          packets_sent: 500000,
          packets_received: 750000,
          errors: 2
        }
      ] as NetworkInterface[];
    },
    refetchInterval: 15000,
  });

  // Generate mock historical data for charts
  const generateHistoricalData = () => {
    const data = [];
    const now = new Date();
    for (let i = 23; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 60 * 60 * 1000);
      data.push({
        time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        disk: Math.random() * 100,
        network: Math.random() * 1000
      });
    }
    return data;
  };

  const historicalData = generateHistoricalData();

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'running':
      case 'up':
        return 'text-green-500';
      case 'stopped':
      case 'down':
        return 'text-yellow-500';
      case 'error':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'running':
      case 'up':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'stopped':
      case 'down':
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-500" />;
    }
  };

  const formatBytes = (bytes: number) => {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;
    
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Health Monitoring</h1>
          <p className="text-muted-foreground">
            Monitor system performance, services, and resource utilization
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetchMetrics()}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* System Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {metricsLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32 bg-background-tertiary/40" />
          ))
        ) : (
          <>
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Cpu className="h-5 w-5 text-blue-500" />
                    <span className="font-medium">CPU Usage</span>
                  </div>
                  <span className="text-2xl font-bold">{metrics?.cpu_usage?.toFixed(1) || 0}%</span>
                </div>
                <Progress value={metrics?.cpu_usage || 0} className="mb-2" />
                <div className="flex items-center text-sm text-muted-foreground">
                  <TrendingUp className="h-3 w-3 mr-1 text-green-500" />
                  Normal load
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <MemoryStick className="h-5 w-5 text-green-500" />
                    <span className="font-medium">Memory Usage</span>
                  </div>
                  <span className="text-2xl font-bold">{metrics?.memory_usage?.toFixed(1) || 0}%</span>
                </div>
                <Progress value={metrics?.memory_usage || 0} className="mb-2" />
                <div className="flex items-center text-sm text-muted-foreground">
                  <TrendingDown className="h-3 w-3 mr-1 text-green-500" />
                  Optimal usage
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <HardDrive className="h-5 w-5 text-yellow-500" />
                    <span className="font-medium">Disk Usage</span>
                  </div>
                  <span className="text-2xl font-bold">{metrics?.disk_usage?.toFixed(1) || 0}%</span>
                </div>
                <Progress value={metrics?.disk_usage || 0} className="mb-2" />
                <div className="flex items-center text-sm text-muted-foreground">
                  <AlertTriangle className="h-3 w-3 mr-1 text-yellow-500" />
                  Monitor closely
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <Network className="h-5 w-5 text-purple-500" />
                    <span className="font-medium">Network</span>
                  </div>
                  <span className="text-2xl font-bold">{formatBytes(metrics?.network_throughput || 0)}/s</span>
                </div>
                <div className="text-sm text-muted-foreground">
                  <div>Connections: {metrics?.active_connections || 0}</div>
                </div>
                <div className="flex items-center text-sm text-muted-foreground mt-2">
                  <CheckCircle className="h-3 w-3 mr-1 text-green-500" />
                  All interfaces up
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="storage">Storage</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {/* Performance Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>System Performance (24h)</CardTitle>
                <CardDescription>CPU and Memory usage over time</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={historicalData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Line 
                      type="monotone" 
                      dataKey="cpu" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      name="CPU %"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="memory" 
                      stroke="#10b981" 
                      strokeWidth={2}
                      name="Memory %"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Disk I/O</CardTitle>
                <CardDescription>Disk read/write activity</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={historicalData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Area 
                      type="monotone" 
                      dataKey="disk" 
                      stroke="#f59e0b" 
                      fill="#f59e0b" 
                      fillOpacity={0.3}
                      name="Disk Usage %"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* System Information */}
          <Card>
            <CardHeader>
              <CardTitle>System Information</CardTitle>
              <CardDescription>Current system status and uptime</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Server className="h-4 w-4 text-blue-500" />
                    <span className="font-medium">System Uptime</span>
                  </div>
                  <p className="text-2xl font-bold">{formatUptime(metrics?.uptime || 0)}</p>
                  <p className="text-sm text-muted-foreground">Since last reboot</p>
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Activity className="h-4 w-4 text-green-500" />
                    <span className="font-medium">Load Average</span>
                  </div>
                  <p className="text-2xl font-bold">1.23</p>
                  <p className="text-sm text-muted-foreground">1 min / 5 min / 15 min</p>
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Thermometer className="h-4 w-4 text-red-500" />
                    <span className="font-medium">Temperature</span>
                  </div>
                  <p className="text-2xl font-bold">42°C</p>
                  <p className="text-sm text-muted-foreground">CPU temperature</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="services" className="space-y-4">
          {/* System Services */}
          <Card>
            <CardHeader>
              <CardTitle>System Services</CardTitle>
              <CardDescription>Status and resource usage of critical services</CardDescription>
            </CardHeader>
            <CardContent>
              {servicesLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Service</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Uptime</TableHead>
                      <TableHead>CPU Usage</TableHead>
                      <TableHead>Memory Usage</TableHead>
                      <TableHead>Restarts</TableHead>
                      <TableHead>Last Restart</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {services.map((service) => (
                      <TableRow key={service.name}>
                        <TableCell className="font-medium">{service.name}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {getStatusIcon(service.status)}
                            <Badge 
                              variant={service.status === 'running' ? 'default' : 'destructive'}
                              className={service.status === 'running' ? '' : 'bg-red-500'}
                            >
                              {service.status}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>{formatUptime(service.uptime)}</TableCell>
                        <TableCell>{service.cpu_usage.toFixed(1)}%</TableCell>
                        <TableCell>{formatBytes(service.memory_usage * 1024 * 1024)}</TableCell>
                        <TableCell>{service.restart_count}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {service.last_restart 
                            ? new Date(service.last_restart).toLocaleString()
                            : 'Never'
                          }
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="storage" className="space-y-4">
          {/* Storage Information */}
          <Card>
            <CardHeader>
              <CardTitle>Disk Usage</CardTitle>
              <CardDescription>Storage utilization across all mounted filesystems</CardDescription>
            </CardHeader>
            <CardContent>
              {diskLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 2 }).map((_, i) => (
                    <Skeleton key={i} className="h-20 w-full" />
                  ))}
                </div>
              ) : (
                <div className="space-y-4">
                  {diskInfo.map((disk) => (
                    <div key={disk.device} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <h4 className="font-medium">{disk.device}</h4>
                          <p className="text-sm text-muted-foreground">
                            {disk.mount_point} • {disk.filesystem}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="font-medium">{disk.usage_percentage}% used</p>
                          <p className="text-sm text-muted-foreground">
                            {formatBytes(disk.used_space)} / {formatBytes(disk.total_space)}
                          </p>
                        </div>
                      </div>
                      <Progress 
                        value={disk.usage_percentage} 
                        className={`h-2 ${disk.usage_percentage > 80 ? 'bg-red-100' : ''}`}
                      />
                      <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                        <span>Used: {formatBytes(disk.used_space)}</span>
                        <span>Free: {formatBytes(disk.free_space)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="network" className="space-y-4">
          {/* Network Interfaces */}
          <Card>
            <CardHeader>
              <CardTitle>Network Interfaces</CardTitle>
              <CardDescription>Status and statistics for all network interfaces</CardDescription>
            </CardHeader>
            <CardContent>
              {interfacesLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 2 }).map((_, i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Interface</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Bytes Sent</TableHead>
                      <TableHead>Bytes Received</TableHead>
                      <TableHead>Packets Sent</TableHead>
                      <TableHead>Packets Received</TableHead>
                      <TableHead>Errors</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {networkInterfaces.map((iface) => (
                      <TableRow key={iface.name}>
                        <TableCell className="font-medium">{iface.name}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {getStatusIcon(iface.status)}
                            <Badge variant={iface.status === 'up' ? 'default' : 'secondary'}>
                              {iface.status}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono">{iface.ip_address}</TableCell>
                        <TableCell>{formatBytes(iface.bytes_sent)}</TableCell>
                        <TableCell>{formatBytes(iface.bytes_received)}</TableCell>
                        <TableCell>{iface.packets_sent.toLocaleString()}</TableCell>
                        <TableCell>{iface.packets_received.toLocaleString()}</TableCell>
                        <TableCell>
                          <Badge variant={iface.errors > 0 ? 'destructive' : 'secondary'}>
                            {iface.errors}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Network Performance Chart */}
          <Card>
            <CardHeader>
              <CardTitle>Network Traffic (24h)</CardTitle>
              <CardDescription>Network throughput over time</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={historicalData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Bar 
                    dataKey="network" 
                    fill="#8b5cf6" 
                    name="Network Throughput (MB/s)"
                  />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
