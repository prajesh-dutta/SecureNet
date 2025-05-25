import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useSocket } from '@/hooks/useSocket';
import { Cpu, HardDrive, Activity, Wifi, Monitor, Clock } from 'lucide-react';

export const RealTimeSystemMetrics: React.FC = () => {
  const { connected, systemMetrics, error, requestUpdate } = useSocket();

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  if (error) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-red-500" />
            Real-Time System Metrics
            <Badge variant="destructive">Error</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-red-500">Connection Error: {error}</p>
          <button 
            onClick={requestUpdate}
            className="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Retry Connection
          </button>
        </CardContent>
      </Card>
    );
  }

  if (!connected) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-yellow-500" />
            Real-Time System Metrics
            <Badge variant="secondary">Connecting...</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p>Connecting to real-time data feed...</p>
        </CardContent>
      </Card>
    );
  }

  if (!systemMetrics) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-green-500" />
            Real-Time System Metrics
            <Badge variant="outline">Connected</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p>Waiting for system data...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-green-500" />
          Real-Time System Metrics
          <Badge variant="default">Live</Badge>
        </CardTitle>
        <div className="text-sm text-muted-foreground">
          {systemMetrics.hostname} ({systemMetrics.platform})
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* CPU Usage */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-blue-500" />
              <span className="font-medium">CPU Usage</span>
            </div>
            <span className="text-sm font-mono">{systemMetrics.cpu_usage.toFixed(1)}%</span>
          </div>
          <Progress 
            value={systemMetrics.cpu_usage} 
            className="h-2"
            // @ts-ignore
            color={systemMetrics.cpu_usage > 80 ? 'red' : systemMetrics.cpu_usage > 60 ? 'yellow' : 'green'}
          />
        </div>

        {/* Memory Usage */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-green-500" />
              <span className="font-medium">Memory Usage</span>
            </div>
            <span className="text-sm font-mono">{systemMetrics.memory_usage.toFixed(1)}%</span>
          </div>
          <Progress 
            value={systemMetrics.memory_usage} 
            className="h-2"
            // @ts-ignore
            color={systemMetrics.memory_usage > 80 ? 'red' : systemMetrics.memory_usage > 60 ? 'yellow' : 'green'}
          />
        </div>

        {/* Disk Usage */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-purple-500" />
              <span className="font-medium">Disk Usage</span>
            </div>
            <span className="text-sm font-mono">{systemMetrics.disk_usage.toFixed(1)}%</span>
          </div>
          <Progress 
            value={systemMetrics.disk_usage} 
            className="h-2"
            // @ts-ignore
            color={systemMetrics.disk_usage > 80 ? 'red' : systemMetrics.disk_usage > 60 ? 'yellow' : 'green'}
          />
        </div>

        {/* Network Stats */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4 text-indigo-500" />
              <span className="text-sm font-medium">Sent</span>
            </div>
            <p className="text-xs font-mono text-muted-foreground">
              {formatBytes(systemMetrics.network_stats?.bytes_sent || 0)}
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4 text-orange-500" />
              <span className="text-sm font-medium">Received</span>
            </div>
            <p className="text-xs font-mono text-muted-foreground">
              {formatBytes(systemMetrics.network_stats?.bytes_recv || 0)}
            </p>
          </div>
        </div>

        {/* System Info */}
        <div className="grid grid-cols-2 gap-4 pt-2 border-t">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-gray-500" />
              <span className="text-sm font-medium">Uptime</span>
            </div>
            <p className="text-xs font-mono text-muted-foreground">
              {formatUptime(systemMetrics.uptime)}
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Monitor className="h-4 w-4 text-teal-500" />
              <span className="text-sm font-medium">Connections</span>
            </div>
            <p className="text-xs font-mono text-muted-foreground">
              {systemMetrics.network_stats?.connections || 0}
            </p>
          </div>
        </div>

        {/* Last Update */}
        <div className="text-xs text-muted-foreground text-center">
          Last updated: {new Date(systemMetrics.timestamp * 1000).toLocaleTimeString()}
        </div>
      </CardContent>
    </Card>
  );
};

export default RealTimeSystemMetrics;
