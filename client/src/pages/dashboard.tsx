import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { StatCard } from '@/components/dashboard/stat-card';
import NetworkTrafficChart from '@/components/dashboard/network-traffic-chart';
import SecurityEventsTable from '@/components/dashboard/security-events-table';
import NetworkTopology from '@/components/dashboard/network-topology';
import ThreatLevelGauge from '@/components/dashboard/threat-level-gauge';
import GeographicThreatMap from '@/components/dashboard/geographic-threat-map';
import SystemStatusCard from '@/components/dashboard/system-status-card';
import ActiveAlertsCard from '@/components/dashboard/active-alerts-card';
import RealTimeSystemMetrics from '@/components/dashboard/real-time-system-metrics';
import { RealtimeSOCDashboard } from '@/components/dashboard/realtime-soc-dashboard';
import { Skeleton } from '@/components/ui/skeleton';
import { AlertTriangle, Computer, Shield, BarChart2, Activity, Zap } from 'lucide-react';
import { apiClient } from '@/lib/api-client';
import { useSocket } from '@/hooks/useSocket';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  
  // Get real-time data from WebSocket
  const { systemMetrics, connected } = useSocket();
  
  const { data: overviewStats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: async () => {
      const [overview, metrics, threats] = await Promise.all([
        apiClient.getDashboardOverview(),
        apiClient.getSystemMetrics(),
        apiClient.getRecentThreats(50)
      ]);
      
      // Calculate stats from real data, prioritize WebSocket data if available
      const realTimeMetrics = systemMetrics ? {
        cpu_usage: systemMetrics.cpu_usage,
        memory_usage: systemMetrics.memory_usage,
        disk_usage: systemMetrics.disk_usage,
        network_throughput: (systemMetrics.network_stats?.bytes_sent || 0) + (systemMetrics.network_stats?.bytes_recv || 0),
        active_connections: systemMetrics.network_stats?.connections || 0,
        uptime: systemMetrics.uptime
      } : metrics;
      
      const activeThreats = threats.filter(t => t.status === 'active').length;
      const criticalThreats = threats.filter(t => t.severity === 'critical').length;
      const blockedAttacks = threats.filter(t => t.status === 'resolved').length;
      
      return {
        activeThreats,
        criticalThreats,
        protectedSystems: Math.round(100 - (realTimeMetrics.cpu_usage + realTimeMetrics.memory_usage) / 2),
        networkTraffic: `${(realTimeMetrics.network_throughput / (1024 * 1024 * 1024)).toFixed(1)} GB`,
        blockedAttacks,
        realTimeData: connected && systemMetrics?.real_time_data
      };
    },
    refetchInterval: connected ? 10000 : 5000 // Reduce polling when WebSocket is connected
  });

  return (
    <div className="space-y-6">
      {/* Dashboard Mode Selector */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-3xl font-bold tracking-tight">Security Operations Center</h1>
            {connected && (
              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                Live Data
              </span>
            )}
          </div>
          <p className="text-muted-foreground">
            Real-time threat monitoring and network security dashboard
            {overviewStats?.realTimeData && " • Live system metrics active"}
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant={activeTab === 'overview' ? 'default' : 'outline'}
            onClick={() => setActiveTab('overview')}
            className="flex items-center space-x-2"
          >
            <BarChart2 className="h-4 w-4" />
            <span>Classic View</span>
          </Button>
          <Button
            variant={activeTab === 'realtime' ? 'default' : 'outline'}
            onClick={() => setActiveTab('realtime')}
            className="flex items-center space-x-2"
          >
            <Activity className="h-4 w-4" />
            <span>Real-time SOC</span>
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="overview" className="flex items-center space-x-2">
            <BarChart2 className="h-4 w-4" />
            <span>Overview Dashboard</span>
          </TabsTrigger>
          <TabsTrigger value="realtime" className="flex items-center space-x-2">
            <Zap className="h-4 w-4" />
            <span>Real-time SOC</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Overview Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {statsLoading ? (
              <>
                <Skeleton className="h-24 w-full bg-background-tertiary/40" />
                <Skeleton className="h-24 w-full bg-background-tertiary/40" />
                <Skeleton className="h-24 w-full bg-background-tertiary/40" />
                <Skeleton className="h-24 w-full bg-background-tertiary/40" />
              </>
            ) : (
              <>
                <StatCard
                  title="Active Threats"
                  value={overviewStats?.activeThreats || 0}
                  change={`${overviewStats?.criticalThreats || 0} critical`}
                  changeType="negative"
                  subtitle={`${overviewStats?.criticalThreats || 0} critical, ${(overviewStats?.activeThreats || 0) - (overviewStats?.criticalThreats || 0)} moderate`}
                  icon={<AlertTriangle className="h-5 w-5" />}
                  iconColor="danger"
                />
                <StatCard
                  title="Protected Systems"
                  value={overviewStats?.protectedSystems || 247}
                  change="+12"
                  changeType="positive"
                  subtitle="98.8% operational"
                  icon={<Computer className="h-5 w-5" />}
                  iconColor="secondary"
                />
                <StatCard
                  title="Network Traffic"
                  value={overviewStats?.networkTraffic || "1.8 TB"}
                  change="+24%"
                  changeType="neutral"
                  subtitle="2.4k active connections"
                  icon={<BarChart2 className="h-5 w-5" />}
                  iconColor="primary"
                />
                <StatCard
                  title="Blocked Attacks"
                  value={overviewStats?.blockedAttacks || 5294}
                  change="+8%"
                  changeType="positive"
                  subtitle="Last 24 hours"
                  icon={<Shield className="h-5 w-5" />}
                  iconColor="tertiary"
                />
              </>
            )}
          </div>
          
          {/* Main Dashboard Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Column */}
            <div className="col-span-2 space-y-6">
              <NetworkTrafficChart />
              <SecurityEventsTable />
              <NetworkTopology />
            </div>
            
            {/* Right Column */}
            <div className="space-y-6">
              <RealTimeSystemMetrics />
              <ThreatLevelGauge />
              <GeographicThreatMap />
              <SystemStatusCard />
              <ActiveAlertsCard />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="realtime" className="space-y-6">
          <RealtimeSOCDashboard />
        </TabsContent>
      </Tabs>
    </div>
  );
}
