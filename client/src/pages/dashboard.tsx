import { useQuery } from '@tanstack/react-query';
import StatCard from '@/components/dashboard/stat-card';
import NetworkTrafficChart from '@/components/dashboard/network-traffic-chart';
import SecurityEventsTable from '@/components/dashboard/security-events-table';
import NetworkTopology from '@/components/dashboard/network-topology';
import ThreatLevelGauge from '@/components/dashboard/threat-level-gauge';
import GeographicThreatMap from '@/components/dashboard/geographic-threat-map';
import SystemStatusCard from '@/components/dashboard/system-status-card';
import ActiveAlertsCard from '@/components/dashboard/active-alerts-card';
import { Skeleton } from '@/components/ui/skeleton';
import { AlertTriangle, Computer, Shield, BarChart2 } from 'lucide-react';

export default function Dashboard() {
  const { data: overviewStats, isLoading: statsLoading } = useQuery({
    queryKey: ['/api/dashboard/overview'],
  });

  return (
    <>
      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
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
              value={12}
              change="+3"
              changeType="negative"
              subtitle="4 critical, 8 moderate"
              icon={<AlertTriangle className="h-5 w-5" />}
              iconColor="danger"
            />
            <StatCard
              title="Protected Systems"
              value={247}
              change="+12"
              changeType="positive"
              subtitle="98.8% operational"
              icon={<Computer className="h-5 w-5" />}
              iconColor="secondary"
            />
            <StatCard
              title="Network Traffic"
              value="1.8 TB"
              change="+24%"
              changeType="neutral"
              subtitle="2.4k active connections"
              icon={<BarChart2 className="h-5 w-5" />}
              iconColor="primary"
            />
            <StatCard
              title="Blocked Attacks"
              value={5294}
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
          <ThreatLevelGauge />
          <GeographicThreatMap />
          <SystemStatusCard />
          <ActiveAlertsCard />
        </div>
      </div>
    </>
  );
}
