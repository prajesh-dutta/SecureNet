import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { useQuery } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { apiClient } from '@/lib/api-client';

interface SystemStatus {
  overallStatus: 'Healthy' | 'Degraded' | 'Critical';
  systems: {
    name: string;
    status: 'Online' | 'Degraded' | 'Offline';
    health: number;
  }[];
}

export default function SystemStatusCard() {
  const { data, isLoading, isError, refetch } = useQuery<SystemStatus>({
    queryKey: ['system-status-card'],
    queryFn: async () => {
      console.log('🔍 SystemStatusCard: Starting API call...');
      try {
        const metrics = await apiClient.getSystemMetrics();
        console.log('✅ SystemStatusCard: API call successful:', metrics);
        
        // Transform SystemMetrics to SystemStatus format
        const overallHealth = (metrics.cpu_usage + metrics.memory_usage + metrics.disk_usage) / 3;
        let overallStatus: 'Healthy' | 'Degraded' | 'Critical' = 'Healthy';
        
        if (overallHealth > 80) overallStatus = 'Critical';
        else if (overallHealth > 60) overallStatus = 'Degraded';
        
        return {
          overallStatus,
          systems: [
            {
              name: 'IDS Engine',
              status: metrics.cpu_usage > 80 ? 'Degraded' : 'Online',
              health: 100 - metrics.cpu_usage
            },
            {
              name: 'Threat Intelligence',
              status: 'Online',
              health: 95
            },
            {
              name: 'Network Monitor',
              status: metrics.memory_usage > 80 ? 'Degraded' : 'Online',
              health: 100 - metrics.memory_usage
            },
            {
              name: 'Log Analysis',
              status: metrics.disk_usage > 90 ? 'Degraded' : 'Online',
              health: 100 - metrics.disk_usage
            }
          ]
        };
      } catch (error) {
        console.error('❌ SystemStatusCard: API call failed:', error);
        throw error;
      }
    },
    refetchInterval: 60000
  });

  const getStatusColor = (status: string) => {
    switch(status) {
      case 'Online': return 'text-accent-secondary';
      case 'Degraded': return 'text-accent-warning';
      case 'Offline': return 'text-accent-danger';
      default: return 'text-text-secondary';
    }
  };

  const getHealthColor = (status: string) => {
    switch(status) {
      case 'Online': return 'bg-accent-secondary';
      case 'Degraded': return 'bg-accent-warning';
      case 'Offline': return 'bg-accent-danger';
      default: return 'bg-gray-600';
    }
  };

  const getOverallStatusBadge = (status: string) => {
    switch(status) {
      case 'Healthy': return 'bg-accent-secondary/20 text-accent-secondary';
      case 'Degraded': return 'bg-accent-warning/20 text-accent-warning';
      case 'Critical': return 'bg-accent-danger/20 text-accent-danger';
      default: return 'bg-gray-700 text-gray-400';
    }
  };

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">System Status</CardTitle>
          <Skeleton className="h-6 w-20 bg-background-tertiary/40" />
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Skeleton className="h-6 w-full bg-background-tertiary/40" />
            <Skeleton className="h-6 w-full bg-background-tertiary/40" />
            <Skeleton className="h-6 w-full bg-background-tertiary/40" />
            <Skeleton className="h-6 w-full bg-background-tertiary/40" />
            <Skeleton className="h-6 w-full bg-background-tertiary/40" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">System Status</CardTitle>
          <Button 
            variant="ghost" 
            size="icon" 
            className="h-8 w-8"
            onClick={() => refetch()}
          >
            <RefreshCw className="h-4 w-4 text-text-secondary" />
          </Button>
        </CardHeader>
        <CardContent>
          <div className="h-40 flex items-center justify-center">
            <p className="text-text-secondary">Failed to load system status data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">System Status</CardTitle>
        <div>
          <span className={`text-xs px-2 py-0.5 rounded-full ${getOverallStatusBadge(data.overallStatus)}`}>
            {data.overallStatus}
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {data.systems.map((system, index) => (
            <div key={index}>
              <div className="flex justify-between text-xs mb-1">
                <span>{system.name}</span>
                <span className={getStatusColor(system.status)}>{system.status}</span>
              </div>
              <div className="w-full h-1.5 bg-background-tertiary rounded-full overflow-hidden">
                <div 
                  className={`h-full ${getHealthColor(system.status)} rounded-full`} 
                  style={{ width: `${system.health}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
