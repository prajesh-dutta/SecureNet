import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useQuery } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import { RefreshCw } from 'lucide-react';
import { apiClient } from '@/lib/api-client';

interface Alert {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  severity: 'Critical' | 'Medium' | 'Low';
}

export default function ActiveAlertsCard() {
  const { data, isLoading, isError, refetch } = useQuery<Alert[]>({
    queryKey: ['active-alerts'],
    queryFn: async () => {
      const threats = await apiClient.getRecentThreats(10);
      return threats
        .filter(threat => threat.status === 'active')
        .map((threat, index) => ({
          id: threat.id,
          title: threat.type.charAt(0).toUpperCase() + threat.type.slice(1),
          description: threat.description,
          timestamp: new Date(threat.timestamp).toLocaleTimeString(),
          severity: threat.severity.charAt(0).toUpperCase() + threat.severity.slice(1) as 'Critical' | 'Medium' | 'Low'
        }));
    },
    refetchInterval: 15000
  });

  const getSeverityColor = (severity: string) => {
    switch(severity) {
      case 'Critical': return 'border-accent-danger';
      case 'Medium': return 'border-accent-warning';
      case 'Low': return 'border-accent-primary';
      default: return 'border-gray-600';
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch(severity) {
      case 'Critical': return 'bg-accent-danger/20 text-accent-danger';
      case 'Medium': return 'bg-accent-warning/20 text-accent-warning';
      case 'Low': return 'bg-accent-primary/20 text-accent-primary';
      default: return 'bg-gray-700 text-gray-400';
    }
  };

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Active Alerts</CardTitle>
          <Button variant="link" size="sm" className="text-accent-primary">
            View All
          </Button>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <Skeleton className="h-24 w-full bg-background-tertiary/40" />
            <Skeleton className="h-24 w-full bg-background-tertiary/40" />
            <Skeleton className="h-24 w-full bg-background-tertiary/40" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Active Alerts</CardTitle>
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
            <p className="text-text-secondary">Failed to load alert data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Active Alerts</CardTitle>
        <Button variant="link" size="sm" className="text-accent-primary">
          View All
        </Button>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {data.map((alert) => (
            <div 
              key={alert.id} 
              className={`p-3 rounded-lg bg-background-tertiary border-l-4 ${getSeverityColor(alert.severity)}`}
            >
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="text-sm font-medium">{alert.title}</h4>
                  <p className="text-xs text-text-secondary mt-1">{alert.description}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full ${getSeverityBadge(alert.severity)}`}>
                  {alert.severity}
                </span>
              </div>
              <div className="flex justify-between items-center mt-3">
                <span className="text-xs text-text-secondary">{alert.timestamp}</span>
                <Button variant="link" size="sm" className="text-accent-primary h-5">
                  Investigate
                </Button>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
