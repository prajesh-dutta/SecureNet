import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table';
import { useQuery } from '@tanstack/react-query';
import { RefreshCw, ExternalLink } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: string;
  source: string;
  destination: string;
  severity: 'Critical' | 'Medium' | 'Low';
  status: 'Blocked' | 'Active' | 'Investigating';
}

const severityColors = {
  Critical: 'bg-accent-danger/20 text-accent-danger',
  Medium: 'bg-accent-warning/20 text-accent-warning',
  Low: 'bg-gray-700 text-gray-400',
};

const statusColors = {
  Blocked: 'bg-accent-secondary/20 text-accent-secondary',
  Active: 'bg-accent-danger/20 text-accent-danger',
  Investigating: 'bg-gray-700 text-gray-400',
};

export default function SecurityEventsTable() {
  const { data, isLoading, isError, refetch } = useQuery<SecurityEvent[]>({
    queryKey: ['/api/threats'],
  });

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Recent Security Events</CardTitle>
          <div className="flex items-center space-x-2">
            <Button variant="link" size="sm" className="text-accent-primary">
              View All
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <RefreshCw className="h-4 w-4 text-text-secondary" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Skeleton className="h-8 w-full bg-background-tertiary/40" />
            <Skeleton className="h-12 w-full bg-background-tertiary/40" />
            <Skeleton className="h-12 w-full bg-background-tertiary/40" />
            <Skeleton className="h-12 w-full bg-background-tertiary/40" />
            <Skeleton className="h-12 w-full bg-background-tertiary/40" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Recent Security Events</CardTitle>
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
          <div className="h-64 flex items-center justify-center">
            <p className="text-text-secondary">Failed to load security events</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Recent Security Events</CardTitle>
        <div className="flex items-center space-x-2">
          <Button variant="link" size="sm" className="text-accent-primary">
            View All
          </Button>
          <Button 
            variant="ghost" 
            size="icon" 
            className="h-8 w-8"
            onClick={() => refetch()}
          >
            <RefreshCw className="h-4 w-4 text-text-secondary" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-gray-800">
                <TableHead className="text-xs text-text-secondary">Timestamp</TableHead>
                <TableHead className="text-xs text-text-secondary">Event Type</TableHead>
                <TableHead className="text-xs text-text-secondary">Source</TableHead>
                <TableHead className="text-xs text-text-secondary">Destination</TableHead>
                <TableHead className="text-xs text-text-secondary">Severity</TableHead>
                <TableHead className="text-xs text-text-secondary">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((event) => (
                <TableRow 
                  key={event.id} 
                  className="border-gray-800 hover:bg-background-tertiary/60"
                >
                  <TableCell className="py-3 text-xs">{event.timestamp}</TableCell>
                  <TableCell className="py-3 text-xs">{event.eventType}</TableCell>
                  <TableCell className="py-3 text-xs">{event.source}</TableCell>
                  <TableCell className="py-3 text-xs">{event.destination}</TableCell>
                  <TableCell className="py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${severityColors[event.severity]}`}>
                      {event.severity}
                    </span>
                  </TableCell>
                  <TableCell className="py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${statusColors[event.status]}`}>
                      {event.status}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
