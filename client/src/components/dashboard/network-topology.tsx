import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Maximize, RefreshCw } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '@/lib/api-client';

export default function NetworkTopology() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['/api/network/topology'],
    queryFn: () => apiClient.getNetworkTopology(),
    refetchInterval: 45000, // Refresh every 45 seconds
  });
  const containerRef = useRef<HTMLDivElement>(null);
  const [fullscreen, setFullscreen] = useState(false);

  const toggleFullscreen = useCallback(() => {
    if (!containerRef.current) return;
    
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().catch(err => {
        console.error(`Error attempting to enable fullscreen: ${err.message}`);
      });
      setFullscreen(true);
    } else {
      document.exitFullscreen();
      setFullscreen(false);
    }
  }, []);

  useEffect(() => {
    const handleFullscreenChange = () => {
      setFullscreen(!!document.fullscreenElement);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Network Topology</CardTitle>
          <div className="flex items-center space-x-2">
            <Button variant="link" size="sm" className="text-accent-primary">
              Zoom
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <Maximize className="h-4 w-4 text-text-secondary" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-80 w-full bg-background-tertiary/40" />
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Network Topology</CardTitle>
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
          <div className="h-80 flex items-center justify-center">
            <p className="text-text-secondary">Failed to load network topology</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Network Topology</CardTitle>
        <div className="flex items-center space-x-2">
          <Button variant="link" size="sm" className="text-accent-primary">
            Zoom
          </Button>
          <Button 
            variant="ghost" 
            size="icon" 
            className="h-8 w-8"
            onClick={toggleFullscreen}
          >
            <Maximize className="h-4 w-4 text-text-secondary" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div 
          ref={containerRef}
          className="h-80 w-full bg-background-primary rounded relative overflow-hidden"
        >
          {/* Network topology visualization using real data */}
          <div className="absolute inset-4">
            {/* Display nodes */}
            {data.nodes?.map((node: any, index: number) => {
              const x = 50 + (index % 3) * 120; // Arrange in grid
              const y = 40 + Math.floor(index / 3) * 80;
              const statusColor = 
                node.status === 'healthy' ? 'border-accent-secondary' :
                node.status === 'warning' ? 'border-accent-warning' :
                'border-accent-danger';
              
              return (
                <div
                  key={node.id}
                  className={`absolute w-12 h-12 ${statusColor} border-2 rounded-full flex items-center justify-center bg-background-tertiary`}
                  style={{ left: x, top: y }}
                  title={`${node.label} (${node.status})`}
                >
                  <div className={`w-8 h-8 rounded-full ${
                    node.type === 'security' ? 'bg-accent-primary' :
                    node.type === 'network' ? 'bg-accent-secondary' :
                    node.type === 'server' ? 'bg-accent-tertiary' :
                    'bg-gray-500'
                  }`}></div>
                </div>
              );
            })}
            
            {/* Display connections */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
              {data.connections?.map((connection: any, index: number) => {
                const sourceNode = data.nodes?.find((n: any) => n.id === connection.source);
                const targetNode = data.nodes?.find((n: any) => n.id === connection.target);
                
                if (!sourceNode || !targetNode) return null;
                
                const sourceIndex = data.nodes.indexOf(sourceNode);
                const targetIndex = data.nodes.indexOf(targetNode);
                
                const x1 = 50 + (sourceIndex % 3) * 120 + 24; // Center of source node
                const y1 = 40 + Math.floor(sourceIndex / 3) * 80 + 24;
                const x2 = 50 + (targetIndex % 3) * 120 + 24; // Center of target node
                const y2 = 40 + Math.floor(targetIndex / 3) * 80 + 24;
                
                return (
                  <line
                    key={index}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke="hsl(var(--accent-primary))"
                    strokeWidth="2"
                    opacity="0.6"
                  />
                );
              })}
            </svg>
            
            {/* Status indicators for critical nodes */}
            {data.nodes?.filter((node: any) => node.status === 'critical' || node.status === 'warning').map((node: any, index: number) => {
              const nodeIndex = data.nodes.indexOf(node);
              const x = 50 + (nodeIndex % 3) * 120 + 24;
              const y = 40 + Math.floor(nodeIndex / 3) * 80 + 24;
              
              return (
                <div
                  key={`alert-${node.id}`}
                  className={`absolute w-3 h-3 rounded-full ping-animation ${
                    node.status === 'critical' ? 'bg-accent-danger' : 'bg-accent-warning'
                  }`}
                  style={{ left: x - 6, top: y - 6 }}
                />
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
