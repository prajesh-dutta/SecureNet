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
          {/* Interactive network topology visualization */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-20 h-20 border-2 border-accent-primary rounded-full flex items-center justify-center relative">
              <span className="absolute w-full h-full rounded-full bg-accent-primary opacity-10 ping-animation"></span>
              <div className="w-16 h-16 bg-background-tertiary rounded-full flex items-center justify-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-accent-primary">
                  <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                  <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                  <line x1="6" y1="10" x2="6" y2="14"></line>
                  <line x1="12" y1="10" x2="12" y2="14"></line>
                  <line x1="18" y1="10" x2="18" y2="14"></line>
                </svg>
              </div>
              
              {/* Connection lines */}
              <div className="absolute top-0 left-full w-20 h-px bg-accent-primary"></div>
              <div className="absolute top-0 right-full w-20 h-px bg-accent-primary"></div>
              <div className="absolute bottom-0 left-full w-20 h-px bg-accent-primary"></div>
              <div className="absolute bottom-0 right-full w-20 h-px bg-accent-primary"></div>
              
              {/* Connected nodes */}
              <div className="absolute top-0 left-full ml-20 -mt-2 w-4 h-4 bg-accent-secondary rounded-full"></div>
              <div className="absolute top-0 right-full mr-20 -mt-2 w-4 h-4 bg-accent-secondary rounded-full"></div>
              <div className="absolute bottom-0 left-full ml-20 -mb-2 w-4 h-4 bg-accent-danger rounded-full"></div>
              <div className="absolute bottom-0 right-full mr-20 -mb-2 w-4 h-4 bg-accent-tertiary rounded-full"></div>
            </div>
          </div>
          
          {/* Alert points */}
          <div className="absolute top-1/4 right-1/4 w-3 h-3 bg-accent-danger rounded-full ping-animation"></div>
          <div className="absolute bottom-1/3 left-1/3 w-3 h-3 bg-accent-warning rounded-full ping-animation"></div>
        </div>
      </CardContent>
    </Card>
  );
}
