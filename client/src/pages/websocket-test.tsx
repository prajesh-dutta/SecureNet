import { useEffect, useState } from 'react';
import { useSocket } from '@/hooks/useSocket';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function WebSocketTest() {
  const [metrics, setMetrics] = useState<any>(null);
  const { socket, isConnected } = useSocket();

  useEffect(() => {
    if (socket) {
      socket.on('system_metrics_update', (data) => {
        setMetrics(data);
      });

      // Request an update when first connected
      socket.emit('request_system_update');

      return () => {
        socket.off('system_metrics_update');
      };
    }
  }, [socket]);

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">WebSocket Connection Test</h1>
      
      <div className="mb-4">
        <p>Connection Status: {isConnected ? 
          <span className="text-green-500 font-bold">Connected</span> : 
          <span className="text-red-500 font-bold">Disconnected</span>}
        </p>
      </div>

      {metrics && (
        <Card>
          <CardHeader>
            <CardTitle>Real-time System Metrics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">CPU Usage</p>
                <p className="text-2xl font-bold">{metrics.cpu_usage}%</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Memory Usage</p>
                <p className="text-2xl font-bold">{metrics.memory_usage}%</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Disk Usage</p>
                <p className="text-2xl font-bold">{metrics.disk_usage}%</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Hostname</p>
                <p className="text-2xl font-bold">{metrics.hostname}</p>
              </div>
            </div>
            
            <div className="mt-4">
              <p className="text-sm text-muted-foreground">Network Stats</p>
              <pre className="mt-2 p-2 bg-gray-100 rounded text-xs overflow-auto">
                {JSON.stringify(metrics.network_stats, null, 2)}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
