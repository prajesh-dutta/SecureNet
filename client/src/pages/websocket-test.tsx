import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useSocket } from '@/hooks/useSocket';

export default function WebSocketTest() {
  const { connected, systemMetrics, error, socket } = useSocket();

  return (
    <div className="container mx-auto p-6 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>WebSocket Connection Test</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <strong>Connection Status:</strong>{' '}
            <span className={connected ? 'text-green-500' : 'text-red-500'}>
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          
          {error && (
            <div className="text-red-500">
              <strong>Error:</strong> {error}
            </div>
          )}
          
          <div>
            <strong>Socket Instance:</strong>{' '}
            <span className={socket ? 'text-green-500' : 'text-red-500'}>
              {socket ? 'Available' : 'Not Available'}
            </span>
          </div>
          
          {systemMetrics && (
            <div className="mt-4">
              <h3 className="text-lg font-semibold mb-2">System Metrics:</h3>
              <pre className="bg-gray-100 p-4 rounded text-sm overflow-auto">
                {JSON.stringify(systemMetrics, null, 2)}
              </pre>
            </div>
          )}
          
          {!systemMetrics && connected && (
            <div className="text-yellow-600">
              Connected but no metrics received yet. Waiting for data...
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
