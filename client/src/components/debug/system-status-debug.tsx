// Debug component to troubleshoot SystemStatusCard API issues
import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/lib/api-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export default function SystemStatusDebug() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['system-metrics-debug'],
    queryFn: async () => {
      console.log('🔍 Debug: Calling apiClient.getSystemMetrics()...');
      try {
        const result = await apiClient.getSystemMetrics();
        console.log('✅ Debug: API call successful:', result);
        return result;
      } catch (err) {
        console.error('❌ Debug: API call failed:', err);
        throw err;
      }
    },
    refetchInterval: 10000
  });

  return (
    <Card className="glass-effect border-2 border-yellow-500">
      <CardHeader>
        <CardTitle className="text-yellow-500">System Status Debug</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2 text-sm">
          <div>
            <strong>Status:</strong>
            <span className="ml-2">
              {isLoading && '🔄 Loading...'}
              {isError && '❌ Error'}
              {data && '✅ Success'}
            </span>
          </div>
          
          {isError && (
            <div>
              <strong>Error:</strong>
              <pre className="mt-1 p-2 bg-red-900/20 rounded text-red-400 text-xs overflow-auto">
                {error?.toString() || 'Unknown error'}
              </pre>
            </div>
          )}
          
          {data && (
            <div>
              <strong>Data:</strong>
              <pre className="mt-1 p-2 bg-green-900/20 rounded text-green-400 text-xs overflow-auto">
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}
          
          <button 
            onClick={() => refetch()} 
            className="px-3 py-1 bg-blue-600 text-white rounded text-xs"
          >
            Retry
          </button>
        </div>
      </CardContent>
    </Card>
  );
}
