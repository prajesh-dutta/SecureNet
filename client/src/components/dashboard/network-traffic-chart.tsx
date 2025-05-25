import { useState, useEffect, useRef } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { MoreHorizontal, RefreshCw } from 'lucide-react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  TooltipProps
} from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import { apiClient } from '@/lib/api-client';

export default function NetworkTrafficChart() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['network-traffic'],
    queryFn: () => apiClient.getNetworkTrafficData(),
    refetchInterval: 30000
  });

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Network Traffic</CardTitle>
          <div className="flex items-center space-x-2">
            <span className="text-xs text-text-secondary">Last 24 hours</span>
            <button className="p-1 rounded hover:bg-background-tertiary">
              <MoreHorizontal className="h-4 w-4 text-text-secondary" />
            </button>
          </div>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-64 w-full bg-background-tertiary/40" />
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Network Traffic</CardTitle>
          <button 
            className="p-1 rounded hover:bg-background-tertiary"
            onClick={() => refetch()}
          >
            <RefreshCw className="h-4 w-4 text-text-secondary" />
          </button>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center">
            <p className="text-text-secondary">Failed to load network traffic data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const CustomTooltip = ({ active, payload, label }: TooltipProps<number, string>) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background-secondary p-3 border border-border rounded-md shadow-md">
          <p className="text-xs font-medium text-text-primary">{`${label}`}</p>
          {payload.map((entry, index) => (
            <div key={index} className="flex items-center mt-1">
              <div 
                className="w-2 h-2 rounded-full mr-1" 
                style={{ backgroundColor: entry.color }}
              />
              <p className="text-xs text-text-secondary">
                {`${entry.name}: ${entry.value} Mbps`}
              </p>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Network Traffic</CardTitle>
        <div className="flex items-center space-x-2">
          <span className="text-xs text-text-secondary">Last 24 hours</span>
          <button className="p-1 rounded hover:bg-background-tertiary">
            <MoreHorizontal className="h-4 w-4 text-text-secondary" />
          </button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={data}
              margin={{ top: 5, right: 5, left: 0, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis 
                dataKey="time" 
                tick={{ fontSize: 10, fill: 'hsl(var(--text-secondary))' }}
                axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                tickLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              />
              <YAxis 
                tick={{ fontSize: 10, fill: 'hsl(var(--text-secondary))' }}
                axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                tickLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              />
              <Tooltip content={<CustomTooltip />} />
              <Line 
                type="monotone" 
                dataKey="inbound" 
                name="Inbound"
                stroke="hsl(var(--accent-primary))" 
                strokeWidth={2}
                activeDot={{ r: 6 }}
                dot={false}
                fill="rgba(14, 165, 233, 0.1)"
              />
              <Line 
                type="monotone" 
                dataKey="outbound" 
                name="Outbound"
                stroke="hsl(var(--accent-tertiary))" 
                strokeWidth={2}
                activeDot={{ r: 6 }}
                dot={false}
              />
              <Line 
                type="monotone" 
                dataKey="blocked" 
                name="Blocked"
                stroke="hsl(var(--accent-danger))" 
                strokeWidth={2}
                activeDot={{ r: 6 }}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="flex justify-between mt-4">
          <div className="flex items-center">
            <span className="w-3 h-3 bg-accent-primary rounded-full"></span>
            <span className="text-xs ml-1 text-text-secondary">Inbound</span>
          </div>
          <div className="flex items-center">
            <span className="w-3 h-3 bg-accent-tertiary rounded-full"></span>
            <span className="text-xs ml-1 text-text-secondary">Outbound</span>
          </div>
          <div className="flex items-center">
            <span className="w-3 h-3 bg-accent-danger rounded-full"></span>
            <span className="text-xs ml-1 text-text-secondary">Blocked</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
