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
import { useEffect, useRef } from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  ResponsiveContainer 
} from 'recharts';
import { apiClient } from '@/lib/api-client';

interface ThreatLevelData {
  score: number;
  level: 'Low' | 'Medium' | 'High';
  metrics: {
    name: string;
    level: 'Low' | 'Medium' | 'High';
    value: number;
  }[];
}

export default function ThreatLevelGauge() {
  const { data, isLoading, isError, refetch } = useQuery<ThreatLevelData>({
    queryKey: ['threats-level'],
    queryFn: async () => {
      const threats = await apiClient.getRecentThreats(50);
      const criticalCount = threats.filter(t => t.severity === 'critical').length;
      const highCount = threats.filter(t => t.severity === 'high').length;
      const mediumCount = threats.filter(t => t.severity === 'medium').length;
      const lowCount = threats.filter(t => t.severity === 'low').length;
      
      // Calculate threat level based on severity distribution
      const totalThreats = threats.length;
      const criticalWeight = criticalCount * 4;
      const highWeight = highCount * 3;
      const mediumWeight = mediumCount * 2;
      const lowWeight = lowCount * 1;
      
      const totalWeight = criticalWeight + highWeight + mediumWeight + lowWeight;
      const maxPossibleWeight = totalThreats * 4;
      
      const score = maxPossibleWeight > 0 ? Math.round((totalWeight / maxPossibleWeight) * 100) : 15;
      
      let level: 'Low' | 'Medium' | 'High' = 'Low';
      if (score >= 75) level = 'High';
      else if (score >= 40) level = 'Medium';
      
      return {
        score,
        level,
        metrics: [
          { name: 'Critical Threats', level: criticalCount > 5 ? 'High' : criticalCount > 2 ? 'Medium' : 'Low', value: Math.min((criticalCount / 10) * 100, 100) },
          { name: 'Network Security', level: score > 60 ? 'High' : score > 30 ? 'Medium' : 'Low', value: 100 - score },
          { name: 'System Health', level: 'Low', value: 85 }
        ]
      };
    },
    refetchInterval: 30000
  });

  const getLevelColor = (level: 'Low' | 'Medium' | 'High') => {
    switch (level) {
      case 'Low': return 'hsl(var(--accent-secondary))';
      case 'Medium': return 'hsl(var(--accent-warning))';
      case 'High': return 'hsl(var(--accent-danger))';
    }
  };

  const getLevelClass = (level: 'Low' | 'Medium' | 'High') => {
    switch (level) {
      case 'Low': return 'threat-indicator-low';
      case 'Medium': return 'threat-indicator-medium';
      case 'High': return 'threat-indicator-high';
    }
  };

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Threat Level</CardTitle>
          <Skeleton className="h-6 w-16 bg-background-tertiary/40" />
        </CardHeader>
        <CardContent className="flex flex-col items-center">
          <Skeleton className="h-48 w-48 rounded-full bg-background-tertiary/40" />
          <div className="mt-4 w-full space-y-2">
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
          <CardTitle className="text-base font-medium">Threat Level</CardTitle>
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
            <p className="text-text-secondary">Failed to load threat level data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Format gauge data for the semi-circle gauge
  const gaugeData = [
    { name: 'Score', value: data.score },
    { name: 'Remaining', value: 100 - data.score }
  ];

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Threat Level</CardTitle>
        <div className="flex items-center space-x-2">
          <span className={`text-xs px-2 py-0.5 rounded-full bg-accent-${data.level.toLowerCase()}/20 text-accent-${data.level.toLowerCase()}`}>
            {data.level}
          </span>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col items-center">
        <div className="relative w-48 h-48">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={gaugeData}
                cx="50%"
                cy="50%"
                startAngle={180}
                endAngle={0}
                innerRadius="70%"
                outerRadius="90%"
                paddingAngle={0}
                dataKey="value"
                stroke="none"
              >
                <Cell fill={getLevelColor(data.level)} />
                <Cell fill="rgba(30, 41, 59, 0.4)" />
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-4xl font-bold font-inter text-accent-${data.level.toLowerCase()}`}>
              {data.score}
            </span>
            <span className="text-xs text-text-secondary">out of 100</span>
          </div>
        </div>
        <div className="mt-4 w-full space-y-2">
          {data.metrics.map((metric, index) => (
            <div key={index}>
              <div className="flex justify-between text-xs mb-1">
                <span>{metric.name}</span>
                <span>{metric.level}</span>
              </div>
              <div className="w-full h-1.5 bg-background-tertiary rounded-full overflow-hidden">
                <div 
                  className={`h-full ${getLevelClass(metric.level)} rounded-full`} 
                  style={{ width: `${metric.value}%` }}
                ></div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
