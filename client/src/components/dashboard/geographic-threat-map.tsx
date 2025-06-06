import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RefreshCw } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { Skeleton } from '@/components/ui/skeleton';
import { apiClient } from '@/lib/api-client';

interface ThreatLocation {
  id: string;
  latitude: number;
  longitude: number;
  severity: 'Critical' | 'Medium' | 'Low';
  country?: string;
  description?: string;
}

interface GeoMapData {
  threats: ThreatLocation[];
  summary: {
    critical: number;
    medium: number;
    low: number;
  };
}

export default function GeographicThreatMap() {
  const { data, isLoading, isError, refetch } = useQuery<GeoMapData>({
    queryKey: ['geographic-threats'],
    queryFn: async () => {
      const geoThreats = await apiClient.getGeographicThreats();
      
      // Transform the data into the expected format
      const threats: ThreatLocation[] = geoThreats.map((threat: any, index: number) => ({
        id: threat.id || `threat-${index}`,
        latitude: threat.latitude || (Math.random() * 60 + 10), // Random lat if not provided
        longitude: threat.longitude || (Math.random() * 140 - 70), // Random lng if not provided
        severity: threat.severity === 'critical' ? 'Critical' : 
                 threat.severity === 'medium' ? 'Medium' : 'Low',
        country: threat.country || 'Unknown',
        description: threat.description || `Threat from ${threat.source_ip || 'Unknown IP'}`
      }));
      
      const summary = {
        critical: threats.filter(t => t.severity === 'Critical').length,
        medium: threats.filter(t => t.severity === 'Medium').length,
        low: threats.filter(t => t.severity === 'Low').length
      };
      
      return { threats, summary };
    },
    refetchInterval: 45000
  });

  if (isLoading) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Geographic Threats</CardTitle>
          <div className="flex items-center space-x-2">
            <span className="text-xs text-text-secondary">Real-time</span>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <RefreshCw className="h-4 w-4 text-text-secondary" />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-64 w-full bg-background-tertiary/40" />
          <Skeleton className="h-6 w-full mt-4 bg-background-tertiary/40" />
        </CardContent>
      </Card>
    );
  }

  if (isError || !data) {
    return (
      <Card className="glass-effect">
        <CardHeader className="flex justify-between items-center pb-2">
          <CardTitle className="text-base font-medium">Geographic Threats</CardTitle>
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
            <p className="text-text-secondary">Failed to load geographic threat data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="glass-effect">
      <CardHeader className="flex justify-between items-center pb-2">
        <CardTitle className="text-base font-medium">Geographic Threats</CardTitle>
        <div className="flex items-center space-x-2">
          <span className="text-xs text-text-secondary">Real-time</span>
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
        <div className="h-64 w-full bg-background-primary rounded relative overflow-hidden">
          {/* World map SVG with darker colors for cybersecurity theme */}
          <svg
            className="w-full h-full opacity-20"
            viewBox="0 0 1000 500"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M781.68,324.4l-2.31,8.68l-12.53,4.23l-3.75-4.4l-1.82,1.24l0.44,2.31l-3.24,1.50l-2.26-8.41l-0.56-8.41l-2.29-1.81l1.94-4.85l4.93-1.24l6.98,3.39l8.25,1.92l4.85,2.31L781.68,324.4L781.68,324.4z M722.48,317.57l-0.35,2.19l6.33,11.31l2.67-2.83l-0.09-3.02l-1.81-1.38l0.35-2.55l1.33-2.37l-1.68-2.73l-4.58,0.27L722.48,317.57L722.48,317.57z M789.53,349.11l2.50,3.88l-2.57,0.85l-0.79,2.82l-1.98,0.07l-1.51-3.11l-2.01-0.85l0.44-1.06l3.87-1.77L789.53,349.11L789.53,349.11z M498.69,375.39l-0.92,1.66l-4.42,0.92l-1.30,0.97l-4.39,0.44l-2.62-1.24l-1.32-2.46l-2.56-0.22l-3.32,1.95l-0.04,1.06l1.77,1.46l-0.74,2.81l-3.11,1.95l-3.23-0.66l-2.56,0.09l-2.87-1.51l-3.32-3.07l-0.07-1.86l1.81-3.46l0.29-6.8l-2.41-3.40l-1.33-3.40l-0.92-3.46l-3.63-3.88l-0.74-2.24l-3.89-0.31l-0.09-3.2l-2.87-0.35l-0.37-4.97l-1.70-0.87l-2.67,1.77l-1.16-0.18l-0.04-2.08l-2.89-1.86l-0.29-3.05l-2.89-0.13l-2.67,3.54l-0.42,3.84l-1.30,1.48l-0.74-0.44l0.42-4.47l1.90-2.66l-1.50-2.33l2.06-7.04l2.69-3.37l2.16-0.93l0.76,3.05l1.95,0.16l1.84-1.86l5.95-2.02l3.47,0.09l1.95,2.50l0.90,0.34l1.13-1.93l3.08-1.13l4.37,0.88l0.78-0.88l2.15-0.88l2.26,0.48l3.32-2.09l3.08-0.54l1.99,1.49l1.06-0.74l4.84,0.15l0.17,1.91l4.37,0.15l2.25-7.20l3.42-3.32l1.25,0.82l-0.36,2.31l1.05,0.15l0.85-1.96l2.01-0.19l1.99-1.43l2.15,0.19l1.06,1.53l0.37,2.01l-1.81,1.91l0.42,1.1l2.72,0.15l1.76-1.96l1.36-0.29l0.70,2.97l-2.56,8.45l0.30,2.20l2.99,1.91l-3.23,4.48L516.80,349.60l-0.32,3.07l1.41,1.20l-1.41,2.82l-2.30,2.35l2.50,4.10l0.03,2.24l-1.30,1.48l0.23,1.10l-2.87,2.34l-4.16,0.62L498.69,375.39L498.69,375.39z M916.72,91.25l3.92,4.58l10.99,4.58l5.71-2.26l5.35,7.51l-3.92,4.17l-10.28,3.50l-11.34-4.85l-6.42-5.71l0.11-4.01L916.72,91.25L916.72,91.25z M983.49,89.59l5.35,0.41l3.92,3.06l-3.92,4.17l-4.06,2.86l-5.50-0.1l-6.69-0.81l-5.35-3.40l0.39-2.45L983.49,89.59L983.49,89.59z M982.85,114.59l3.92-0.25l-6.47,3.87l-14.46,5.26l-9.70,1.32l-9.59-2.45l-7.65-3.98l-9.97-6.69l-1.90-4.25l10.51-4.68l7.65,0.51l7.61,6.20l8.61,1.89L982.85,114.59L982.85,114.59z M926.44,112.62l1.96-2.45l8.61,0.41l2.94,2.04l-4.90,4.48l-8.61,0.41L926.44,112.62L926.44,112.62z M892.44,119.10l9.61-4.17h8.29l7.97,1.67l1.18,2.45l-9.76,1.33l-7.79,2.45l-6.49-0.84L892.44,119.10L892.44,119.10z M718.88,177.34l-8.18,2.04l-3.92-1.84l-1.96-3.05l-1.96-0.82l-1.96,2.45l-11.96,2.04l-6.67-3.40l-8.18-1.84l-8.18-2.45l3.92-3.36l-5.88-2.45l-8.33-1.43l-3.92-1.84l-4.65-0.82l-0.65-1.84l-8.18-1.84l-1.96-1.43l-10.47-3.05l-8.18-1.03l-3.92-2.45l-4.90-1.84l-1.96-2.04l3.92-1.43l7.19,0.21l5.88-1.84l-5.88-2.04l1.31-2.86l4.90-0.61l6.54-0.41l-1.96-1.63l-6.54-1.43l-3.27-0.82l-1.96-2.04l8.83-2.04l7.52-0.21l11.31,2.86l9.49,5.10l3.92,1.84l10.14,1.43l18.97,6.95l6.22,2.86l-1.96,1.43l5.23,1.43l13.92,2.24l7.19,3.87h-2.61L718.88,177.34L718.88,177.34z M782.86,153.97l-9.47-3.57l-5.33-1.77l-6.83-0.07l-5.32,1.69l-11.87-1.95l-7.68-2.68l-9.99-0.02l-7.32-0.59l-3.49,2.95l-3.75,0.71l-4.81-0.08l-7.78-3.31l-2.69-2.58l5.08-2.81l5.98-0.04l6.88-0.04l-5.35-2.96l-1.42-2.52l-8.83-2.88l7.98-0.04l-0.08-3.40l-1.96-2.45l6.54-2.45l3.92-0.41l7.19,1.43l3.27-0.41l9.15,1.22l14.70,6.95l9.80,0.82l5.23,1.43l13.58,1.84l13.27,2.24l6.54,1.84L782.86,153.97L782.86,153.97z M794.76,132.03l-4.41-2.67l-8.20-0.15l-2.09-0.75l2.94-1.59l-1.47-1.77l3.92-1.59l7.74-0.05l0.04,1.72l-0.98,2.69L794.76,132.03L794.76,132.03z M812.41,123.75l-2.77,2.17l-2.94-1.59l-0.49-2.19l6.37-0.20L812.41,123.75L812.41,123.75z M816.33,116.88l1.96-1.63l5.88,1.22l-1.96,1.84L816.33,116.88L816.33,116.88z M830.90,124.31l-5.55-0.05l-6.52-1.54l2.94-1.59l7.19,0.41l0.98,1.17L830.90,124.31L830.90,124.31z M851.69,125.95l-5.88-0.61l-8.18-1.22l-7.84-2.25l-7.32-3.87l2.16-2.35l2.12-0.78l6.74,0.73l-0.17-1.17l-3.07-0.20l0.17-1.95l3.33-1.63l2.11-0.39l7.65,2.74l5.68,0.20l-0.33,2.45l4.24,0.59l3.72,0.87l-0.24,1.27l-4.20,0.49l-4.12,2.45l4.32,2.21L851.69,125.95L851.69,125.95z M873.91,95.18l-7.28,3.48l-1.35-2.30l2.94-2.18l6.87-2.30L873.91,95.18L873.91,95.18z M880.58,131.66l-3.43-1.12l-2.77-1.54l1.96-1.63l4.90,1.43L880.58,131.66L880.58,131.66z M874.63,133.71l-2.77,1.95l-1.11-1.95l0.33-1.54l3.72-1.95l1.47,1.54L874.63,133.71L874.63,133.71z M877.08,125.95l-2.61,1.59l-2.57-0.37l-0.04-1.72l2.94-1.59l1.83,0.23L877.08,125.95L877.08,125.95z M868.92,137.34l-2.61-1.17l0.33-1.54l2.28-1.54l2.77,2.72L868.92,137.34L868.92,137.34z M896.53,117.72l-6.87,0.41l-8.16-1.62l-0.98-1.17l7.19-1.22l4.57,0.81l3.92,1.63L896.53,117.72L896.53,117.72z M893.92,123.95l-5.06,0.48l-4.90-1.53l-2.37-1.85l0.90-1.48l8.94,0.81l3.27,1.43L893.92,123.95L893.92,123.95z M899.14,142.59l-6.87-1.95l-2.61-1.59v-1.95l9.47,2.35L899.14,142.59L899.14,142.59z M909.26,144.95l-2.45-3.67l-3.43-2.72l-3.73-3.27l-1.13-2.72l-7.19-4.08l-5.55-0.05l-2.61,0.59l-9.31-1.17l-3.10-0.78l-2.45-0.98l2.94-2.35l7.19,0.61l14.05-0.97l-1.14-1.37l-10.79-0.20l-8.82-1.37l-7.36-2.72l-3.43-2.15l-0.65-1.59l4.57-1.95l-2.45-1.77l-3.10-0.98l-2.45-1.95l-2.45-2.93l-3.10-1.95l-2.45-1.95l-0.33-2.35l-1.31-1.37l-3.43-1.37l0.33-2.35l-3.76-3.32l-1.96-1.17l0.33-2.93l7.84-2.95l10.14-0.61l1.63,2.56l1.31-0.59l3.92,2.35l-3.43,0.59l-6.21,0.20l-2.94,1.17l3.76,2.95l-0.33,1.37l11.12,1.56l-2.45,1.57l-4.57-0.39l-5.88-1.17l-2.94,0.59l-1.31,1.17l4.57,2.74l9.80,2.54l-0.98,1.37l-10.80-1.95l-2.12,1.17l-2.28,0.20l0.65,1.76l-3.92,0.78l-1.31,0.98l1.31,1.96l2.77,0.59l0.33,1.37l3.27,1.76l6.54-0.39l3.10,1.17l-1.96,1.96l-0.65,2.15l-2.45-0.59l-3.76-2.35l-3.59,0.20l-0.49,0.98l2.94,2.54l0.16,1.76l-2.28,1.17l-1.63-0.78l-2.45,1.76l3.92,1.95l1.31,2.15l-1.31,1.76l-3.10,0.20l-2.28-3.91l-2.12-0.20l-3.27-0.98l-2.12,0.39l-2.28,1.96l1.80,1.76l8.82,4.10l1.96,2.15l2.77,0.59l2.45-0.59l2.61,1.56l2.28-0.59l3.76,2.35l1.63,0.59l10.14,0.39l5.23-1.17l2.12,0.98l-0.33,2.54l1.31,0.59l4.57-1.17l7.19-0.59l5.88,1.56L909.26,144.95L909.26,144.95z M917.44,155.97l-4.90,0.61l-2.94-1.84l0.65-1.43l4.90-0.82l3.59,1.22L917.44,155.97L917.44,155.97z M931.69,155.76l-5.88-0.41l-2.94-1.02l2.61-1.02l5.23-0.20L931.69,155.76L931.69,155.76z M938.55,149.84l-4.08,0.16l-3.96-1.87l-1.07-1.13l2.93-0.87l5.06,0.87l2.49,1.91L938.55,149.84L938.55,149.84z M952.82,154.44l-3.59-0.20l-3.59-1.22l-3.27-1.22l0.98-1.43l3.59-0.20l6.87,1.63L952.82,154.44L952.82,154.44z M967.52,143.21l-3.27-0.82l-0.65-1.84l-2.61-0.20l-2.61,1.22l-3.27-1.43l1.31-1.43l3.59-2.45l4.24,0.61l3.59,2.04l1.96,1.43L967.52,143.21L967.52,143.21z M992.43,151.38l-4.57-0.20l-5.88-1.02l-2.61,0.61l-2.61-0.61l-5.23-1.84l-5.88-1.43l0.65-1.43l3.27-0.82l5.23,0.20l6.21,0.41l7.84,0.82l2.94,2.24L992.43,151.38L992.43,151.38z M225.93,175.94l-1.74,0.92l-3.54-0.63l-2.47-1.48l0.72-1.13l1.19,0.14l2.47,1.13L225.93,175.94L225.93,175.94z M245.23,175.73l-1.83,1.05l-3.54-0.63l-2.47-1.48l0.65-1.13l1.37,0.14l2.47,1.13L245.23,175.73L245.23,175.73z M265.56,175.66l-4.68-0.42l-0.65-0.70l4.68-0.92l1.53,0.42L265.56,175.66L265.56,175.66z M272.40,177.86l-3.01,0.42l-5.59-0.84l-4.25-0.42l-3.01-1.27v-1.41l1.12-0.21l4.25,0.84l3.61-0.42l2.73,0.84L272.40,177.86L272.40,177.86z M295.53,199.32l-2.83-1.27l-3.54-2.54l-4.11-1.27l-1.34-2.11l-2.12-1.06l-3.54,0.85l-2.40-1.69l-2.83,0.56l-5.09-1.04l-4.11-0.28l-3.82-1.27l-1.41-1.41h-9.64l-7.79,1.41l-2.97-1.13l-2.47,1.98l-0.85,0.14l-2.26-3.25l-4.11-1.98l-1.98-1.41l-0.28-1.83l-3.25-2.54l0.28-1.27l-1.35-1.40l-2.54-0.42l-1.13-0.42l0.42-2.11l-1.69-1.13l-0.85-1.83l0.28-0.35l3.11,0.71l0.99-0.28l3.68-1.69l1.69,0.28l2.11-1.13l3.11-3.81l4.25-0.71l2.11-0.28l0.42,1.55l3.54-0.14l2.83-1.40l2.40-0.71l1.69-0.71l2.11,1.69l2.68,0.28l-0.14,1.40l-4.39,0.14l-0.14,0.85l-2.83,2.11l-2.40,2.96h-2.68l-0.71,3.39l3.82,2.82l4.68,0.56l2.40-0.56l3.25,1.98l3.82,0.85l3.68,0.14v2.11l1.55,1.55l0.85-0.85l-1.69-3.11l3.68-1.98l2.26-1.13l2.68,0.14l2.96,2.25l-0.14,1.13l3.11,0.28l0.85,0.71l2.54-1.83l3.54-0.42l0.42,2.39l2.68,0.14l1.55,1.69l-0.85,1.13l0.42,2.11l3.96,1.69l3.96-0.28l2.82,0.99l2.54,2.96v0.85l-4.53,0.14l-0.42,0.71l1.55,1.13l-1.13,1.98l-2.54,0.42l-1.13,1.41l-2.82,0.14l-2.11,0.99l-0.28,0.85l1.98,0.28L295.53,199.32L295.53,199.32z M265.99,218.45l-2.47-1.69l0.14-1.55l2.54-2.11l-2.54-2.54l-3.25-0.14l-3.11-3.53l-2.11-0.99l-0.85-2.25l-0.14-1.55l-3.11-1.13l0.99-1.69l-0.28-1.69l-4.82-0.42l-0.85-1.41l-2.68-0.14l-1.83,0.99l-3.11-0.71l-5.22-2.11l-0.85-1.69h-3.82l-0.42-1.55l-2.54-0.85l-0.99-3.39l1.83-1.27l-0.71-1.55l-0.71-0.14l-0.71,2.54l-1.13,0.85l-1.13-0.85l0.14-3.53l2.11-0.71l0.14-1.41l-1.41-0.71l-1.55,0.28l-3.11-1.69l-3.11,0.28l-0.14,1.13l-1.98,1.13l-0.85-0.14l-0.99,1.27l-3.25-0.14l-3.54-1.27l-4.96-0.71l-3.54-1.55l-1.41-2.96l-2.54-0.28l-3.11-1.55l-3.39,0.71l-3.82-0.71l-1.41,0.99h-3.39l-2.54-1.27l-1.27,0.85l-3.68-1.41l-1.41-0.85l-3.39,0.71l-2.68-1.55l-3.54,0.14l-2.68-0.28l-2.26,0.85l-1.13-1.41l-1.98-0.71l-1.13,0.28l-0.85-0.71l-1.13,1.27l-5.09,0.14l-2.40,0.28l0.28-1.83l-2.68-0.71l-0.42-0.71l-0.85-0.99l0.85-0.42l3.39,0.85l2.11-0.28l2.82,0.56l2.97-1.55h1.13l2.82,0.71l4.82-0.56l-0.42-1.69l-1.41-0.56l-1.55-0.14l-1.98,0.99l-1.83-0.99l1.13-1.27l4.11-1.55l2.40-1.69l5.64-0.56l-0.28-1.13l3.39-2.25l2.97-0.56l4.53-1.55l2.40-2.82l2.68-1.69l-0.14-1.83l-1.69-1.83l-0.56-1.97l4.39-3.53l2.40-0.56l3.68-2.68l3.82-0.42l1.41-0.71l-0.28-1.83l2.11-0.85l2.11,0.56l0.42,1.41l2.82,0.56l0.85-0.85l-0.28-1.69l0.85-0.56l0.28-1.69l-3.39-0.56l-1.55,0.42l-1.83-0.71l-1.83,0.71l-5.64-0.14l-0.42-0.85l0.85-1.55l-0.85-0.71l-2.82,1.55l-3.39-0.42l-2.82-1.13l-1.98,1.13l-2.97,0.28l-0.42-1.69l-3.11-1.27l-3.68-2.25l-3.82-0.14l-0.85-1.13l-3.39-0.71l-2.40-1.83l-3.25-0.28l-0.56-0.42l-2.97-0.14l-2.82-0.71l-1.69-1.97l-1.83-0.14v-1.41l-2.54-1.13l-2.82,0.14l-1.69-0.71l0.42-1.69l0.71-0.85l2.97-0.14l1.69-0.56h1.83l0.71-0.71l2.11,0.56l2.82-1.55l1.41,0.14l1.83-0.99l3.54,0.28l6.49,0.14l4.68,0.28l1.13,1.13l5.51,0.28l0.42-1.13l3.25-0.85l0.56,0.42l3.39-0.14l2.97,2.11l1.83,0.28l1.55,0.85l2.40-0.56l2.68,1.69l3.54-0.14l6.21,0.28l0.85,1.27l1.98,0.28l3.54,1.83l2.68,2.25l4.11,0.85l0.85,1.27l-1.13,1.27l-1.13,1.83l-1.69-0.28l-2.82,0.42l-0.42,1.41l-0.71,0.14l-1.41-1.97l-4.82-0.14l-3.11,0.85l-1.98-0.56l-0.85,0.56l0.71,2.11l-0.85,0.56h-2.54l-4.82-0.42l-4.39-0.99l-1.55,1.97l0.42,1.55l-1.13,0.85l-2.97,0.42l-1.69,0.56l-0.85,1.41h-0.28l-1.13-1.13l-1.69,0.28l-2.97,2.25h-2.40l-3.11-0.28l-1.13,0.42l-1.55-0.42l-1.83,0.42l-1.41-0.42l-1.69,0.71l-1.55-0.85l-1.41,0.42l-2.54-0.42l-1.98,1.97l0.28,2.25l1.83,1.41l-0.28,0.71l-2.11,0.14l-1.69,1.69l-0.28,1.83l-0.99,0.85l1.41,1.55l-0.56,0.85l1.13,0.85l-0.71,2.11l1.13,0.99l-0.28,0.56l-2.40,0.71l-1.55,1.13l-0.42,1.41l1.55,0.42l-1.55,1.97l0.42,1.69l-1.13,0.71l0.71,1.83l2.68,0.42l0.85,1.27h1.69l2.40,0.85l1.98-0.14l2.11,1.13l2.82-1.55l1.98,0.28l0.71,0.71l3.25-0.28l1.13,0.42l0.71,1.13l2.68,0.28l2.68,1.13l0.14,0.85l1.55,0.71l2.68-0.56l0.85,0.56l2.40-0.71l2.97,0.71l-0.14,1.27l3.54,1.41l1.83-0.85l2.11,0.99l1.55-0.42l1.55,0.85l-0.71,0.85l1.13,1.27l-0.28,1.69l1.41,0.42l-0.56,1.83l0.85,0.28l0.85,1.27l-0.85,0.99l0.42,2.11l-0.99,0.71l1.13,1.41l-0.14,1.13l-2.11,1.69v1.41l1.83,1.69l0.28,1.13l2.54,0.28l0.71,1.98l1.41,0.71l0.71,1.83l-0.71,1.13l1.13,1.41v1.41l-1.13,0.99l-0.28,2.11l-1.13,0.28l0.14,1.13l-1.83,1.98l1.55,1.83l-1.27,2.40l-1.41,0.71l-0.42,1.83l1.27,1.83l-0.71,1.55l0.71,0.56l-0.71,1.27l0.71,1.55l-0.71,0.85l1.41,0.42l0.14,1.41l3.82,0.56l2.82,1.27L265.99,218.45L265.99,218.45z M207.23,139.16l-1.13-2.11l-1.13-0.14l-1.98-1.13l-0.28-1.27l-1.83-0.56l-0.99-1.41l-2.68-0.56l-0.14-0.85l-1.41-0.56l-0.85-1.69l-2.82-1.27l3.54-0.99l2.40,0.28l2.68-0.99l1.98,0.28l1.55,1.27l2.40,0.71l1.55,1.41l4.11,0.56l-1.41,0.85l0.42,1.69l-0.71,1.13l0.71,1.83l-2.68,1.98L207.23,139.16L207.23,139.16z M183.32,156.01l-1.26-0.49l-1.23,0.52l-0.91-1.47l0.70-0.56l0.56,0.35l0.35-0.49l0.91,0.84L183.32,156.01L183.32,156.01z M186.60,154.71l-0.60-0.63l-0.60-0.28l-0.77,0.49l-0.63-0.14l-0.07-0.91h-0.91l0.35-0.56l0.98-0.28l0.91,0.84h1.05l0.28,0.91L186.60,154.71L186.60,154.71z M162.47,143.67l-0.98-0.98l1.12-0.63l0.63,0.21l0.28,0.49L162.47,143.67L162.47,143.67z M161.42,140.81l-0.49-0.49l-0.98,0.14l-0.47-0.56l0.28-0.49l1.12,0.56L161.42,140.81L161.42,140.81z M192.59,163.20l0.42-1.27l0.85-0.85l0.71-0.14l1.41,1.13l-0.85,0.85l-0.99,0.14L192.59,163.20L192.59,163.20z M460.89,76.21l-1.97,1.93l-2.96-1.40l-1.55,0.30l-0.17,1.24l-5.05,1.67l-3.33-0.90l-4.88,3.10l-0.38,1.24l-3.50-1.65l-2.36,0.33l-2.80-0.37l-0.55,1.90l-2.63-0.52l-1.97,0.82l-1.13-0.52l-3.33-1.05l-2.52-1.20l-2.60,0.75l-2.13-0.67l-1.60,0.60l-2.21-0.90l-3.13,0.60l-2.80-1.57l-2.35,0.22l-2.10,1.12l-1.68-0.22l-1.85,0.97l-1.97-0.82l-2.38,1.27l-3.16-0.22l-1.80-0.82l-2.77,0.52l-2.63,0.30l-2.10-1.05l-1.80,0.22l-1.77-1.57l-1.38,1.42l-1.22-0.52l-0.88-1.20l-1.30-0.37l-1.72,0.90l-1.38-2.10l-1.30-0.37l-2.35,0.52l-1.22-0.75l-0.71,0.30l-0.28-1.88l-1.80-0.60l-1.22,0.30l-0.71-1.65l-2.35-0.22l-1.13-1.42l-2.38-0.22l-2.21,0.97l-4.71-0.22l-0.38-0.75l-1.38-0.22l-0.55-1.35h-1.97l-1.60-0.82l-2.52-0.22l-0.88-1.05l-0.55-0.52l-2.63,0.60l-1.38-0.60l-1.63-1.35l-2.35-0.07l-0.38-0.82l-2.80-0.52l-2.52,0.90l-2.49,0.22l-1.55-0.97l-2.27,0.37l-0.58-0.67l-0.16-1.95l2.80-0.22l1.13-0.52l0.17-1.27l-1.55-0.67l-0.71-1.05l0.88-1.35l2.85,0.22l0.55-0.75l-1.55-1.50l-0.05-0.97l1.88-1.50l1.22,0.22l2.99-1.27l2.88,0.97l2.60,0.37l1.88-0.37l2.66,0.52l1.97-1.27l1.47,0.37l0.88-0.67l1.30,0.22l1.05-0.45l1.22,0.45l2.52-0.82l1.46,0.52l1.97-0.45l3.80-0.07l2.80-1.27l2.21-0.07l2.35-1.05l2.16,0.75l2.80-0.15l2.24,0.60l2.63-1.50l3.10-0.90l0.30-1.27l-2.16-1.72l1.05-1.35l2.35-0.45l2.21,0.45l0.38,1.57l2.10-0.60l2.85,0.30l1.97-1.50l2.27,0.30l2.38-1.05l0.66-1.35l1.16-0.22l-0.05-1.20l3.33-1.27l3.63-0.52l2.99-1.05l1.46,0.15l2.24-1.12l2.71,0.07l2.35,0.75l3.55-0.37l2.35-1.35l0.99,0.22l2.40-0.97l2.63,0.07l2.16-0.90l0.44-0.97l2.16-0.97l1.68,0.07l3.13-1.20l2.52-0.15l1.88-0.82l0.60-1.20l1.63-0.37l0.71-1.05l2.27-0.82l0.44-1.12l4.74-1.57l2.10,0.45l3.38-0.97l2.44,0.75l3.16,0.22l2.13,0.82l0.82,0.52l2.85-0.45l-0.44,0.97l1.05,1.05l1.55,0.22l0.17,0.67l3.13,0.97l0.82,1.20l2.52,0.45l0.88,1.50l2.80,0.37l0.55,0.52l2.27-0.07l0.44,0.37l2.40-0.97l1.80,0.22l1.88-0.97l1.55,0.45l0.55-1.12l1.46,0.97l2.27-0.07l1.80,0.60l0.33,0.97l1.71-0.07l0.14,0.60l2.77,0.15l1.05-0.75l0.88,0.15l0.82-0.90l1.97,0.30l0.99-0.97l0.27,0.90l1.63,0.52l0.88-0.75l2.49,0.22l0.38,0.37l2.35-0.67l0.44,0.67l2.10-0.37l1.72,0.45l1.30-0.22l-1.43,2.62l-1.38,0.97l-1.05-0.37l-2.35,0.52l-0.11,0.52l-3.03,0.45l-0.33,0.60l-2.77,0.90l-0.44,0.97l-2.60,0.45l-1.68,1.27l-1.30,0.15l-0.11,0.52l-3.13,0.07l-0.22,0.97l-0.88,0.37l-1.38-0.60l-2.21,0.97l-2.88-0.37l-1.97,0.45l-0.60,0.60l-2.49,0.15l-1.97,1.12l-0.66,0.75l-1.60,0.37l-0.93,1.87l-1.55,1.42l-0.17,1.20l-1.80,0.90l0.22,1.05l-1.97,0.45l-0.82,1.65l-1.38,0.97l-0.93,1.65h-1.22l-1.80,0.90l-0.49,0.97l-3.71-0.45l-1.46,0.75l-0.66,1.35l-1.13-0.75l-0.33-1.05l-2.71,0.97l0.05,1.05l-0.77,0.45l-0.11,1.05l-1.60,0.15l-0.71,0.60l-0.55-0.60l-2.52,0.97l-0.77-0.82l-0.36,1.84l-2.27-0.15l-0.33-0.37l-2.21,0.52l-0.99,0.75l-0.11,0.75l-1.63,0.75l-0.99-0.22l-0.60,0.60l-2.38-0.22l-1.46,0.67l-0.71-0.82l-1.68,0.30l-1.49-0.37l-0.55-0.60l-2.27,0.45l-0.88-0.82L460.89,76.21L460.89,76.21z"
              fill="#3b4a61"
            />
          </svg>
          
          {/* Threat indicators on the map */}
          <div className="absolute top-1/4 left-1/4 w-3 h-3 bg-accent-danger rounded-full ping-animation"></div>
          <div className="absolute top-1/3 right-1/3 w-3 h-3 bg-accent-danger rounded-full ping-animation"></div>
          <div className="absolute bottom-1/4 right-1/4 w-3 h-3 bg-accent-warning rounded-full ping-animation"></div>
          <div className="absolute bottom-1/3 left-1/5 w-3 h-3 bg-accent-warning rounded-full ping-animation"></div>
          <div className="absolute top-1/2 right-1/4 w-3 h-3 bg-accent-primary rounded-full ping-animation"></div>
        </div>
        <div className="mt-4">
          <div className="flex justify-between text-xs">
            <div className="flex items-center">
              <span className="w-3 h-3 bg-accent-danger rounded-full"></span>
              <span className="ml-1">Critical ({data.summary.critical})</span>
            </div>
            <div className="flex items-center">
              <span className="w-3 h-3 bg-accent-warning rounded-full"></span>
              <span className="ml-1">Medium ({data.summary.medium})</span>
            </div>
            <div className="flex items-center">
              <span className="w-3 h-3 bg-accent-primary rounded-full"></span>
              <span className="ml-1">Low ({data.summary.low})</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
