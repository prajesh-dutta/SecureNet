import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { apiClient } from "./api-client";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
): Promise<Response> {
  const res = await fetch(url, {
    method,
    headers: data ? { "Content-Type": "application/json" } : {},
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const endpoint = queryKey[0] as string;
    
    try {
      // Map common endpoints to API client methods
      if (endpoint === '/api/dashboard/overview') {
        return await apiClient.getDashboardOverview();
      } else if (endpoint === '/api/dashboard/metrics') {
        return await apiClient.getSystemMetrics();
      } else if (endpoint === '/api/dashboard/traffic') {
        return await apiClient.getNetworkTrafficData();
      } else if (endpoint === '/api/threats' || endpoint === '/api/threats/recent') {
        return await apiClient.getRecentThreats();
      } else if (endpoint === '/api/security/events') {
        return await apiClient.getSecurityEvents();
      } else if (endpoint === '/api/network/status') {
        return await apiClient.getNetworkStatus();
      } else if (endpoint === '/api/network/devices') {
        return await apiClient.getNetworkDevices();
      } else if (endpoint === '/api/network/topology') {
        return await apiClient.getNetworkTopology();
      } else if (endpoint === '/api/threats/geographic') {
        return await apiClient.getGeographicThreats();
      } else if (endpoint === '/api/vulnerabilities') {
        return await apiClient.getVulnerabilities();
      } else if (endpoint === '/api/incidents') {
        return await apiClient.getIncidents();
      } else if (endpoint === '/api/incidents/active') {
        return await apiClient.getActiveIncidents();
      } else if (endpoint === '/api/logs/security') {
        return await apiClient.getSecurityLogs();
      } else if (endpoint === '/api/security/ids/alerts') {
        return await apiClient.getIDSAlerts();
      } else if (endpoint === '/api/security/statistics') {
        return await apiClient.getSecurityStatistics();
      } else {
        // Fallback to direct fetch for unknown endpoints
        const res = await fetch(endpoint, {
          credentials: "include",
        });

        if (unauthorizedBehavior === "returnNull" && res.status === 401) {
          return null;
        }

        await throwIfResNotOk(res);
        return await res.json();
      }
    } catch (error) {
      if (unauthorizedBehavior === "returnNull" && (error as Error).message.includes('Authentication required')) {
        return null;
      }
      throw error;
    }
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
