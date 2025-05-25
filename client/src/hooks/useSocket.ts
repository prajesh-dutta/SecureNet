import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';

interface SystemMetrics {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  network_stats: {
    bytes_sent: number;
    bytes_recv: number;
    connections: number;
  };
  hostname: string;
  platform: string;
  uptime: number;
  timestamp: number;
  real_time_data: boolean;
}

interface UseSocketReturn {
  socket: Socket | null;
  connected: boolean;
  systemMetrics: SystemMetrics | null;
  error: string | null;
  requestUpdate: () => void;
}

export const useSocket = (serverUrl: string = 'http://localhost:5001'): UseSocketReturn => {
  const [connected, setConnected] = useState(false);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Initialize socket connection
    try {
      const socket = io(serverUrl, {
        transports: ['websocket', 'polling'],
        timeout: 5000,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });

      socketRef.current = socket;

      // Connection event handlers
      socket.on('connect', () => {
        console.log('Connected to server');
        setConnected(true);
        setError(null);
      });

      socket.on('disconnect', () => {
        console.log('Disconnected from server');
        setConnected(false);
      });

      socket.on('connect_error', (err) => {
        console.error('Connection error:', err);
        setError(`Connection failed: ${err.message}`);
        setConnected(false);
      });

      // System metrics event handler
      socket.on('system_metrics_update', (data: SystemMetrics) => {
        console.log('Received system metrics:', data);
        setSystemMetrics(data);
        setError(null);
      });

      // Cleanup on unmount
      return () => {
        socket.disconnect();
      };
    } catch (err) {
      console.error('Socket initialization error:', err);
      setError('Failed to initialize socket connection');
    }
  }, [serverUrl]);

  const requestUpdate = () => {
    if (socketRef.current && connected) {
      socketRef.current.emit('request_system_update');
    }
  };

  return {
    socket: socketRef.current,
    connected,
    systemMetrics,
    error,
    requestUpdate,
  };
};

export default useSocket;
