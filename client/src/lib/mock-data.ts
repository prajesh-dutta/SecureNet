import { format } from 'date-fns';

// Utility function to generate timestamps
export const getTimeString = (date: Date): string => {
  return format(date, 'yyyy-MM-dd HH:mm:ss');
};

// Generate random IP addresses
export const generateRandomIP = (): string => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

// Network Traffic Data
export const generateNetworkTrafficData = () => {
  const hours = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  return hours.map((time) => ({
    time,
    inbound: Math.floor(Math.random() * 60) + 20,
    outbound: Math.floor(Math.random() * 50) + 15,
    blocked: Math.floor(Math.random() * 15) + 2,
  }));
};

// Security Events
export const generateSecurityEvents = () => {
  const eventTypes = [
    'Brute Force Attack',
    'SQL Injection',
    'Suspicious Login',
    'Data Exfiltration',
    'Port Scan',
    'DDoS Attack',
    'Malware Detected',
    'Unauthorized Access',
    'Cross-Site Scripting',
    'Phishing Attempt'
  ];
  
  const severities = ['Critical', 'Medium', 'Low'] as const;
  const statuses = ['Blocked', 'Active', 'Investigating'] as const;
  
  return Array.from({ length: 5 }, (_, i) => {
    const date = new Date();
    date.setMinutes(date.getMinutes() - i * 15);
    
    return {
      id: `event-${i}`,
      timestamp: getTimeString(date),
      eventType: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      source: generateRandomIP(),
      destination: i % 2 === 0 ? 
        `Web Server (172.16.0.${Math.floor(Math.random() * 20) + 1})` : 
        `API Gateway (172.16.0.${Math.floor(Math.random() * 20) + 1})`,
      severity: i < 2 ? 'Critical' : i < 4 ? 'Medium' : 'Low',
      status: i % 3 === 0 ? 'Blocked' : i % 3 === 1 ? 'Active' : 'Investigating'
    };
  });
};

// Threat Level Data
export const generateThreatLevelData = () => {
  return {
    score: Math.floor(Math.random() * 30) + 60, // Generate a score between 60 and 90
    level: 'High' as const,
    metrics: [
      {
        name: 'Intrusion Attempts',
        level: 'High' as const,
        value: Math.floor(Math.random() * 20) + 75, // 75-95%
      },
      {
        name: 'Malware Detected',
        level: 'Medium' as const,
        value: Math.floor(Math.random() * 20) + 50, // 50-70%
      },
      {
        name: 'Vulnerability Score',
        level: 'High' as const,
        value: Math.floor(Math.random() * 20) + 65, // 65-85%
      },
    ],
  };
};

// Geographic Threat Data
export const generateGeoThreatData = () => {
  return {
    threats: Array.from({ length: 10 }, (_, i) => ({
      id: `threat-${i}`,
      latitude: (Math.random() * 180) - 90,
      longitude: (Math.random() * 360) - 180,
      severity: i < 3 ? 'Critical' : i < 7 ? 'Medium' : 'Low',
    })),
    summary: {
      critical: 12,
      medium: 24,
      low: 53,
    },
  };
};

// System Status Data
export const generateSystemStatusData = () => {
  return {
    overallStatus: 'Healthy' as const,
    systems: [
      {
        name: 'Firewall',
        status: 'Online' as const,
        health: 100,
      },
      {
        name: 'IDS/IPS',
        status: 'Online' as const,
        health: 100,
      },
      {
        name: 'VPN Service',
        status: 'Degraded' as const,
        health: 65,
      },
      {
        name: 'Log Collection',
        status: 'Online' as const,
        health: 92,
      },
      {
        name: 'Email Security',
        status: 'Online' as const,
        health: 98,
      },
    ],
  };
};

// Active Alerts
export const generateActiveAlerts = () => {
  return [
    {
      id: 'alert-1',
      title: 'Brute Force Attack',
      description: 'Multiple failed login attempts detected on Admin Portal',
      timestamp: '13:42:15',
      severity: 'Critical' as const,
    },
    {
      id: 'alert-2',
      title: 'Data Exfiltration',
      description: 'Unusual outbound data transfer from Database Server',
      timestamp: '13:25:36',
      severity: 'Critical' as const,
    },
    {
      id: 'alert-3',
      title: 'Suspicious Login',
      description: 'Login from unusual location for user admin@example.com',
      timestamp: '13:30:57',
      severity: 'Medium' as const,
    },
  ];
};

// Dashboard Overview Stats
export const generateOverviewStats = () => {
  return [
    {
      title: 'Active Threats',
      value: 12,
      change: '+3',
      changeType: 'negative' as const,
      subtitle: '4 critical, 8 moderate',
      iconType: 'warning',
    },
    {
      title: 'Protected Systems',
      value: 247,
      change: '+12',
      changeType: 'positive' as const,
      subtitle: '98.8% operational',
      iconType: 'computer',
    },
    {
      title: 'Network Traffic',
      value: '1.8 TB',
      change: '+24%',
      changeType: 'neutral' as const,
      subtitle: '2.4k active connections',
      iconType: 'network',
    },
    {
      title: 'Blocked Attacks',
      value: 5294,
      change: '+8%',
      changeType: 'positive' as const,
      subtitle: 'Last 24 hours',
      iconType: 'shield',
    },
  ];
};
