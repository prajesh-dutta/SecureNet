import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { 
  Search, 
  Filter, 
  Download, 
  Calendar as CalendarIcon, 
  Eye, 
  Shield, 
  User, 
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  Database,
  FileText,
  Settings
} from "lucide-react";
import { cn } from "@/lib/utils";
import { format, subDays } from "date-fns";
import { apiClient } from "@/lib/api-client";

interface SecurityLog {
  id: string;
  timestamp: string;
  level: 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO' | 'DEBUG';
  category: string;
  event_type: string;
  source: string;
  user_id?: string;
  user_ip?: string;
  description: string;
  details: any;
  result: string;
  risk_score: number;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  category: string;
  action: string;
  user_id: string;
  user_ip?: string;
  description: string;
  details: any;
  result: string;
  source: string;
}

interface LogsStats {
  total_events: number;
  critical_alerts: number;
  warning_alerts: number;
  info_events: number;
  unique_users: number;
  failed_authentications: number;
  data_access_events: number;
  admin_actions: number;
}

const getSeverityColor = (level: string) => {
  switch (level?.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'error': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'warning': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'info': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'debug': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const getResultIcon = (result: string) => {
  switch (result?.toLowerCase()) {
    case 'success': return <CheckCircle className="h-4 w-4 text-green-400" />;
    case 'failure': case 'failed': return <XCircle className="h-4 w-4 text-red-400" />;
    case 'partial': return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
    default: return <Clock className="h-4 w-4 text-gray-400" />;
  }
};

export default function Logs() {
  const [activeTab, setActiveTab] = useState("security");
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [userFilter, setUserFilter] = useState("");
  const [dateRange, setDateRange] = useState<{ from: Date; to: Date }>({
    from: subDays(new Date(), 7),
    to: new Date()
  });
  const [selectedLog, setSelectedLog] = useState<SecurityLog | AuditEvent | null>(null);

  // Security Logs Query
  const { data: securityLogs = [], refetch: refetchSecurityLogs } = useQuery({
    queryKey: ['securityLogs', severityFilter, categoryFilter, searchTerm, dateRange],
    queryFn: async () => {
      const filters: any = {};
      if (severityFilter !== 'all') filters.severity = severityFilter;
      if (categoryFilter !== 'all') filters.event_type = categoryFilter;
      if (searchTerm) filters.search = searchTerm;
      if (dateRange.from) filters.start_time = dateRange.from.toISOString();
      if (dateRange.to) filters.end_time = dateRange.to.toISOString();
      
      const response = await apiClient.getSecurityLogs(filters);
      return Array.isArray(response) ? response : (response as any).logs || [];
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Audit Events Query
  const { data: auditEvents = [], refetch: refetchAuditEvents } = useQuery({
    queryKey: ['auditEvents', userFilter, searchTerm, dateRange],
    queryFn: async () => {
      const filters: any = {};
      if (userFilter) filters.user_id = userFilter;
      if (searchTerm) filters.action = searchTerm;
      if (dateRange.from) filters.start_time = dateRange.from.toISOString();
      if (dateRange.to) filters.end_time = dateRange.to.toISOString();
      
      const response = await apiClient.getAuditTrail(filters);
      return Array.isArray(response) ? response : (response as any).events || [];
    },
    refetchInterval: 45000, // Refresh every 45 seconds
  });

  // Log Statistics Query
  const { data: logsStats } = useQuery({
    queryKey: ['logsStats'],
    queryFn: async () => {
      try {
        // Try to get stats from backend first
        const response = await apiClient.getLogsStatistics();
        return response;
      } catch (error) {
        // Fallback to calculating stats from frontend data
        const criticalCount = securityLogs.filter((log: SecurityLog) => 
          log.level === 'CRITICAL' || log.level === 'ERROR'
        ).length;
        
        const warningCount = securityLogs.filter((log: SecurityLog) => 
          log.level === 'WARNING'
        ).length;
        
        const infoCount = securityLogs.filter((log: SecurityLog) => 
          log.level === 'INFO'
        ).length;
        
        const uniqueUsers = new Set(
          [...securityLogs, ...auditEvents]
            .map((log: any) => log.user_id)
            .filter(Boolean)
        ).size;
        
        const failedAuth = securityLogs.filter((log: SecurityLog) => 
          log.category === 'AUTHENTICATION' && log.result === 'FAILURE'
        ).length;
        
        const dataAccess = securityLogs.filter((log: SecurityLog) => 
          log.category === 'DATA_ACCESS'
        ).length;
      
        const adminActions = auditEvents.filter((event: AuditEvent) => 
          event.category === 'ADMIN_ACTION'
        ).length;

        return {
          total_events: securityLogs.length + auditEvents.length,
          critical_alerts: criticalCount,
          warning_alerts: warningCount,
          info_events: infoCount,
          unique_users: uniqueUsers,
          failed_authentications: failedAuth,
          data_access_events: dataAccess,
          admin_actions: adminActions
        };
      }
    },
    refetchInterval: 60000, // Refresh every minute
  });

  const exportLogs = () => {
    const data = activeTab === 'security' ? securityLogs : auditEvents;
    const csv = [
      Object.keys(data[0] || {}).join(','),
      ...data.map((log: any) => Object.values(log).join(','))
    ].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeTab}_logs_${format(new Date(), 'yyyy-MM-dd')}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const filteredSecurityLogs = securityLogs.filter((log: SecurityLog) => {
    const matchesSearch = !searchTerm || 
      log.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.source.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesSearch;
  });

  const filteredAuditEvents = auditEvents.filter((event: AuditEvent) => {
    const matchesSearch = !searchTerm || 
      event.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      event.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (event.user_id && event.user_id.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesUser = !userFilter || 
      (event.user_id && event.user_id.toLowerCase().includes(userFilter.toLowerCase()));
    
    return matchesSearch && matchesUser;
  });

  return (
    <div className="space-y-6">
      {/* Statistics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="glass-effect">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-secondary">Total Events</p>
                <p className="text-2xl font-bold text-primary">{logsStats?.total_events || 0}</p>
              </div>
              <Activity className="h-8 w-8 text-primary/70" />
            </div>
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-secondary">Critical Alerts</p>
                <p className="text-2xl font-bold text-red-400">{logsStats?.critical_alerts || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400/70" />
            </div>
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-secondary">Failed Logins</p>
                <p className="text-2xl font-bold text-yellow-400">{logsStats?.failed_authentications || 0}</p>
              </div>
              <Shield className="h-8 w-8 text-yellow-400/70" />
            </div>
          </CardContent>
        </Card>

        <Card className="glass-effect">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-text-secondary">Unique Users</p>
                <p className="text-2xl font-bold text-blue-400">{logsStats?.unique_users || 0}</p>
              </div>
              <User className="h-8 w-8 text-blue-400/70" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Logs Interface */}
      <Card className="glass-effect">
        <CardHeader>
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <CardTitle className="flex items-center gap-2">
              <Database className="h-6 w-6 text-primary" />
              Security Logs & Audit Trail
            </CardTitle>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={exportLogs}
                className="glass-button"
              >
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  refetchSecurityLogs();
                  refetchAuditEvents();
                }}
                className="glass-button"
              >
                <TrendingUp className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-2 glass-effect">
              <TabsTrigger value="security" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Security Logs
              </TabsTrigger>
              <TabsTrigger value="audit" className="flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Audit Trail
              </TabsTrigger>
            </TabsList>

            {/* Filters */}
            <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-text-secondary" />
                <Input
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 glass-input"
                />
              </div>

              {activeTab === 'security' && (
                <>
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="glass-select">
                      <SelectValue placeholder="Select severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="CRITICAL">Critical</SelectItem>
                      <SelectItem value="ERROR">Error</SelectItem>
                      <SelectItem value="WARNING">Warning</SelectItem>
                      <SelectItem value="INFO">Info</SelectItem>
                      <SelectItem value="DEBUG">Debug</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                    <SelectTrigger className="glass-select">
                      <SelectValue placeholder="Select category" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Categories</SelectItem>
                      <SelectItem value="AUTHENTICATION">Authentication</SelectItem>
                      <SelectItem value="AUTHORIZATION">Authorization</SelectItem>
                      <SelectItem value="DATA_ACCESS">Data Access</SelectItem>
                      <SelectItem value="SECURITY_ALERT">Security Alert</SelectItem>
                      <SelectItem value="CONFIGURATION_CHANGE">Config Change</SelectItem>
                      <SelectItem value="ADMIN_ACTION">Admin Action</SelectItem>
                    </SelectContent>
                  </Select>
                </>
              )}

              {activeTab === 'audit' && (
                <Input
                  placeholder="Filter by user..."
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  className="glass-input"
                />
              )}

              <Popover>
                <PopoverTrigger asChild>
                  <Button variant="outline" className="glass-button justify-start text-left font-normal">
                    <CalendarIcon className="mr-2 h-4 w-4" />
                    {format(dateRange.from, "MMM dd")} - {format(dateRange.to, "MMM dd")}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0 glass-effect border-border/50">
                  <div className="p-3">
                    <div className="grid grid-cols-2 gap-2 mb-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setDateRange({
                          from: subDays(new Date(), 1),
                          to: new Date()
                        })}
                        className="glass-button"
                      >
                        Last 24h
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setDateRange({
                          from: subDays(new Date(), 7),
                          to: new Date()
                        })}
                        className="glass-button"
                      >
                        Last 7 days
                      </Button>
                    </div>
                    <Calendar
                      mode="range"
                      defaultMonth={dateRange.from}
                      selected={{ from: dateRange.from, to: dateRange.to }}
                      onSelect={(range) => {
                        if (range?.from && range?.to) {
                          setDateRange({ from: range.from, to: range.to });
                        }
                      }}
                      numberOfMonths={1}
                      className="glass-effect"
                    />
                  </div>
                </PopoverContent>
              </Popover>
            </div>

            <TabsContent value="security" className="mt-6">
              <div className="rounded-lg border border-border/30 overflow-hidden">
                <Table>
                  <TableHeader className="bg-card/50">
                    <TableRow className="border-border/30">
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Event Type</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>Risk Score</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSecurityLogs.slice(0, 50).map((log: SecurityLog) => (
                      <TableRow 
                        key={log.id}
                        className="border-border/30 hover:bg-card/30"
                      >
                        <TableCell className="font-mono text-sm">
                          {format(new Date(log.timestamp), 'MMM dd HH:mm:ss')}
                        </TableCell>
                        <TableCell>
                          <Badge className={cn("text-xs", getSeverityColor(log.level))}>
                            {log.level}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.category}
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.event_type}
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.source}
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.user_id || '-'}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            {getResultIcon(log.result)}
                            <span className="text-xs">{log.result}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge 
                            variant={log.risk_score >= 8 ? 'destructive' : 
                                   log.risk_score >= 5 ? 'secondary' : 'outline'}
                            className="text-xs"
                          >
                            {log.risk_score.toFixed(1)}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedLog(log)}
                            className="h-8 w-8 p-0"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                
                {filteredSecurityLogs.length === 0 && (
                  <div className="p-8 text-center text-text-secondary">
                    No security logs found matching your filters
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="audit" className="mt-6">
              <div className="rounded-lg border border-border/30 overflow-hidden">
                <Table>
                  <TableHeader className="bg-card/50">
                    <TableRow className="border-border/30">
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAuditEvents.slice(0, 50).map((event: AuditEvent) => (
                      <TableRow 
                        key={event.id}
                        className="border-border/30 hover:bg-card/30"
                      >
                        <TableCell className="font-mono text-sm">
                          {format(new Date(event.timestamp), 'MMM dd HH:mm:ss')}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {event.category}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm">
                          {event.action}
                        </TableCell>
                        <TableCell className="text-sm font-medium">
                          {event.user_id}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {event.user_ip || '-'}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            {getResultIcon(event.result)}
                            <span className="text-xs">{event.result}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-sm">
                          {event.source}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedLog(event)}
                            className="h-8 w-8 p-0"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                
                {filteredAuditEvents.length === 0 && (
                  <div className="p-8 text-center text-text-secondary">
                    No audit events found matching your filters
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Log Details Modal/Sidebar */}
      {selectedLog && (
        <Card className="glass-effect">
          <CardHeader>
            <div className="flex justify-between items-start">
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-primary" />
                Event Details
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedLog(null)}
              >
                ×
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-text-secondary">ID</label>
                  <p className="font-mono text-sm">{selectedLog.id}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-text-secondary">Timestamp</label>
                  <p className="font-mono text-sm">
                    {format(new Date(selectedLog.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                  </p>
                </div>
                {'level' in selectedLog && (
                  <div>
                    <label className="text-sm font-medium text-text-secondary">Severity</label>
                    <Badge className={cn("text-xs", getSeverityColor(selectedLog.level))}>
                      {selectedLog.level}
                    </Badge>
                  </div>
                )}
                <div>
                  <label className="text-sm font-medium text-text-secondary">Category</label>
                  <p className="text-sm">{selectedLog.category}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-text-secondary">
                    {'event_type' in selectedLog ? 'Event Type' : 'Action'}
                  </label>
                  <p className="text-sm">
                    {'event_type' in selectedLog ? selectedLog.event_type : selectedLog.action}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-text-secondary">Source</label>
                  <p className="text-sm">{selectedLog.source}</p>
                </div>
                {selectedLog.user_id && (
                  <div>
                    <label className="text-sm font-medium text-text-secondary">User ID</label>
                    <p className="text-sm font-medium">{selectedLog.user_id}</p>
                  </div>
                )}
                {selectedLog.user_ip && (
                  <div>
                    <label className="text-sm font-medium text-text-secondary">IP Address</label>
                    <p className="font-mono text-sm">{selectedLog.user_ip}</p>
                  </div>
                )}
                <div>
                  <label className="text-sm font-medium text-text-secondary">Result</label>
                  <div className="flex items-center gap-2">
                    {getResultIcon(selectedLog.result)}
                    <span className="text-sm">{selectedLog.result}</span>
                  </div>
                </div>
                {'risk_score' in selectedLog && (
                  <div>
                    <label className="text-sm font-medium text-text-secondary">Risk Score</label>
                    <Badge 
                      variant={selectedLog.risk_score >= 8 ? 'destructive' : 
                             selectedLog.risk_score >= 5 ? 'secondary' : 'outline'}
                    >
                      {selectedLog.risk_score.toFixed(1)} / 10.0
                    </Badge>
                  </div>
                )}
              </div>
              
              <div>
                <label className="text-sm font-medium text-text-secondary">Description</label>
                <p className="text-sm mt-1 p-3 bg-card/50 rounded border">
                  {selectedLog.description}
                </p>
              </div>
              
              {selectedLog.details && Object.keys(selectedLog.details).length > 0 && (
                <div>
                  <label className="text-sm font-medium text-text-secondary">Additional Details</label>
                  <pre className="text-xs mt-1 p-3 bg-card/50 rounded border overflow-auto">
                    {JSON.stringify(selectedLog.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
