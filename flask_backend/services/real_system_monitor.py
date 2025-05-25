#!/usr/bin/env python3
"""
Real System Monitor Service for SecureNet SOC Platform
Gets actual system metrics from the host machine
"""

import psutil
import socket
import subprocess
import platform
import json
import time
from datetime import datetime
import requests
import os
from typing import Dict, List, Any

class RealSystemMonitor:
    """Real-time system monitoring service"""
    
    def __init__(self):
        self.hostname = socket.gethostname()
        self.platform = platform.system()
        
    def get_real_system_health(self) -> Dict[str, Any]:
        """Get actual system health metrics"""
        try:
            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory Usage
            memory = psutil.virtual_memory()
            memory_total_gb = round(memory.total / (1024**3), 2)
            memory_used_gb = round(memory.used / (1024**3), 2)
            memory_percent = memory.percent
            
            # Disk Usage
            disk = psutil.disk_usage('/')
            disk_total_gb = round(disk.total / (1024**3), 2)
            disk_used_gb = round(disk.used / (1024**3), 2)
            disk_percent = round((disk.used / disk.total) * 100, 1)
            
            # Network Stats
            net_io = psutil.net_io_counters()
            
            # Process Count
            process_count = len(psutil.pids())
            
            # Boot Time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            
            return {
                "timestamp": datetime.now().isoformat(),
                "hostname": self.hostname,
                "platform": self.platform,
                "cpu": {
                    "usage_percent": cpu_percent,
                    "cores": cpu_count,
                    "frequency_mhz": cpu_freq.current if cpu_freq else None,
                    "status": "critical" if cpu_percent > 90 else "warning" if cpu_percent > 70 else "healthy"
                },
                "memory": {
                    "total_gb": memory_total_gb,
                    "used_gb": memory_used_gb,
                    "available_gb": round(memory.available / (1024**3), 2),
                    "usage_percent": memory_percent,
                    "status": "critical" if memory_percent > 90 else "warning" if memory_percent > 70 else "healthy"
                },
                "disk": {
                    "total_gb": disk_total_gb,
                    "used_gb": disk_used_gb,
                    "free_gb": round(disk.free / (1024**3), 2),
                    "usage_percent": disk_percent,
                    "status": "critical" if disk_percent > 90 else "warning" if disk_percent > 70 else "healthy"
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                },
                "processes": {
                    "count": process_count
                },
                "uptime": {
                    "boot_time": boot_time.isoformat(),
                    "uptime_seconds": int(uptime.total_seconds()),
                    "uptime_days": uptime.days,
                    "uptime_hours": uptime.seconds // 3600
                },
                "overall_status": self._calculate_overall_status(cpu_percent, memory_percent, disk_percent)
            }
            
        except Exception as e:
            return {
                "error": f"Failed to get system metrics: {str(e)}",
                "timestamp": datetime.now().isoformat(),
                "status": "error"
            }
    
    def get_real_network_connections(self) -> List[Dict[str, Any]]:
        """Get actual network connections"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    connections.append({
                        "local_address": local_addr,
                        "remote_address": remote_addr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "timestamp": datetime.now().isoformat()
                    })
            
            return connections[:50]  # Limit to 50 most recent
            
        except Exception as e:
            return [{"error": f"Failed to get network connections: {str(e)}"}]
    
    def get_real_running_processes(self) -> List[Dict[str, Any]]:
        """Get actual running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    if pinfo['cpu_percent'] is None:
                        pinfo['cpu_percent'] = 0.0
                    if pinfo['memory_percent'] is None:
                        pinfo['memory_percent'] = 0.0
                        
                    processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "cpu_percent": round(pinfo['cpu_percent'], 2),
                        "memory_percent": round(pinfo['memory_percent'], 2),
                        "status": pinfo['status'],
                        "timestamp": datetime.now().isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage and return top 20
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:20]
            
        except Exception as e:
            return [{"error": f"Failed to get running processes: {str(e)}"}]
    
    def get_real_security_events(self) -> List[Dict[str, Any]]:
        """Get real security-related events from system"""
        try:
            events = []
            
            # Check for suspicious processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    
                    # Flag high CPU/memory usage as potential security event
                    if pinfo['cpu_percent'] and pinfo['cpu_percent'] > 80:
                        events.append({
                            "id": f"proc_{pinfo['pid']}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "High CPU Usage",
                            "level": "WARNING",
                            "source": "System Monitor",
                            "message": f"Process {pinfo['name']} (PID: {pinfo['pid']}) using {pinfo['cpu_percent']:.1f}% CPU",
                            "details": {
                                "process_name": pinfo['name'],
                                "pid": pinfo['pid'],
                                "cpu_percent": pinfo['cpu_percent'],
                                "memory_percent": pinfo['memory_percent']
                            }
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > 85:
                events.append({
                    "id": f"disk_{int(time.time())}",
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "High Disk Usage",
                    "level": "WARNING" if disk_percent < 95 else "CRITICAL",
                    "source": "System Monitor",
                    "message": f"Disk usage at {disk_percent:.1f}%",
                    "details": {
                        "disk_percent": disk_percent,
                        "free_gb": round(disk.free / (1024**3), 2)
                    }
                })
            
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 85:
                events.append({
                    "id": f"memory_{int(time.time())}",
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "High Memory Usage",
                    "level": "WARNING" if memory.percent < 95 else "CRITICAL",
                    "source": "System Monitor",
                    "message": f"Memory usage at {memory.percent:.1f}%",
                    "details": {
                        "memory_percent": memory.percent,
                        "available_gb": round(memory.available / (1024**3), 2)
                    }
                })
            
            return events
            
        except Exception as e:
            return [{"error": f"Failed to get security events: {str(e)}"}]
    
    def get_network_traffic_stats(self) -> Dict[str, Any]:
        """Get real network traffic statistics"""
        try:
            net_io = psutil.net_io_counters()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errors_in": net_io.errin,
                "errors_out": net_io.errout,
                "drops_in": net_io.dropin,
                "drops_out": net_io.dropout,
                "total_traffic_gb": round((net_io.bytes_sent + net_io.bytes_recv) / (1024**3), 2)
            }
            
        except Exception as e:
            return {"error": f"Failed to get network stats: {str(e)}"}
    
    def _calculate_overall_status(self, cpu_percent: float, memory_percent: float, disk_percent: float) -> str:
        """Calculate overall system health status"""
        if any(metric > 90 for metric in [cpu_percent, memory_percent, disk_percent]):
            return "critical"
        elif any(metric > 70 for metric in [cpu_percent, memory_percent, disk_percent]):
            return "warning"
        else:
            return "healthy"


class RealThreatDetector:
    """Real-time threat detection service"""
    
    def __init__(self):
        self.suspicious_processes = [
            'nc.exe', 'netcat', 'nmap', 'masscan', 'hping3',
            'mimikatz', 'psexec', 'wmic', 'powershell.exe'
        ]
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5985, 5986]
    
    def detect_threats(self) -> List[Dict[str, Any]]:
        """Detect real security threats on the system"""
        threats = []
        
        try:
            # Check for suspicious processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.info
                    if any(susp in pinfo['name'].lower() for susp in self.suspicious_processes):
                        threats.append({
                            "id": f"threat_proc_{pinfo['pid']}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Suspicious Process",
                            "level": "HIGH",
                            "source": "Process Monitor",
                            "description": f"Potentially suspicious process detected: {pinfo['name']}",
                            "details": {
                                "process_name": pinfo['name'],
                                "pid": pinfo['pid'],
                                "command_line": ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else "N/A"
                            },
                            "mitigation": f"Investigate process {pinfo['name']} (PID: {pinfo['pid']})"
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Check for suspicious network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in self.suspicious_ports:
                        threats.append({
                            "id": f"threat_net_{conn.raddr.ip}_{conn.raddr.port}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Suspicious Network Connection",
                            "level": "MEDIUM",
                            "source": "Network Monitor",
                            "description": f"Connection to suspicious port {conn.raddr.port}",
                            "details": {
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "local_port": conn.laddr.port if conn.laddr else "N/A",
                                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                            },
                            "mitigation": f"Investigate connection to {conn.raddr.ip}:{conn.raddr.port}"
                        })
            
            return threats
            
        except Exception as e:
            return [{"error": f"Failed to detect threats: {str(e)}"}]


# Singleton instances
system_monitor = RealSystemMonitor()
threat_detector = RealThreatDetector()
