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
import shutil
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
        try:            # CPU Usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            try:
                cpu_freq = psutil.cpu_freq()
                cpu_freq_current = cpu_freq.current if cpu_freq else None
            except (AttributeError, OSError):
                cpu_freq_current = None
            
            # Memory Usage
            memory = psutil.virtual_memory()
            memory_total_gb = round(memory.total / (1024**3), 2)
            memory_used_gb = round(memory.used / (1024**3), 2)
            memory_percent = memory.percent            # Disk Usage (Windows compatible)
            try:
                # Use shutil for disk usage as it's more reliable on Windows
                if self.platform == 'Windows':
                    disk_total, disk_used, disk_free = shutil.disk_usage('C:')
                else:
                    disk_total, disk_used, disk_free = shutil.disk_usage('/')
                disk_total_gb = round(disk_total / (1024**3), 2)
                disk_used_gb = round(disk_used / (1024**3), 2)
                disk_free_gb = round(disk_free / (1024**3), 2)
                disk_percent = round((disk_used / disk_total) * 100, 1)
            except Exception as e:
                print(f"Disk usage error: {e}")
                # Fallback values if disk usage fails
                disk_total_gb = 100.0
                disk_used_gb = 50.0
                disk_free_gb = 50.0
                disk_percent = 50.0
            
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
                "platform": self.platform,                "cpu": {
                    "usage_percent": cpu_percent,
                    "cores": cpu_count,
                    "frequency_mhz": cpu_freq_current,
                    "status": "critical" if cpu_percent > 90 else "warning" if cpu_percent > 70 else "healthy"
                },
                "memory": {
                    "total_gb": memory_total_gb,
                    "used_gb": memory_used_gb,
                    "available_gb": round(memory.available / (1024**3), 2),
                    "usage_percent": memory_percent,
                    "status": "critical" if memory_percent > 90 else "warning" if memory_percent > 70 else "healthy"
                },                "disk": {
                    "total_gb": disk_total_gb,
                    "used_gb": disk_used_gb,
                    "free_gb": disk_free_gb,
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
            return [{"error": f"Failed to get security events: {str(e)}"}]    def get_network_traffic_stats(self) -> Dict[str, Any]:
        """Get detailed network traffic statistics with speed calculations"""
        try:
            # Get network I/O counters
            net_io = psutil.net_io_counters()
            
            # Calculate network speeds if we have previous data
            current_time = time.time()
            current_bytes_sent = net_io.bytes_sent
            current_bytes_recv = net_io.bytes_recv
            
            upload_speed = 0
            download_speed = 0
            
            if hasattr(self, 'last_net_time') and hasattr(self, 'last_bytes_sent') and hasattr(self, 'last_bytes_recv'):
                time_diff = current_time - self.last_net_time
                if time_diff > 0:
                    upload_speed = (current_bytes_sent - self.last_bytes_sent) / time_diff  # bytes per second
                    download_speed = (current_bytes_recv - self.last_bytes_recv) / time_diff  # bytes per second
            
            # Store current values for next calculation
            self.last_net_time = current_time
            self.last_bytes_sent = current_bytes_sent
            self.last_bytes_recv = current_bytes_recv
            
            # Get network interfaces
            interfaces = []
            try:
                for interface_name, interface_addresses in psutil.net_if_addrs().items():
                    interface_stats = psutil.net_if_stats().get(interface_name, None)
                    
                    for addr in interface_addresses:
                        if addr.family == socket.AF_INET:  # IPv4
                            interfaces.append({
                                "name": interface_name,
                                "ip_address": addr.address,
                                "netmask": addr.netmask,
                                "is_up": interface_stats.isup if interface_stats else False,
                                "speed": interface_stats.speed if interface_stats else 0,
                                "mtu": interface_stats.mtu if interface_stats else 0
                            })
            except Exception as e:
                interfaces = [{"error": f"Failed to get interface info: {str(e)}"}]
            
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
                "upload_speed_bps": upload_speed,
                "download_speed_bps": download_speed,
                "upload_speed_mbps": round(upload_speed / (1024 * 1024), 2),
                "download_speed_mbps": round(download_speed / (1024 * 1024), 2),
                "interfaces": interfaces,
                "active_connections": len(psutil.net_connections()),
                "total_traffic_gb": round((net_io.bytes_sent + net_io.bytes_recv) / (1024**3), 2),
                "status": "healthy"
            }
            
        except Exception as e:
            return {
                "error": f"Failed to get network traffic stats: {str(e)}",
                "status": "error"
            }
    
    def _calculate_overall_status(self, cpu_percent: float, memory_percent: float, disk_percent: float) -> str:
        """Calculate overall system health status"""
        if any(metric > 90 for metric in [cpu_percent, memory_percent, disk_percent]):
            return "critical"
        elif any(metric > 70 for metric in [cpu_percent, memory_percent, disk_percent]):
            return "warning"
        else:
            return "healthy"


class RealThreatDetector:
    """Real-time threat detection service with enhanced monitoring capabilities"""
    
    def __init__(self):
        self.suspicious_processes = [
            'nc.exe', 'netcat', 'nmap', 'masscan', 'hping3',
            'mimikatz', 'psexec', 'wmic', 'powershell.exe',
            'meterpreter', 'putty.exe', 'cmd.exe', 'at.exe',
            'telnet.exe', 'ftp.exe', 'reg.exe', 'regedit.exe'
        ]
        self.suspicious_ports = [22, 23, 25, 135, 139, 445, 1433, 3389, 5985, 5986, 4444, 4445, 8080]
        self.high_risk_ports = [21, 23, 445, 3389]  # FTP, Telnet, SMB, RDP
        self.connection_history = {}
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        self.rate_limit_threshold = 100  # connections per minute
        self.known_file_hashes = set()  # For tracking file integrity
      def detect_threats(self) -> List[Dict[str, Any]]:
        """Detect real security threats on the system"""
        threats = []
        
        try:
            # Cleanup old connection history periodically
            self._cleanup_connection_history()
            
            # Check for suspicious processes
            threats.extend(self._detect_process_threats())
            
            # Check for network-based threats
            threats.extend(self._detect_network_threats())
            
            # Check for rate limiting attacks
            threats.extend(self._detect_rate_limiting_threats())
            
            # Check for system anomalies
            threats.extend(self._detect_system_anomalies())
            
            return threats
            
        except Exception as e:
            return [{"error": f"Failed to detect threats: {str(e)}"}]
    
    def _detect_process_threats(self) -> List[Dict[str, Any]]:
        """Detect process-based security threats"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    pinfo = proc.info
                    process_name = pinfo['name'].lower()
                    
                    # Check for suspicious process names
                    if any(susp in process_name for susp in self.suspicious_processes):
                        threats.append({
                            "id": f"threat_proc_{pinfo['pid']}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Suspicious Process",
                            "level": "HIGH",
                            "source": "Process Monitor",
                            "description": f"Potentially malicious process detected: {pinfo['name']}",
                            "details": {
                                "process_name": pinfo['name'],
                                "pid": pinfo['pid'],
                                "command_line": ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else "N/A",
                                "cpu_percent": pinfo['cpu_percent'],
                                "memory_percent": pinfo['memory_percent']
                            },
                            "mitigation": f"Terminate process {pinfo['name']} (PID: {pinfo['pid']}) and investigate"
                        })
                    
                    # Check for suspicious command line arguments
                    cmdline = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ""
                    suspicious_args = ['powershell', '-enc', '-nop', '-w hidden', 'bypass', 'unrestricted']
                    if any(arg in cmdline.lower() for arg in suspicious_args):
                        threats.append({
                            "id": f"threat_cmdline_{pinfo['pid']}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Suspicious Command Line",
                            "level": "HIGH",
                            "source": "Process Monitor",
                            "description": f"Suspicious command line detected in {pinfo['name']}",
                            "details": {
                                "process_name": pinfo['name'],
                                "pid": pinfo['pid'],
                                "command_line": cmdline,
                                "suspicious_flags": [arg for arg in suspicious_args if arg in cmdline.lower()]
                            },
                            "mitigation": f"Investigate command line execution for PID {pinfo['pid']}"
                        })
                    
                    # Check for processes with excessive resource usage
                    if pinfo['cpu_percent'] and pinfo['cpu_percent'] > 95:
                        threats.append({
                            "id": f"threat_cpu_{pinfo['pid']}_{int(time.time())}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "CPU Exhaustion Attack",
                            "level": "MEDIUM",
                            "source": "Resource Monitor",
                            "description": f"Process consuming excessive CPU: {pinfo['name']} ({pinfo['cpu_percent']:.1f}%)",
                            "details": {
                                "process_name": pinfo['name'],
                                "pid": pinfo['pid'],
                                "cpu_percent": pinfo['cpu_percent'],
                                "memory_percent": pinfo['memory_percent']
                            },
                            "mitigation": f"Monitor or limit resources for process {pinfo['name']}"
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            threats.append({"error": f"Process threat detection failed: {str(e)}"})
        
        return threats
    
    def _detect_network_threats(self) -> List[Dict[str, Any]]:
        """Detect network-based security threats"""
        threats = []
        
        try:
            current_time = time.time()
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Track connection frequency for rate limiting detection
                    conn_key = f"{remote_ip}:{remote_port}"
                    if conn_key not in self.connection_history:
                        self.connection_history[conn_key] = []
                    self.connection_history[conn_key].append(current_time)
                    
                    # Check for high-risk ports
                    if remote_port in self.high_risk_ports:
                        threats.append({
                            "id": f"threat_highrisk_{remote_ip}_{remote_port}_{int(current_time)}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "High-Risk Port Connection",
                            "level": "HIGH",
                            "source": "Network Monitor",
                            "description": f"Connection to high-risk port {remote_port} on {remote_ip}",
                            "details": {
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_port": conn.laddr.port if conn.laddr else "N/A",
                                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                                "risk_level": "HIGH"
                            },
                            "mitigation": f"Block or investigate connection to {remote_ip}:{remote_port}"
                        })
                    
                    # Check for suspicious ports
                    elif remote_port in self.suspicious_ports:
                        threats.append({
                            "id": f"threat_suspicious_{remote_ip}_{remote_port}_{int(current_time)}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Suspicious Port Connection",
                            "level": "MEDIUM",
                            "source": "Network Monitor",
                            "description": f"Connection to suspicious port {remote_port}",
                            "details": {
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_port": conn.laddr.port if conn.laddr else "N/A",
                                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                            },
                            "mitigation": f"Monitor connection to {remote_ip}:{remote_port}"
                        })
                    
                    # Check for potential data exfiltration (multiple connections to same IP)
                    ip_connections = [k for k in self.connection_history.keys() if k.startswith(remote_ip)]
                    if len(ip_connections) > 5:
                        threats.append({
                            "id": f"threat_exfil_{remote_ip}_{int(current_time)}",
                            "timestamp": datetime.now().isoformat(),
                            "threat_type": "Potential Data Exfiltration",
                            "level": "HIGH",
                            "source": "Network Monitor",
                            "description": f"Multiple connections detected to {remote_ip} (possible data exfiltration)",
                            "details": {
                                "remote_ip": remote_ip,
                                "connection_count": len(ip_connections),
                                "ports": [k.split(':')[1] for k in ip_connections]
                            },
                            "mitigation": f"Investigate multiple connections to {remote_ip}"
                        })
        
        except Exception as e:
            threats.append({"error": f"Network threat detection failed: {str(e)}"})
        
        return threats
    
    def _detect_rate_limiting_threats(self) -> List[Dict[str, Any]]:
        """Detect rate limiting and brute force attacks"""
        threats = []
        
        try:
            current_time = time.time()
            one_minute_ago = current_time - 60
            
            # Check for rapid connections (potential brute force)
            for conn_key, timestamps in self.connection_history.items():
                recent_connections = [t for t in timestamps if t > one_minute_ago]
                
                if len(recent_connections) > self.rate_limit_threshold:
                    remote_ip = conn_key.split(':')[0]
                    threats.append({
                        "id": f"threat_ratelimit_{remote_ip}_{int(current_time)}",
                        "timestamp": datetime.now().isoformat(),
                        "threat_type": "Rate Limiting Attack",
                        "level": "CRITICAL",
                        "source": "Rate Limiter",
                        "description": f"Potential brute force attack from {remote_ip}",
                        "details": {
                            "remote_ip": remote_ip,
                            "connections_per_minute": len(recent_connections),
                            "threshold": self.rate_limit_threshold,
                            "connection_endpoint": conn_key
                        },
                        "mitigation": f"Block IP {remote_ip} - rate limit exceeded"
                    })
        
        except Exception as e:
            threats.append({"error": f"Rate limiting detection failed: {str(e)}"})
        
        return threats
    
    def _detect_system_anomalies(self) -> List[Dict[str, Any]]:
        """Detect system-level security anomalies"""
        threats = []
        
        try:
            # Check for unusual login times (simplified)
            current_hour = datetime.now().hour
            if current_hour < 6 or current_hour > 22:  # Outside normal business hours
                active_users = len([p for p in psutil.process_iter(['username']) 
                                  if p.info['username'] and p.info['username'] != 'SYSTEM'])
                if active_users > 5:
                    threats.append({
                        "id": f"threat_offhours_{int(time.time())}",
                        "timestamp": datetime.now().isoformat(),
                        "threat_type": "Off-Hours Activity",
                        "level": "MEDIUM",
                        "source": "System Monitor",
                        "description": f"Unusual activity detected during off-hours ({current_hour}:00)",
                        "details": {
                            "current_hour": current_hour,
                            "active_user_sessions": active_users
                        },
                        "mitigation": "Investigate off-hours system activity"
                    })
            
            # Check for excessive failed login attempts (by monitoring auth processes)
            auth_processes = [p for p in psutil.process_iter(['name']) 
                            if 'auth' in p.info['name'].lower() or 'login' in p.info['name'].lower()]
            if len(auth_processes) > 10:
                threats.append({
                    "id": f"threat_auth_{int(time.time())}",
                    "timestamp": datetime.now().isoformat(),
                    "threat_type": "Excessive Authentication Attempts",
                    "level": "HIGH",
                    "source": "Authentication Monitor",
                    "description": f"High number of authentication processes detected ({len(auth_processes)})",
                    "details": {
                        "auth_process_count": len(auth_processes),
                        "process_names": [p.info['name'] for p in auth_processes[:5]]
                    },
                    "mitigation": "Investigate potential brute force authentication attempts"
                })
        
        except Exception as e:
            threats.append({"error": f"System anomaly detection failed: {str(e)}"})
        
        return threats
    
    def _cleanup_connection_history(self):
        """Clean up old connection history to prevent memory bloat"""
        current_time = time.time()
        
        if current_time - self.last_cleanup > self.cleanup_interval:
            # Remove connections older than 1 hour
            one_hour_ago = current_time - 3600
            
            for conn_key in list(self.connection_history.keys()):
                self.connection_history[conn_key] = [
                    t for t in self.connection_history[conn_key] if t > one_hour_ago
                ]
                
                # Remove empty entries
                if not self.connection_history[conn_key]:
                    del self.connection_history[conn_key]
            
            self.last_cleanup = current_time
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get comprehensive threat detection statistics"""
        try:
            current_threats = self.detect_threats()
            
            # Count threats by type and level
            threat_types = {}
            threat_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            
            for threat in current_threats:
                if "error" not in threat:
                    threat_type = threat.get("threat_type", "Unknown")
                    threat_level = threat.get("level", "MEDIUM")
                    
                    threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                    threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
            
            return {
                "timestamp": datetime.now().isoformat(),
                "total_threats": len(current_threats),
                "active_connections": len(self.connection_history),
                "threat_by_type": threat_types,
                "threat_by_level": threat_levels,
                "detection_status": "operational",
                "last_scan": datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                "error": f"Failed to get threat statistics: {str(e)}",
                "detection_status": "error"
            }
    
    def get_geographic_threat_distribution(self) -> Dict[str, Any]:
        """Get geographic distribution of threats based on IP addresses"""
        try:
            threats = self.detect_threats()
            geo_distribution = {}
            threat_ips = set()
            
            # Extract IPs from threat data
            for threat in threats:
                if "error" not in threat and "details" in threat:
                    details = threat["details"]
                    if "remote_ip" in details:
                        threat_ips.add(details["remote_ip"])
            
            # Simulate IP geolocation (in production, use real geolocation service)
            for ip in threat_ips:
                country = self._get_simulated_country_from_ip(ip)
                if country not in geo_distribution:
                    geo_distribution[country] = {
                        "count": 0,
                        "ips": [],
                        "threat_levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                    }
                geo_distribution[country]["count"] += 1
                geo_distribution[country]["ips"].append(ip)
            
            # Add threat level distribution per country
            for threat in threats:
                if "error" not in threat and "details" in threat:
                    details = threat["details"]
                    if "remote_ip" in details:
                        ip = details["remote_ip"]
                        country = self._get_simulated_country_from_ip(ip)
                        threat_level = threat.get("level", "MEDIUM")
                        if country in geo_distribution:
                            geo_distribution[country]["threat_levels"][threat_level] += 1
            
            return {
                "timestamp": datetime.now().isoformat(),
                "total_countries": len(geo_distribution),
                "total_threat_ips": len(threat_ips),
                "geographic_distribution": geo_distribution,
                "top_threat_countries": sorted(
                    geo_distribution.items(),
                    key=lambda x: x[1]["count"],
                    reverse=True
                )[:5]
            }
        
        except Exception as e:
            return {
                "error": f"Failed to get geographic threat distribution: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _get_simulated_country_from_ip(self, ip: str) -> str:
        """Simulate IP geolocation (replace with real geolocation service in production)"""
        # Simple simulation based on IP ranges
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            try:
                first_octet = int(ip_parts[0])
                
                # Simulated country mapping based on first octet
                country_mapping = {
                    range(1, 50): "United States",
                    range(50, 80): "China",
                    range(80, 100): "Russia",
                    range(100, 120): "Germany",
                    range(120, 140): "Brazil",
                    range(140, 160): "India",
                    range(160, 180): "Japan",
                    range(180, 200): "United Kingdom",
                    range(200, 220): "France",
                    range(220, 256): "Other"
                }
                
                for ip_range, country in country_mapping.items():
                    if first_octet in ip_range:
                        return country
                
                return "Unknown"
            except ValueError:
                return "Invalid IP"
        return "Invalid IP"
    
    def get_real_time_threat_feed(self) -> Dict[str, Any]:
        """Get real-time threat intelligence feed"""
        try:
            current_threats = self.detect_threats()
            geo_distribution = self.get_geographic_threat_distribution()
            stats = self.get_threat_statistics()
            
            # Get recent threat trends (simplified)
            threat_trend = self._calculate_threat_trend()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "feed_status": "active",
                "current_threats": current_threats[:10],  # Latest 10 threats
                "threat_statistics": stats,
                "geographic_distribution": geo_distribution,
                "threat_trend": threat_trend,
                "risk_level": self._calculate_overall_risk_level(current_threats),
                "recommendations": self._generate_security_recommendations(current_threats)
            }
        
        except Exception as e:
            return {
                "error": f"Failed to get threat feed: {str(e)}",
                "feed_status": "error",
                "timestamp": datetime.now().isoformat()
            }
    
    def _calculate_threat_trend(self) -> Dict[str, Any]:
        """Calculate threat trends over time"""
        try:
            current_time = time.time()
            one_hour_ago = current_time - 3600
            
            # Count connections in the last hour
            recent_connections = 0
            for timestamps in self.connection_history.values():
                recent_connections += len([t for t in timestamps if t > one_hour_ago])
            
            # Simple trend calculation
            trend_direction = "stable"
            if recent_connections > 100:
                trend_direction = "increasing"
            elif recent_connections < 20:
                trend_direction = "decreasing"
            
            return {
                "period": "1 hour",
                "connection_count": recent_connections,
                "trend_direction": trend_direction,
                "risk_assessment": "high" if recent_connections > 200 else "medium" if recent_connections > 50 else "low"
            }
        
        except Exception as e:
            return {
                "error": f"Failed to calculate threat trend: {str(e)}"
            }
    
    def _calculate_overall_risk_level(self, threats: List[Dict[str, Any]]) -> str:
        """Calculate overall system risk level based on current threats"""
        if not threats:
            return "low"
        
        critical_count = sum(1 for t in threats if t.get("level") == "CRITICAL")
        high_count = sum(1 for t in threats if t.get("level") == "HIGH")
        
        if critical_count > 0:
            return "critical"
        elif high_count > 3:
            return "high"
        elif high_count > 0 or len(threats) > 5:
            return "medium"
        else:
            return "low"
      def _generate_security_recommendations(self, threats: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on current threats"""
        recommendations = []
        
        # Check for common threat patterns
        threat_types = [t.get("threat_type", "") for t in threats if "error" not in t]
        
        # Extract severity levels for prioritization
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for threat in threats:
            level = threat.get("level", "")
            if level in severity_counts:
                severity_counts[level] += 1
        
        # Add recommendations based on threat types
        if "Rate Limiting Attack" in threat_types:
            recommendations.append("Implement IP-based rate limiting and consider using a Web Application Firewall (WAF)")
        
        if "Suspicious Process" in threat_types:
            recommendations.append("Review and update antivirus signatures, enable process monitoring and behavioral analysis")
        
        if "High-Risk Port Connection" in threat_types:
            recommendations.append("Review firewall rules and close unnecessary ports, implement network segmentation")
        
        if "Potential Data Exfiltration" in threat_types:
            recommendations.append("Monitor network traffic patterns, implement Data Loss Prevention (DLP) controls")
        
        if "Off-Hours Activity" in threat_types:
            recommendations.append("Review user access controls and implement time-based access restrictions")
            recommendations.append("Set up alerts for after-hours system access and consider implementing multi-factor authentication")
            recommendations.append("Create an access audit trail and review logs regularly for unauthorized access attempts")
        
        if "System Anomaly" in threat_types:
            recommendations.append("Investigate system resource spikes and consider adjusting monitoring thresholds")
            
        if "Multiple Failed Logins" in threat_types:
            recommendations.append("Implement account lockout policies and strengthen password requirements")
            
        # Recommendations based on threat severity
        if severity_counts["CRITICAL"] > 0:
            recommendations.append("URGENT: Critical threats detected - initiate incident response procedures immediately")
        
        if severity_counts["HIGH"] > 2:
            recommendations.append("Multiple high-severity threats detected - consider isolating affected systems")
        
        # General recommendations based on threat load
        if len(threats) > 15:
            recommendations.append("CRITICAL: System under extreme threat load - consider activating emergency response protocols")
        elif len(threats) > 10:
            recommendations.append("System under high threat load - consider enabling enhanced monitoring mode and notifying security team")
        elif len(threats) > 5:
            recommendations.append("Elevated threat activity detected - increase scanning frequency and review security logs")
        
        # Default recommendation if no others were added
        if not recommendations:
            recommendations.append("Continue monitoring - system security status appears normal")
        
        return recommendations[:5]  # Limit to 5 most critical recommendations
```
