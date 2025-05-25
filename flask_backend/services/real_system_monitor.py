import psutil
import socket
import subprocess
import platform
import json
import time
import shutil
import requests
import os
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import re
from typing import Dict, List, Optional, Any


class RealSystemMonitor:
    """Real-time system monitoring for cybersecurity analysis."""
    
    def __init__(self):
        self.monitoring = False
        self.security_events = []
        self.baseline_metrics = {}
        self.alert_thresholds = {
            'cpu_usage': 85.0,
            'memory_usage': 90.0,
            'disk_usage': 95.0,
            'network_connections': 1000,
            'failed_logins': 5
        }
        
    def start_monitoring(self):
        """Start continuous system monitoring."""
        self.monitoring = True
        self._establish_baseline()
        
    def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        
    def _establish_baseline(self):
        """Establish baseline system metrics for anomaly detection."""
        try:
            self.baseline_metrics = {
                'cpu_avg': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                'network_io': psutil.net_io_counters()._asdict(),
                'process_count': len(psutil.pids()),
                'boot_time': psutil.boot_time()
            }
        except Exception as e:
            print(f"Error establishing baseline: {e}")
    
    def get_real_system_health(self):
        """Get real-time system health metrics for the dashboard."""
        try:
            # Get system metrics using the underlying method
            metrics = self.get_system_metrics()
            
            # Get network connections
            connections = self.get_network_connections()
            connection_count = len(connections) if isinstance(connections, list) else 0
            
            # Get boot time and calculate uptime
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            
            # Calculate average CPU usage across all cores
            cpu_percent = metrics.get('cpu', {}).get('percent', 0)
            
            # Get memory usage
            memory_percent = metrics.get('memory', {}).get('percent', 0)
            
            # Get disk usage - average if multiple partitions
            disk_partitions = metrics.get('disk', {})
            if isinstance(disk_partitions, dict) and disk_partitions:
                disk_percentages = [
                    usage.get('percent', 0) 
                    for usage in disk_partitions.values() 
                    if isinstance(usage, dict)
                ]
                disk_usage_percent = sum(disk_percentages) / max(len(disk_percentages), 1)
            else:
                disk_usage_percent = 0
            
            # Get network stats
            network_stats = metrics.get('network', {})
            
            # Format the response for the dashboard
            return {
                'cpu_usage': cpu_percent,
                'memory_usage': memory_percent,
                'disk_usage': disk_usage_percent,
                'network_stats': {
                    'bytes_sent': network_stats.get('bytes_sent', 0),
                    'bytes_recv': network_stats.get('bytes_recv', 0),
                    'packets_sent': network_stats.get('packets_sent', 0),
                    'packets_recv': network_stats.get('packets_recv', 0),
                    'connections': connection_count
                },
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'uptime': uptime_seconds,
                'timestamp': time.time(),
                'overall_status': self._calculate_overall_health(cpu_percent, memory_percent, disk_usage_percent)
            }
        except Exception as e:
            print(f"Error getting real system health: {e}")
            return {
                'error': str(e),
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'network_stats': {
                    'bytes_sent': 0,
                    'bytes_recv': 0,
                    'packets_sent': 0,
                    'packets_recv': 0,
                    'connections': 0
                },
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'uptime': 0,
                'timestamp': time.time(),
                'overall_status': 'error'
            }
    
    def _calculate_overall_health(self, cpu_percent, memory_percent, disk_percent):
        """Calculate overall system health based on resource usage."""
        if cpu_percent > self.alert_thresholds['cpu_usage'] or \
           memory_percent > self.alert_thresholds['memory_usage'] or \
           disk_percent > self.alert_thresholds['disk_usage']:
            return 'critical'
        elif cpu_percent > self.alert_thresholds['cpu_usage'] * 0.8 or \
             memory_percent > self.alert_thresholds['memory_usage'] * 0.8 or \
             disk_percent > self.alert_thresholds['disk_usage'] * 0.8:
            return 'warning'
        else:
            return 'healthy'
            
    def get_system_metrics(self):
        """Get current system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk_usage = {}
            try:
                if platform.system() == "Windows":
                    for partition in psutil.disk_partitions():
                        try:
                            usage = psutil.disk_usage(partition.mountpoint)
                            disk_usage[partition.mountpoint] = {
                                'total': usage.total,
                                'used': usage.used,
                                'free': usage.free,
                                'percent': (usage.used / usage.total) * 100
                            }
                        except PermissionError:
                            continue
                else:
                    usage = psutil.disk_usage('/')
                    disk_usage['/'] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
            except Exception as e:
                disk_usage = {'error': str(e)}
            
            # Network metrics
            network = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())
            
            # Process metrics
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent
                },
                'disk': disk_usage,
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv,
                    'connections': network_connections
                },
                'processes': {
                    'count': len(processes),
                    'top_cpu': sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:5],
                    'top_memory': sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:5]
                }
            }
        except Exception as e:
            return {'error': f'Failed to get system metrics: {str(e)}'}
    
    def get_network_connections(self):
        """Get active network connections."""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status,
                        'pid': conn.pid
                    })
            return connections
        except Exception as e:
            return {'error': f'Failed to get network connections: {str(e)}'}
    
    def get_real_network_connections(self):
        """Alias for get_network_connections for backwards compatibility."""
        return self.get_network_connections()
    
    def detect_anomalies(self, current_metrics):
        """Detect system anomalies based on thresholds and baseline."""
        anomalies = []
        
        try:
            # CPU anomaly detection
            if current_metrics.get('cpu', {}).get('percent', 0) > self.alert_thresholds['cpu_usage']:
                anomalies.append({
                    'type': 'high_cpu_usage',
                    'severity': 'warning',
                    'value': current_metrics['cpu']['percent'],
                    'threshold': self.alert_thresholds['cpu_usage'],
                    'timestamp': datetime.now().isoformat()
                })
            
            # Memory anomaly detection
            if current_metrics.get('memory', {}).get('percent', 0) > self.alert_thresholds['memory_usage']:
                anomalies.append({
                    'type': 'high_memory_usage',
                    'severity': 'warning',
                    'value': current_metrics['memory']['percent'],
                    'threshold': self.alert_thresholds['memory_usage'],
                    'timestamp': datetime.now().isoformat()
                })
            
            # Disk anomaly detection
            disk_data = current_metrics.get('disk', {})
            for mount_point, usage in disk_data.items():
                if isinstance(usage, dict) and usage.get('percent', 0) > self.alert_thresholds['disk_usage']:
                    anomalies.append({
                        'type': 'high_disk_usage',
                        'severity': 'critical',
                        'value': usage['percent'],
                        'threshold': self.alert_thresholds['disk_usage'],
                        'mount_point': mount_point,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Network anomaly detection
            if current_metrics.get('network', {}).get('connections', 0) > self.alert_thresholds['network_connections']:
                anomalies.append({
                    'type': 'high_network_connections',
                    'severity': 'warning',
                    'value': current_metrics['network']['connections'],
                    'threshold': self.alert_thresholds['network_connections'],
                    'timestamp': datetime.now().isoformat()
                })
            
        except Exception as e:
            anomalies.append({
                'type': 'anomaly_detection_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
        
        return anomalies
    
    def log_security_event(self, event_type, description, severity='info'):
        """Log a security event."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'description': description,
            'severity': severity,
            'system_state': self.get_system_metrics()
        }
        self.security_events.append(event)
        
        # Keep only last 1000 events to manage memory
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
        
        return event
    
    def get_security_events(self, limit=100):
        """Get recent security events."""
        return self.security_events[-limit:] if self.security_events else []


class RealThreatDetector:
    """Real-time threat detection system."""
    
    def __init__(self):
        self.system_monitor = RealSystemMonitor()
        self.threat_patterns = self._load_threat_patterns()
        self.rate_limiters = defaultdict(lambda: deque(maxlen=100))
        self.suspicious_processes = set()
        self.known_malware_hashes = set()
        self.network_anomalies = defaultdict(int)
        
    def _load_threat_patterns(self):
        """Load threat detection patterns."""
        return {
            'suspicious_processes': [
                'nc.exe', 'netcat', 'ncat', 'socat', 'telnet',
                'powershell.exe -enc', 'cmd.exe /c', 'wscript.exe',
                'cscript.exe', 'mshta.exe', 'rundll32.exe'
            ],
            'suspicious_network_ports': [
                1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999,
                12345, 54321, 65534
            ],
            'suspicious_file_extensions': [
                '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
                '.vbs', '.js', '.jar', '.ps1'
            ],
            'malicious_domains': [
                'malware.com', 'badsite.org', 'phishing.net'
            ]
        }
    
    def detect_process_anomalies(self):
        """Detect suspicious processes."""
        threats = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '').lower()
                    cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
                    
                    # Check for suspicious process names
                    for suspicious in self.threat_patterns['suspicious_processes']:
                        if suspicious.lower() in proc_name or suspicious.lower() in cmdline:
                            threat = {
                                'type': 'suspicious_process',
                                'severity': 'high',
                                'process_name': proc_info.get('name'),
                                'pid': proc_info.get('pid'),
                                'cmdline': cmdline,
                                'cpu_percent': proc_info.get('cpu_percent', 0),
                                'memory_percent': proc_info.get('memory_percent', 0),
                                'timestamp': datetime.now().isoformat()
                            }
                            threats.append(threat)
                            self.suspicious_processes.add(proc_info.get('pid'))
                            break
                    
                    # Check for high resource usage (potential cryptominer)
                    if (proc_info.get('cpu_percent', 0) > 80 and 
                        proc_info.get('memory_percent', 0) > 50):
                        threats.append({
                            'type': 'high_resource_usage',
                            'severity': 'medium',
                            'process_name': proc_info.get('name'),
                            'pid': proc_info.get('pid'),
                            'cpu_percent': proc_info.get('cpu_percent', 0),
                            'memory_percent': proc_info.get('memory_percent', 0),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            threats.append({
                'type': 'process_detection_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
        return threats
    
    def detect_network_anomalies(self):
        """Detect network-based threats."""
        threats = []
        try:
            connections = self.system_monitor.get_network_connections()
            
            if isinstance(connections, dict) and 'error' in connections:
                return [connections]
            
            for conn in connections:
                try:
                    remote_addr = conn.get('remote_address', '')
                    if ':' in remote_addr:
                        remote_ip, remote_port = remote_addr.split(':')
                        remote_port = int(remote_port)
                        
                        # Check for suspicious ports
                        if remote_port in self.threat_patterns['suspicious_network_ports']:
                            threats.append({
                                'type': 'suspicious_port_connection',
                                'severity': 'high',
                                'remote_address': remote_addr,
                                'local_address': conn.get('local_address', ''),
                                'port': remote_port,
                                'pid': conn.get('pid'),
                                'timestamp': datetime.now().isoformat()
                            })
                        
                        # Track connection frequency for rate limiting detection
                        self.rate_limiters[remote_ip].append(datetime.now())
                        
                        # Check for potential DDoS or brute force
                        recent_connections = [
                            ts for ts in self.rate_limiters[remote_ip] 
                            if datetime.now() - ts < timedelta(minutes=1)
                        ]
                        
                        if len(recent_connections) > 50:  # More than 50 connections per minute
                            threats.append({
                                'type': 'potential_ddos_bruteforce',
                                'severity': 'critical',
                                'remote_ip': remote_ip,
                                'connection_count': len(recent_connections),
                                'timestamp': datetime.now().isoformat()
                            })
                            
                except (ValueError, AttributeError):
                    continue
                    
        except Exception as e:
            threats.append({
                'type': 'network_detection_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
        return threats
    
    def detect_file_system_anomalies(self):
        """Detect file system-based threats."""
        threats = []
        try:
            # Check for suspicious file modifications in system directories
            system_dirs = [
                os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files')),
                '/bin', '/sbin', '/usr/bin', '/usr/sbin'  # Linux system directories
            ]
            
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    try:
                        # Check for recently modified files (last 10 minutes)
                        current_time = time.time()
                        for root, dirs, files in os.walk(sys_dir):
                            for file in files[:10]:  # Limit to prevent performance issues
                                file_path = os.path.join(root, file)
                                try:
                                    mod_time = os.path.getmtime(file_path)
                                    if current_time - mod_time < 600:  # 10 minutes
                                        threats.append({
                                            'type': 'system_file_modification',
                                            'severity': 'high',
                                            'file_path': file_path,
                                            'modification_time': datetime.fromtimestamp(mod_time).isoformat(),
                                            'timestamp': datetime.now().isoformat()
                                        })
                                except (OSError, PermissionError):
                                    continue
                            break  # Only check immediate directory to avoid deep recursion
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            threats.append({
                'type': 'filesystem_detection_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
        return threats
    
    def detect_system_anomalies(self):
        """Detect system-level anomalies."""
        threats = []
        try:
            metrics = self.system_monitor.get_system_metrics()
            
            if isinstance(metrics, dict) and 'error' in metrics:
                return [metrics]
            
            # Check for unusual boot time (system restart)
            boot_time = psutil.boot_time()
            if hasattr(self, 'last_boot_time'):
                if boot_time != self.last_boot_time:
                    threats.append({
                        'type': 'system_restart_detected',
                        'severity': 'medium',
                        'boot_time': datetime.fromtimestamp(boot_time).isoformat(),
                        'timestamp': datetime.now().isoformat()
                    })
            self.last_boot_time = boot_time
            
            # Check for unusual process count
            process_count = metrics.get('processes', {}).get('count', 0)
            if process_count > 500:  # Threshold for suspicious process count
                threats.append({
                    'type': 'high_process_count',
                    'severity': 'medium',
                    'process_count': process_count,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Check for memory usage patterns
            memory_percent = metrics.get('memory', {}).get('percent', 0)
            if memory_percent > 95:
                threats.append({
                    'type': 'critical_memory_usage',
                    'severity': 'high',
                    'memory_percent': memory_percent,
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            threats.append({
                'type': 'system_anomaly_detection_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
            
        return threats
    
    def run_comprehensive_scan(self):
        """Run a comprehensive threat detection scan."""
        all_threats = []
        
        # Start system monitoring if not already started
        if not self.system_monitor.monitoring:
            self.system_monitor.start_monitoring()
        
        try:
            # Run all detection methods
            process_threats = self.detect_process_anomalies()
            network_threats = self.detect_network_anomalies()
            filesystem_threats = self.detect_file_system_anomalies()
            system_threats = self.detect_system_anomalies()
            
            # Combine all threats
            all_threats.extend(process_threats)
            all_threats.extend(network_threats)
            all_threats.extend(filesystem_threats)
            all_threats.extend(system_threats)
            
            # Log security events for detected threats
            for threat in all_threats:
                if threat.get('severity') in ['high', 'critical']:
                    self.system_monitor.log_security_event(
                        threat.get('type', 'unknown_threat'),
                        f"Threat detected: {threat}",
                        threat.get('severity', 'info')
                    )
            
        except Exception as e:
            all_threats.append({
                'type': 'comprehensive_scan_error',
                'severity': 'error',
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
        
        return {
            'scan_timestamp': datetime.now().isoformat(),
            'total_threats': len(all_threats),
            'threats': all_threats,
            'system_metrics': self.system_monitor.get_system_metrics()
        }
    
    def get_threat_summary(self):
        """Get a summary of current threat status."""
        try:
            scan_results = self.run_comprehensive_scan()
            threats = scan_results.get('threats', [])
            
            # Categorize threats by severity
            severity_counts = defaultdict(int)
            threat_types = defaultdict(int)
            
            for threat in threats:
                severity = threat.get('severity', 'unknown')
                threat_type = threat.get('type', 'unknown')
                severity_counts[severity] += 1
                threat_types[threat_type] += 1
            
            return {
                'timestamp': datetime.now().isoformat(),
                'total_threats': len(threats),
                'severity_breakdown': dict(severity_counts),
                'threat_type_breakdown': dict(threat_types),
                'system_status': 'critical' if severity_counts['critical'] > 0 
                               else 'warning' if severity_counts['high'] > 0 
                               else 'normal',
                'recent_threats': threats[-10:] if threats else []
            }
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': f'Failed to generate threat summary: {str(e)}',
                'system_status': 'error'
            }
