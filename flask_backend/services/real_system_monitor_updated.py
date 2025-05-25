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
                'timestamp': datetime.now().isoformat()        })
        
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
