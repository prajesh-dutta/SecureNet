import psutil
import socket
import subprocess
import threading
import time
import json
import datetime
import ipaddress
import nmap
import scapy.all as scapy
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from flask import current_app
from flask_backend.models.models import NetworkTraffic, db

@dataclass
class NetworkDevice:
    """Network device information"""
    ip: str
    mac: str
    hostname: str
    manufacturer: str
    open_ports: List[int]
    os_info: str
    last_seen: datetime.datetime
    status: str  # online, offline, unknown
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'manufacturer': self.manufacturer,
            'open_ports': self.open_ports,
            'os_info': self.os_info,
            'last_seen': self.last_seen.isoformat(),
            'status': self.status
        }

@dataclass
class NetworkFlow:
    """Network traffic flow information"""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    start_time: datetime.datetime
    end_time: datetime.datetime
    status: str  # active, closed, timeout
    
    def to_dict(self):
        return {
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'status': self.status
        }

class AdvancedNetworkMonitor:
    """Advanced network monitoring and analysis service"""
    
    def __init__(self):
        self.is_monitoring = False
        self.devices = {}  # ip -> NetworkDevice
        self.active_flows = {}  # (source_ip, dest_ip, source_port, dest_port) -> NetworkFlow
        self.traffic_history = deque(maxlen=1000)  # Keep last 1000 traffic samples
        self.bandwidth_usage = defaultdict(list)  # ip -> list of (timestamp, bytes)
        self.port_scan_detection = defaultdict(set)  # ip -> set of ports accessed
        self.monitor_thread = None
        self.last_network_scan = 0
        self.network_interfaces = []
        
        # Initialize network interfaces
        self._initialize_interfaces()
    
    def _initialize_interfaces(self):
        """Initialize network interface monitoring"""
        try:
            self.network_interfaces = list(psutil.net_if_addrs().keys())
            current_app.logger.info(f"Monitoring network interfaces: {self.network_interfaces}")
        except Exception as e:
            current_app.logger.error(f"Failed to initialize network interfaces: {str(e)}")
            self.network_interfaces = ['eth0', 'wlan0']  # Default fallback
    
    def start_monitoring(self):
        """Start network monitoring in background thread"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        current_app.logger.info("Advanced network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        current_app.logger.info("Advanced network monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Update network statistics
                self._update_network_stats()
                
                # Scan for new devices (every 5 minutes)
                if time.time() - self.last_network_scan > 300:
                    self._scan_network_devices()
                    self.last_network_scan = time.time()
                
                # Monitor active connections
                self._monitor_connections()
                
                # Detect port scanning
                self._detect_port_scanning()
                
                # Clean up old flows
                self._cleanup_old_flows()
                
                time.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                current_app.logger.error(f"Network monitoring error: {str(e)}")
                time.sleep(30)
    
    def _update_network_stats(self):
        """Update network interface statistics"""
        try:
            net_stats = psutil.net_io_counters(pernic=True)
            current_time = datetime.datetime.utcnow()
            
            for interface, stats in net_stats.items():
                if interface in self.network_interfaces:
                    # Calculate bandwidth usage
                    bytes_total = stats.bytes_sent + stats.bytes_recv
                    
                    # Store in traffic history
                    traffic_sample = {
                        'timestamp': current_time,
                        'interface': interface,
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'errors_in': stats.errin,
                        'errors_out': stats.errout,
                        'drops_in': stats.dropin,
                        'drops_out': stats.dropout
                    }
                    
                    self.traffic_history.append(traffic_sample)
                    
                    # Save to database
                    self._save_traffic_to_db(traffic_sample)
                    
        except Exception as e:
            current_app.logger.error(f"Failed to update network stats: {str(e)}")
    
    def _scan_network_devices(self):
        """Scan network for active devices"""
        try:
            # Get network range
            network_range = self._get_network_range()
            if not network_range:
                return
            
            current_app.logger.info(f"Scanning network range: {network_range}")
            
            # Use nmap for network discovery
            nm = nmap.PortScanner()
            scan_result = nm.scan(hosts=network_range, arguments='-sn')  # Ping scan
            
            for host in scan_result['scan']:
                if scan_result['scan'][host]['status']['state'] == 'up':
                    self._discover_device(host)
                    
        except Exception as e:
            current_app.logger.error(f"Network scan error: {str(e)}")
    
    def _discover_device(self, ip: str):
        """Discover detailed information about a device"""
        try:
            device_info = {
                'ip': ip,
                'mac': self._get_mac_address(ip),
                'hostname': self._get_hostname(ip),
                'manufacturer': 'Unknown',
                'open_ports': self._scan_ports(ip),
                'os_info': self._detect_os(ip),
                'last_seen': datetime.datetime.utcnow(),
                'status': 'online'
            }
            
            device = NetworkDevice(**device_info)
            self.devices[ip] = device
            
            current_app.logger.info(f"Discovered device: {ip} ({device.hostname})")
            
        except Exception as e:
            current_app.logger.error(f"Device discovery error for {ip}: {str(e)}")
    
    def _get_network_range(self) -> Optional[str]:
        """Get the network range to scan"""
        try:
            # Get default gateway
            gateways = psutil.net_if_addrs()
            for interface, addrs in gateways.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        # Create network range (assume /24)
                        network = ipaddress.IPv4Network(f"{addr.address}/24", strict=False)
                        return str(network)
            return None
        except Exception:
            return "192.168.1.0/24"  # Default fallback
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP"""
        try:
            # Use ARP table
            arp_output = subprocess.check_output(['arp', '-n', ip], stderr=subprocess.DEVNULL)
            lines = arp_output.decode().split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for an IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return f"host-{ip.split('.')[-1]}"
    
    def _scan_ports(self, ip: str, top_ports: int = 100) -> List[int]:
        """Scan top ports on a device"""
        try:
            nm = nmap.PortScanner()
            scan_result = nm.scan(ip, arguments=f'--top-ports {top_ports}')
            
            open_ports = []
            if ip in scan_result['scan']:
                tcp_ports = scan_result['scan'][ip].get('tcp', {})
                for port, info in tcp_ports.items():
                    if info['state'] == 'open':
                        open_ports.append(port)
            
            return open_ports
        except:
            return []
    
    def _detect_os(self, ip: str) -> str:
        """Detect operating system of a device"""
        try:
            nm = nmap.PortScanner()
            scan_result = nm.scan(ip, arguments='-O')
            
            if ip in scan_result['scan']:
                osmatches = scan_result['scan'][ip].get('osmatch', [])
                if osmatches:
                    return osmatches[0]['name']
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _monitor_connections(self):
        """Monitor active network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            current_time = datetime.datetime.utcnow()
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
                    flow_key = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port)
                    
                    if flow_key not in self.active_flows:
                        # New connection
                        flow = NetworkFlow(
                            source_ip=conn.laddr.ip,
                            dest_ip=conn.raddr.ip,
                            source_port=conn.laddr.port,
                            dest_port=conn.raddr.port,
                            protocol='TCP',
                            bytes_sent=0,
                            bytes_received=0,
                            packets_sent=0,
                            packets_received=0,
                            start_time=current_time,
                            end_time=current_time,
                            status='active'
                        )
                        self.active_flows[flow_key] = flow
                    else:
                        # Update existing connection
                        self.active_flows[flow_key].end_time = current_time
                        self.active_flows[flow_key].status = 'active'
                        
        except Exception as e:
            current_app.logger.error(f"Connection monitoring error: {str(e)}")
    
    def _detect_port_scanning(self):
        """Detect potential port scanning activity"""
        try:
            current_time = time.time()
            
            for ip, ports in self.port_scan_detection.items():
                # If an IP has accessed more than 20 ports in recent time, flag as scanning
                if len(ports) > 20:
                    current_app.logger.warning(f"Potential port scan detected from {ip}: {len(ports)} ports accessed")
                    
                    # Clear the record to avoid spam
                    self.port_scan_detection[ip].clear()
            
            # Clean old records (older than 5 minutes)
            # This is simplified - in reality, you'd track timestamps per port
            if current_time % 300 < 10:  # Every 5 minutes
                self.port_scan_detection.clear()
                
        except Exception as e:
            current_app.logger.error(f"Port scan detection error: {str(e)}")
    
    def _cleanup_old_flows(self):
        """Clean up old network flows"""
        try:
            current_time = datetime.datetime.utcnow()
            cutoff_time = current_time - datetime.timedelta(minutes=30)
            
            flows_to_remove = []
            for flow_key, flow in self.active_flows.items():
                if flow.end_time < cutoff_time:
                    flows_to_remove.append(flow_key)
            
            for flow_key in flows_to_remove:
                del self.active_flows[flow_key]
                
        except Exception as e:
            current_app.logger.error(f"Flow cleanup error: {str(e)}")
    
    def _save_traffic_to_db(self, traffic_sample: Dict[str, Any]):
        """Save traffic sample to database"""
        try:
            # Calculate total traffic
            total_bytes = traffic_sample['bytes_sent'] + traffic_sample['bytes_recv']
            
            # Create network traffic record
            traffic_record = NetworkTraffic(
                timestamp=traffic_sample['timestamp'],
                inbound_traffic=traffic_sample['bytes_recv'] // (1024 * 1024),  # Convert to MB
                outbound_traffic=traffic_sample['bytes_sent'] // (1024 * 1024),  # Convert to MB
                blocked_traffic=0,  # Would need DPI to determine blocked traffic
                total_connections=len(self.active_flows),
                average_response_time=50 + (len(self.active_flows) * 2)  # Simulated response time
            )
            
            db.session.add(traffic_record)
            db.session.commit()
            
        except Exception as e:
            current_app.logger.error(f"Failed to save traffic to database: {str(e)}")
            db.session.rollback()
    
    def get_network_topology(self) -> Dict[str, Any]:
        """Get current network topology"""
        try:
            nodes = []
            edges = []
            
            # Add discovered devices as nodes
            for ip, device in self.devices.items():
                node = {
                    'id': ip,
                    'label': device.hostname or ip,
                    'type': self._classify_device(device),
                    'status': device.status,
                    'ip': ip,
                    'mac': device.mac,
                    'open_ports': len(device.open_ports),
                    'os': device.os_info
                }
                nodes.append(node)
            
            # Add connections as edges
            for flow_key, flow in self.active_flows.items():
                if flow.status == 'active':
                    edge = {
                        'source': flow.source_ip,
                        'target': flow.dest_ip,
                        'protocol': flow.protocol,
                        'port': flow.dest_port,
                        'bytes': flow.bytes_sent + flow.bytes_received
                    }
                    edges.append(edge)
            
            return {
                'nodes': nodes,
                'edges': edges,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'total_devices': len(nodes),
                'active_connections': len(edges)
            }
            
        except Exception as e:
            current_app.logger.error(f"Failed to get network topology: {str(e)}")
            return {'nodes': [], 'edges': [], 'error': str(e)}
    
    def _classify_device(self, device: NetworkDevice) -> str:
        """Classify device type based on open ports and OS"""
        open_ports = set(device.open_ports)
        os_info = device.os_info.lower()
        
        # Web servers
        if 80 in open_ports or 443 in open_ports:
            return 'web_server'
        
        # Database servers
        if any(port in open_ports for port in [3306, 5432, 1433, 27017]):
            return 'database'
        
        # Network devices
        if 161 in open_ports or 'cisco' in os_info or 'router' in device.hostname.lower():
            return 'network_device'
        
        # Windows systems
        if 135 in open_ports or 445 in open_ports or 'windows' in os_info:
            return 'windows_host'
        
        # Linux systems
        if 22 in open_ports or 'linux' in os_info:
            return 'linux_host'
        
        return 'unknown'
    
    def get_bandwidth_usage(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get bandwidth usage statistics"""
        try:
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
            
            # Filter traffic history
            recent_traffic = [
                sample for sample in self.traffic_history
                if sample['timestamp'] >= cutoff_time
            ]
            
            # Aggregate by hour
            hourly_data = defaultdict(lambda: {'inbound': 0, 'outbound': 0, 'total': 0})
            
            for sample in recent_traffic:
                hour_key = sample['timestamp'].replace(minute=0, second=0, microsecond=0)
                hourly_data[hour_key]['inbound'] += sample['bytes_recv']
                hourly_data[hour_key]['outbound'] += sample['bytes_sent']
                hourly_data[hour_key]['total'] += sample['bytes_recv'] + sample['bytes_sent']
            
            # Convert to list
            result = []
            for timestamp, data in sorted(hourly_data.items()):
                result.append({
                    'timestamp': timestamp.isoformat(),
                    'inbound_mb': data['inbound'] // (1024 * 1024),
                    'outbound_mb': data['outbound'] // (1024 * 1024),
                    'total_mb': data['total'] // (1024 * 1024)
                })
            
            return result
            
        except Exception as e:
            current_app.logger.error(f"Failed to get bandwidth usage: {str(e)}")
            return []
    
    def get_device_list(self) -> List[Dict[str, Any]]:
        """Get list of discovered devices"""
        try:
            devices = []
            for ip, device in self.devices.items():
                devices.append(device.to_dict())
            
            return sorted(devices, key=lambda x: x['last_seen'], reverse=True)
            
        except Exception as e:
            current_app.logger.error(f"Failed to get device list: {str(e)}")
            return []
    
    def scan_device_vulnerabilities(self, ip: str) -> Dict[str, Any]:
        """Scan a specific device for vulnerabilities"""
        try:
            if ip not in self.devices:
                return {'error': f'Device {ip} not found'}
            
            device = self.devices[ip]
            vulnerabilities = []
            
            # Check for common vulnerable services
            for port in device.open_ports:
                vuln_info = self._check_port_vulnerabilities(port, device.os_info)
                if vuln_info:
                    vulnerabilities.extend(vuln_info)
            
            # Security score based on vulnerabilities
            if not vulnerabilities:
                security_score = 95
                risk_level = 'Low'
            elif len(vulnerabilities) <= 2:
                security_score = 75
                risk_level = 'Medium'
            else:
                security_score = 45
                risk_level = 'High'
            
            return {
                'device_ip': ip,
                'device_hostname': device.hostname,
                'scan_timestamp': datetime.datetime.utcnow().isoformat(),
                'vulnerabilities': vulnerabilities,
                'security_score': security_score,
                'risk_level': risk_level,
                'open_ports': device.open_ports,
                'os_info': device.os_info
            }
            
        except Exception as e:
            current_app.logger.error(f"Vulnerability scan error for {ip}: {str(e)}")
            return {'error': str(e)}
    
    def _check_port_vulnerabilities(self, port: int, os_info: str) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities on a specific port"""
        vulnerabilities = []
        
        # Common vulnerable services (simplified)
        vuln_db = {
            21: {'service': 'FTP', 'vulns': ['Anonymous FTP access', 'Weak encryption']},
            23: {'service': 'Telnet', 'vulns': ['Unencrypted communication', 'Weak authentication']},
            80: {'service': 'HTTP', 'vulns': ['Unencrypted web traffic', 'Potential web vulnerabilities']},
            135: {'service': 'RPC', 'vulns': ['RPC vulnerabilities', 'Information disclosure']},
            139: {'service': 'NetBIOS', 'vulns': ['SMB vulnerabilities', 'Null session attacks']},
            445: {'service': 'SMB', 'vulns': ['SMB vulnerabilities', 'EternalBlue susceptibility']},
            1433: {'service': 'SQL Server', 'vulns': ['SQL injection potential', 'Weak authentication']},
            3389: {'service': 'RDP', 'vulns': ['BlueKeep vulnerability', 'Brute force attacks']}
        }
        
        if port in vuln_db:
            service = vuln_db[port]
            for vuln in service['vulns']:
                vulnerabilities.append({
                    'port': port,
                    'service': service['service'],
                    'vulnerability': vuln,
                    'severity': 'Medium',  # Simplified severity
                    'description': f"{vuln} on {service['service']} service (port {port})"
                })
        
        return vulnerabilities

# Global network monitor instance
network_monitor = None

def get_network_monitor() -> AdvancedNetworkMonitor:
    """Get or create the global network monitor instance"""
    global network_monitor
    
    if network_monitor is None:
        network_monitor = AdvancedNetworkMonitor()
        network_monitor.start_monitoring()
    
    return network_monitor

def start_network_monitoring():
    """Start network monitoring service"""
    monitor = get_network_monitor()
    current_app.logger.info("Advanced network monitoring service started")
