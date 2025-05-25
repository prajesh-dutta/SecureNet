"""
Intrusion Detection System (IDS) for SecureNet Dashboard

This module provides comprehensive intrusion detection capabilities including:
- Real-time packet analysis
- Signature-based detection
- Anomaly-based detection
- Protocol analysis
- Attack pattern recognition
- Behavioral analysis
"""

import asyncio
import json
import logging
import time
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import ipaddress
import re
import hashlib

import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

@dataclass
class DetectionAlert:
    """Represents an IDS detection alert"""
    id: str
    timestamp: datetime
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # MALWARE, EXPLOIT, ANOMALY, POLICY_VIOLATION, etc.
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    description: str
    details: Dict[str, Any]
    confidence: float
    rule_id: Optional[str] = None
    signature: Optional[str] = None

@dataclass
class NetworkBaseline:
    """Network baseline for anomaly detection"""
    avg_packets_per_minute: float
    avg_bytes_per_minute: float
    common_ports: List[int]
    common_protocols: List[str]
    peak_hours: List[int]
    normal_connections: Dict[str, int]

class SignatureEngine:
    """Signature-based detection engine"""
    
    def __init__(self):
        self.signatures = {}
        self.load_default_signatures()
    
    def load_default_signatures(self):
        """Load default IDS signatures"""
        self.signatures = {
            # Network scanning patterns
            'port_scan': {
                'pattern': r'tcp.*flags.*S.*',
                'threshold': 10,
                'window': 60,
                'severity': 'MEDIUM',
                'description': 'Port scan detected'
            },
            
            # Malware communication patterns
            'c2_beaconing': {
                'pattern': r'periodic_dns_queries',
                'threshold': 5,
                'window': 300,
                'severity': 'HIGH',
                'description': 'C2 beaconing detected'
            },
            
            # Exploitation attempts
            'sql_injection': {
                'pattern': r'(union.*select|drop.*table|exec.*xp_)',
                'threshold': 1,
                'window': 1,
                'severity': 'HIGH',
                'description': 'SQL injection attempt'
            },
            
            'xss_attempt': {
                'pattern': r'(<script|javascript:|onerror=|onload=)',
                'threshold': 1,
                'window': 1,
                'severity': 'MEDIUM',
                'description': 'XSS attempt detected'
            },
            
            # DDoS patterns
            'syn_flood': {
                'pattern': r'tcp.*flags.*S.*',
                'threshold': 100,
                'window': 10,
                'severity': 'HIGH',
                'description': 'SYN flood attack detected'
            },
            
            'udp_flood': {
                'pattern': r'udp.*',
                'threshold': 1000,
                'window': 60,
                'severity': 'HIGH',
                'description': 'UDP flood attack detected'
            },
            
            # Data exfiltration
            'large_upload': {
                'pattern': r'http.*post.*',
                'threshold': 1,
                'size_threshold': 10485760,  # 10MB
                'window': 300,
                'severity': 'MEDIUM',
                'description': 'Large data upload detected'
            },
            
            # Lateral movement
            'admin_share_access': {
                'pattern': r'smb.*admin\$|c\$|ipc\$',
                'threshold': 3,
                'window': 300,
                'severity': 'HIGH',
                'description': 'Administrative share access detected'
            }
        }
    
    def check_signature(self, packet_data: Dict[str, Any], signature: Dict[str, Any]) -> bool:
        """Check if packet matches a signature"""
        pattern = signature.get('pattern', '')
        packet_str = json.dumps(packet_data).lower()
        
        if re.search(pattern, packet_str, re.IGNORECASE):
            return True
        
        return False

class AnomalyDetector:
    """Machine learning-based anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline = None
        self.training_data = []
        self.feature_window = deque(maxlen=1000)
    
    def extract_features(self, packet_data: Dict[str, Any]) -> List[float]:
        """Extract features from packet data for ML analysis"""
        features = []
        
        # Packet size
        features.append(packet_data.get('size', 0))
        
        # Protocol (encoded)
        protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3, 'other': 4}
        features.append(protocol_map.get(packet_data.get('protocol', '').lower(), 4))
        
        # Port numbers (normalized)
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        features.extend([src_port / 65535.0, dst_port / 65535.0])
        
        # Flags (TCP)
        flags = packet_data.get('flags', 0)
        features.append(flags)
        
        # Time-based features
        hour = datetime.now().hour
        day_of_week = datetime.now().weekday()
        features.extend([hour / 24.0, day_of_week / 7.0])
        
        # Connection statistics
        conn_count = packet_data.get('connection_count', 0)
        features.append(min(conn_count / 100.0, 1.0))
        
        return features
    
    def train_baseline(self, training_packets: List[Dict[str, Any]]):
        """Train the anomaly detection model with baseline data"""
        if len(training_packets) < 100:
            logging.warning("Insufficient training data for anomaly detection")
            return
        
        features = []
        for packet in training_packets:
            packet_features = self.extract_features(packet)
            features.append(packet_features)
        
        features_array = np.array(features)
        scaled_features = self.scaler.fit_transform(features_array)
        
        self.isolation_forest.fit(scaled_features)
        self.is_trained = True
        
        logging.info(f"Anomaly detector trained with {len(training_packets)} samples")
    
    def detect_anomaly(self, packet_data: Dict[str, Any]) -> Tuple[bool, float]:
        """Detect if packet is anomalous"""
        if not self.is_trained:
            return False, 0.0
        
        features = self.extract_features(packet_data)
        features_array = np.array([features])
        scaled_features = self.scaler.transform(features_array)
        
        # Get anomaly score
        anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
        is_anomaly = self.isolation_forest.predict(scaled_features)[0] == -1
        
        # Convert score to confidence (0-1)
        confidence = abs(anomaly_score)
        
        return is_anomaly, confidence

class NetworkBehaviorAnalyzer:
    """Analyzes network behavior patterns"""
    
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.traffic_timeline = deque(maxlen=3600)  # 1 hour of data
        self.dns_queries = defaultdict(list)
        self.http_requests = defaultdict(list)
    
    def analyze_packet(self, packet_data: Dict[str, Any]) -> List[DetectionAlert]:
        """Analyze packet for behavioral anomalies"""
        alerts = []
        timestamp = datetime.now()
        
        # Track connection patterns
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        protocol = packet_data.get('protocol', '')
        
        # Update statistics
        self.protocol_stats[protocol] += 1
        if packet_data.get('dst_port'):
            self.port_stats[packet_data['dst_port']] += 1
        
        # Track traffic timeline
        self.traffic_timeline.append({
            'timestamp': timestamp,
            'size': packet_data.get('size', 0),
            'protocol': protocol
        })
        
        # Detect port scanning
        if protocol.lower() == 'tcp':
            self.connection_tracker[src_ip].append({
                'dst_ip': dst_ip,
                'dst_port': packet_data.get('dst_port'),
                'timestamp': timestamp
            })
            
            # Check for port scan (multiple ports in short time)
            recent_connections = [
                conn for conn in self.connection_tracker[src_ip]
                if timestamp - conn['timestamp'] < timedelta(minutes=5)
            ]
            
            unique_ports = len(set(conn['dst_port'] for conn in recent_connections if conn['dst_port']))
            
            if unique_ports > 20:  # Threshold for port scan detection
                alerts.append(DetectionAlert(
                    id=hashlib.md5(f"{src_ip}_port_scan_{timestamp}".encode()).hexdigest()[:16],
                    timestamp=timestamp,
                    severity='MEDIUM',
                    category='RECONNAISSANCE',
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=packet_data.get('src_port'),
                    dest_port=packet_data.get('dst_port'),
                    protocol=protocol,
                    description=f'Port scan detected from {src_ip}',
                    details={'unique_ports': unique_ports, 'time_window': '5 minutes'},
                    confidence=min(unique_ports / 50.0, 1.0)
                ))
        
        # Detect DNS tunneling
        if protocol.lower() == 'dns' and packet_data.get('dns_query'):
            query = packet_data['dns_query']
            self.dns_queries[src_ip].append({
                'query': query,
                'timestamp': timestamp,
                'size': len(query)
            })
            
            # Check for suspicious DNS patterns
            recent_queries = [
                q for q in self.dns_queries[src_ip]
                if timestamp - q['timestamp'] < timedelta(minutes=10)
            ]
            
            avg_query_size = sum(q['size'] for q in recent_queries) / len(recent_queries)
            
            if len(recent_queries) > 50 and avg_query_size > 50:
                alerts.append(DetectionAlert(
                    id=hashlib.md5(f"{src_ip}_dns_tunnel_{timestamp}".encode()).hexdigest()[:16],
                    timestamp=timestamp,
                    severity='HIGH',
                    category='EXFILTRATION',
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=packet_data.get('src_port'),
                    dest_port=packet_data.get('dst_port'),
                    protocol=protocol,
                    description=f'Possible DNS tunneling from {src_ip}',
                    details={'query_count': len(recent_queries), 'avg_size': avg_query_size},
                    confidence=0.8
                ))
        
        # Detect traffic volume anomalies
        if len(self.traffic_timeline) > 100:
            recent_traffic = list(self.traffic_timeline)[-60:]  # Last minute
            total_bytes = sum(packet['size'] for packet in recent_traffic)
            
            if total_bytes > 10485760:  # 10MB in 1 minute
                alerts.append(DetectionAlert(
                    id=hashlib.md5(f"traffic_spike_{timestamp}".encode()).hexdigest()[:16],
                    timestamp=timestamp,
                    severity='MEDIUM',
                    category='ANOMALY',
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=packet_data.get('src_port'),
                    dest_port=packet_data.get('dst_port'),
                    protocol=protocol,
                    description='High traffic volume detected',
                    details={'bytes_per_minute': total_bytes},
                    confidence=0.7
                ))
        
        return alerts

class IntrusionDetectionSystem:
    """Main IDS engine coordinating all detection methods"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.behavior_analyzer = NetworkBehaviorAnalyzer()
          # Detection statistics
        self.packet_count = 0
        self.packets_processed = 0
        self.alert_count = 0
        self.detection_stats = defaultdict(int)
        
        # Alert storage
        self.alerts = deque(maxlen=10000)
        self.db_path = self.config.get('ids_db_path', './ids_alerts.db')
        
        # Threading
        self.is_running = False
        self.capture_thread = None
        self.analysis_queue = asyncio.Queue()
        
        # Initialize database
        self.init_database()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize SQLite database for storing alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                category TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                description TEXT,
                details TEXT,
                confidence REAL,
                rule_id TEXT,
                signature TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_stats (
                timestamp TEXT,
                total_packets INTEGER,
                total_alerts INTEGER,
                category_stats TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def packet_callback(self, packet):
        """Callback function for packet capture"""
        try:
            packet_data = self.parse_packet(packet)
            if packet_data:
                asyncio.run_coroutine_threadsafe(
                    self.analysis_queue.put(packet_data),
                    asyncio.get_event_loop()
                )
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse scapy packet into structured data"""
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        packet_data = {
            'timestamp': datetime.now(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': ip_layer.proto,
            'size': len(packet),
            'ttl': ip_layer.ttl
        }
        
        # TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_data.update({
                'protocol': 'tcp',
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': tcp_layer.flags,
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack
            })
            
            # HTTP detection
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                packet_data.update({
                    'http_method': http_layer.Method.decode() if http_layer.Method else None,
                    'http_host': http_layer.Host.decode() if http_layer.Host else None,
                    'http_path': http_layer.Path.decode() if http_layer.Path else None,
                    'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else None
                })
        
        # UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_data.update({
                'protocol': 'udp',
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport
            })
            
            # DNS detection
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # Query
                    packet_data['dns_query'] = dns_layer.qd.qname.decode() if dns_layer.qd else None
                else:  # Response
                    packet_data['dns_response'] = True
        
        # ICMP layer
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_data.update({
                'protocol': 'icmp',
                'icmp_type': icmp_layer.type,
                'icmp_code': icmp_layer.code
            })
        
        return packet_data
      async def analyze_packet(self, packet_data: Dict[str, Any]) -> List[DetectionAlert]:
        """Analyze packet using all detection engines"""
        self.packets_processed += 1
        alerts = []
        
        # Signature-based detection
        for rule_id, signature in self.signature_engine.signatures.items():
            if self.signature_engine.check_signature(packet_data, signature):
                alert = DetectionAlert(
                    id=hashlib.md5(f"{rule_id}_{packet_data['src_ip']}_{datetime.now()}".encode()).hexdigest()[:16],
                    timestamp=packet_data['timestamp'],
                    severity=signature['severity'],
                    category='SIGNATURE_MATCH',
                    source_ip=packet_data['src_ip'],
                    dest_ip=packet_data['dst_ip'],
                    source_port=packet_data.get('src_port'),
                    dest_port=packet_data.get('dst_port'),
                    protocol=packet_data.get('protocol', 'unknown'),
                    description=signature['description'],
                    details={'rule_id': rule_id, 'signature': signature['pattern']},
                    confidence=0.9,
                    rule_id=rule_id,
                    signature=signature['pattern']
                )
                alerts.append(alert)
        
        # Anomaly-based detection
        is_anomaly, confidence = self.anomaly_detector.detect_anomaly(packet_data)
        if is_anomaly and confidence > 0.7:
            alert = DetectionAlert(
                id=hashlib.md5(f"anomaly_{packet_data['src_ip']}_{datetime.now()}".encode()).hexdigest()[:16],
                timestamp=packet_data['timestamp'],
                severity='MEDIUM' if confidence < 0.9 else 'HIGH',
                category='ANOMALY',
                source_ip=packet_data['src_ip'],
                dest_ip=packet_data['dst_ip'],
                source_port=packet_data.get('src_port'),
                dest_port=packet_data.get('dst_port'),
                protocol=packet_data.get('protocol', 'unknown'),
                description='Anomalous network behavior detected',
                details={'anomaly_score': confidence},
                confidence=confidence
            )
            alerts.append(alert)
        
        # Behavioral analysis
        behavior_alerts = self.behavior_analyzer.analyze_packet(packet_data)
        alerts.extend(behavior_alerts)
        
        return alerts
    
    def store_alert(self, alert: DetectionAlert):
        """Store alert in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO ids_alerts
            (id, timestamp, severity, category, source_ip, dest_ip, source_port, dest_port,
             protocol, description, details, confidence, rule_id, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.id,
            alert.timestamp.isoformat(),
            alert.severity,
            alert.category,
            alert.source_ip,
            alert.dest_ip,
            alert.source_port,
            alert.dest_port,
            alert.protocol,
            alert.description,
            json.dumps(alert.details),
            alert.confidence,
            alert.rule_id,
            alert.signature
        ))
        
        conn.commit()
        conn.close()
    
    async def start_monitoring(self, interface: str = None):
        """Start IDS monitoring"""
        self.is_running = True
        self.logger.info("Starting Intrusion Detection System...")
        
        # Start packet analysis loop
        analysis_task = asyncio.create_task(self.analysis_loop())
        
        # Start packet capture in separate thread
        if interface:
            self.capture_thread = threading.Thread(
                target=self.start_packet_capture,
                args=(interface,)
            )
            self.capture_thread.start()
        
        # Wait for analysis task
        await analysis_task
    
    def start_packet_capture(self, interface: str):
        """Start packet capture using scapy"""
        try:
            self.logger.info(f"Starting packet capture on interface: {interface}")
            scapy.sniff(
                iface=interface,
                prn=self.packet_callback,
                stop_filter=lambda x: not self.is_running,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
    
    async def analysis_loop(self):
        """Main analysis loop"""
        while self.is_running:
            try:
                # Get packet from queue with timeout
                packet_data = await asyncio.wait_for(
                    self.analysis_queue.get(),
                    timeout=1.0
                )
                
                self.packet_count += 1
                
                # Analyze packet
                alerts = await self.analyze_packet(packet_data)
                
                # Process alerts
                for alert in alerts:
                    self.alerts.append(alert)
                    self.store_alert(alert)
                    self.alert_count += 1
                    self.detection_stats[alert.category] += 1
                    
                    # Log high severity alerts
                    if alert.severity in ['HIGH', 'CRITICAL']:
                        self.logger.warning(f"IDS Alert: {alert.description} - {alert.source_ip}")
                
                # Update statistics every 1000 packets
                if self.packet_count % 1000 == 0:
                    self.logger.info(f"Processed {self.packet_count} packets, {self.alert_count} alerts")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in analysis loop: {e}")
    
    def stop_monitoring(self):
        """Stop IDS monitoring"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join()
        self.logger.info("IDS monitoring stopped")
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM ids_alerts
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        alerts = []
        
        for row in cursor.fetchall():
            alert_dict = dict(zip(columns, row))
            alert_dict['details'] = json.loads(alert_dict['details']) if alert_dict['details'] else {}
            alerts.append(alert_dict)
        
        conn.close()
        return alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get IDS statistics"""
        return {
            'total_packets': self.packet_count,
            'total_alerts': self.alert_count,
            'alerts_by_category': dict(self.detection_stats),
            'is_running': self.is_running,
            'recent_alerts_count': len(self.alerts)
        }
    
    def add_custom_signature(self, rule_id: str, signature: Dict[str, Any]):
        """Add custom detection signature"""
        self.signature_engine.signatures[rule_id] = signature
        self.logger.info(f"Added custom signature: {rule_id}")
    
    def train_anomaly_detector(self, training_data: List[Dict[str, Any]]):
        """Train anomaly detector with baseline data"""
        self.anomaly_detector.train_baseline(training_data)
        self.logger.info("Anomaly detector training completed")
    
    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge a security alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update alert status to acknowledged
            cursor.execute("""
                UPDATE alerts 
                SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?
                WHERE id = ?
            """, (user_id, datetime.now().isoformat(), alert_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self.logger.info(f"Alert {alert_id} acknowledged by user {user_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive IDS system status"""
        try:
            # Calculate uptime
            uptime = time.time() - self.start_time if self.start_time else 0
            
            # Get alert statistics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count alerts by severity in last 24 hours
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM alerts 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            """)
            alert_stats = dict(cursor.fetchall())
            
            # Count total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            
            # Count acknowledged vs unacknowledged alerts
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM alerts 
                GROUP BY status
            """)
            status_stats = dict(cursor.fetchall())
            
            conn.close()
            
            # System resource usage
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'status': 'active' if self.is_running else 'stopped',
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime))),
                'monitoring_interface': getattr(self, 'interface', 'unknown'),
                'alerts_24h': alert_stats,
                'total_alerts': total_alerts,
                'alert_status_breakdown': status_stats,
                'active_rules': len(self.signature_engine.signatures),
                'packets_processed': getattr(self, 'packets_processed', 0),
                'anomaly_detector_trained': hasattr(self.anomaly_detector, 'model') and self.anomaly_detector.model is not None,
                'system_resources': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available_gb': round(memory.available / (1024**3), 2),
                    'disk_percent': disk.percent,
                    'disk_free_gb': round(disk.free / (1024**3), 2)
                },
                'last_alert': self.alerts[-1].timestamp.isoformat() if self.alerts else None,
                'detection_engines': {
                    'signature_based': True,
                    'anomaly_based': hasattr(self.anomaly_detector, 'model') and self.anomaly_detector.model is not None,
                    'behavioral_analysis': True
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'uptime_seconds': 0
            }
    
    def get_detection_rules(self) -> List[Dict[str, Any]]:
        """Get all current detection rules"""
        try:
            rules = []
            for rule_id, rule_data in self.signature_engine.signatures.items():
                rules.append({
                    'id': rule_id,
                    'name': rule_data.get('description', rule_id),
                    'pattern': rule_data.get('pattern', ''),
                    'severity': rule_data.get('severity', 'MEDIUM'),
                    'threshold': rule_data.get('threshold', 1),
                    'window': rule_data.get('window', 60),
                    'description': rule_data.get('description', ''),
                    'enabled': rule_data.get('enabled', True),
                    'created_at': rule_data.get('created_at', datetime.now().isoformat()),
                    'updated_at': rule_data.get('updated_at', datetime.now().isoformat())
                })
            
            return sorted(rules, key=lambda x: x['name'])
            
        except Exception as e:
            self.logger.error(f"Failed to get detection rules: {e}")
            return []
      def add_detection_rule(self, name: str, pattern: str, action: str, 
                          severity: str = 'MEDIUM', description: str = '', 
                          enabled: bool = True, **kwargs) -> str:
        """Add a new detection rule"""
        try:
            rule_id = str(uuid.uuid4())
            
            rule_data = {
                'pattern': pattern,
                'action': action,
                'severity': severity.upper(),
                'description': description or name,
                'enabled': enabled,
                'threshold': kwargs.get('threshold', 1),
                'window': kwargs.get('window', 60),
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'created_by': kwargs.get('user_id', 'system')
            }
            
            # Add additional rule properties from kwargs
            for key, value in kwargs.items():
                if key not in rule_data:
                    rule_data[key] = value
            
            self.signature_engine.signatures[rule_id] = rule_data
            self.logger.info(f"Added detection rule: {name} (ID: {rule_id})")
            
            return rule_id
            
        except Exception as e:
            self.logger.error(f"Failed to add detection rule {name}: {e}")
            raise
    
    def update_detection_rule(self, rule_id: str, update_data: Dict[str, Any]) -> bool:
        """Update an existing detection rule"""
        try:
            if rule_id not in self.signature_engine.signatures:
                self.logger.warning(f"Detection rule {rule_id} not found")
                return False
            
            # Update rule data
            rule = self.signature_engine.signatures[rule_id]
            
            # Update allowed fields
            allowed_fields = [
                'pattern', 'action', 'severity', 'description', 'enabled', 
                'threshold', 'window', 'name'
            ]
            
            for field in allowed_fields:
                if field in update_data:
                    if field == 'severity':
                        rule[field] = update_data[field].upper()
                    else:
                        rule[field] = update_data[field]
            
            rule['updated_at'] = datetime.now().isoformat()
            
            self.logger.info(f"Updated detection rule: {rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update detection rule {rule_id}: {e}")
            return False
    
    def delete_detection_rule(self, rule_id: str) -> bool:
        """Delete a detection rule"""
        try:
            if rule_id not in self.signature_engine.signatures:
                self.logger.warning(f"Detection rule {rule_id} not found")
                return False
            
            # Don't allow deletion of default rules
            default_rules = [
                'port_scan', 'c2_beaconing', 'sql_injection', 'xss_attempt',
                'syn_flood', 'udp_flood', 'large_upload', 'admin_share_access'
            ]
            
            if rule_id in default_rules:
                self.logger.warning(f"Cannot delete default rule: {rule_id}")
                return False
            
            del self.signature_engine.signatures[rule_id]
            self.logger.info(f"Deleted detection rule: {rule_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete detection rule {rule_id}: {e}")
            return False

# Global IDS instance
ids_instance = None

def get_ids_instance(config=None):
    """Get or create IDS instance"""
    global ids_instance
    if ids_instance is None:
        ids_instance = IntrusionDetectionSystem(config)
    return ids_instance

async def start_ids_monitoring(interface: str = None, config=None):
    """Start IDS monitoring"""
    ids = get_ids_instance(config)
    await ids.start_monitoring(interface)

def stop_ids_monitoring():
    """Stop IDS monitoring"""
    global ids_instance
    if ids_instance:
        ids_instance.stop_monitoring()
