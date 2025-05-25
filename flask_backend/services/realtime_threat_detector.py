import asyncio
import json
import websockets
import threading
import time
import random
import datetime
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from flask import current_app
from models.models import SecurityEvent, ThreatDetection, db
from services.enhanced_threat_intelligence import EnhancedThreatIntelligence, IndicatorType, ThreatLevel

class AlertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class RealTimeAlert:
    """Real-time security alert structure"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    indicator: str
    indicator_type: IndicatorType
    threat_level: ThreatLevel
    confidence: float
    source_ip: Optional[str]
    destination_ip: Optional[str]
    timestamp: datetime.datetime
    tags: List[str]
    raw_data: Dict[str, Any]
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'indicator': self.indicator,
            'indicator_type': self.indicator_type.value,
            'threat_level': self.threat_level.value,
            'confidence': self.confidence,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags,
            'raw_data': self.raw_data
        }

class RealTimeThreatDetector:
    """Real-time threat detection and alerting engine"""
    
    def __init__(self):
        self.is_running = False
        self.websocket_clients = set()
        self.detection_rules = []
        self.alert_queue = asyncio.Queue()
        self.last_network_scan = 0
        self.suspicious_ips = set()
        self.threat_intelligence = None
        
        # Load detection rules
        self._load_detection_rules()
    
    def _load_detection_rules(self):
        """Load threat detection rules"""
        self.detection_rules = [
            {
                'name': 'Multiple Failed Logins',
                'type': 'behavioral',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': AlertSeverity.HIGH,
                'description': 'Multiple failed login attempts detected'
            },
            {
                'name': 'Suspicious Port Scanning',
                'type': 'network',
                'threshold': 10,
                'timeframe': 60,  # 1 minute
                'severity': AlertSeverity.MEDIUM,
                'description': 'Port scanning activity detected'
            },
            {
                'name': 'Data Exfiltration',
                'type': 'network',
                'threshold': 100,  # MB
                'timeframe': 300,  # 5 minutes
                'severity': AlertSeverity.CRITICAL,
                'description': 'Large data transfer to external IP detected'
            },
            {
                'name': 'Malware Communication',
                'type': 'threat_intel',
                'severity': AlertSeverity.CRITICAL,
                'description': 'Communication with known malicious IP detected'
            }
        ]
    
    async def start_monitoring(self):
        """Start the real-time threat monitoring system"""
        if self.is_running:
            return
        
        self.is_running = True
        current_app.logger.info("Starting real-time threat detection engine...")
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self._monitor_network_traffic()),
            asyncio.create_task(self._monitor_authentication_events()),
            asyncio.create_task(self._monitor_threat_intelligence()),
            asyncio.create_task(self._process_alerts()),
            asyncio.create_task(self._websocket_server())
        ]
        
        await asyncio.gather(*tasks)
    
    async def stop_monitoring(self):
        """Stop the threat monitoring system"""
        self.is_running = False
        current_app.logger.info("Stopping real-time threat detection engine...")
    
    async def _monitor_network_traffic(self):
        """Monitor network traffic for suspicious patterns"""
        while self.is_running:
            try:
                # Simulate network traffic monitoring
                # In a real implementation, this would connect to network monitoring tools
                traffic_data = self._generate_network_traffic_data()
                
                for connection in traffic_data:
                    await self._analyze_network_connection(connection)
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                current_app.logger.error(f"Network monitoring error: {str(e)}")
                await asyncio.sleep(10)
    
    async def _monitor_authentication_events(self):
        """Monitor authentication events for suspicious activity"""
        while self.is_running:
            try:
                # Simulate authentication monitoring
                # In a real implementation, this would connect to auth logs
                auth_events = self._generate_auth_events()
                
                for event in auth_events:
                    await self._analyze_auth_event(event)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                current_app.logger.error(f"Authentication monitoring error: {str(e)}")
                await asyncio.sleep(15)
    
    async def _monitor_threat_intelligence(self):
        """Monitor for known threat indicators"""
        while self.is_running:
            try:
                # Check suspicious IPs against threat intelligence
                if self.suspicious_ips:
                    ip_to_check = self.suspicious_ips.pop()
                    await self._check_threat_intelligence(ip_to_check)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                current_app.logger.error(f"Threat intelligence monitoring error: {str(e)}")
                await asyncio.sleep(30)
    
    async def _analyze_network_connection(self, connection: Dict[str, Any]):
        """Analyze a network connection for threats"""
        source_ip = connection.get('source_ip')
        dest_ip = connection.get('dest_ip')
        bytes_transferred = connection.get('bytes', 0)
        ports_accessed = connection.get('ports', [])
        
        # Check for port scanning
        if len(ports_accessed) > 10:
            alert = RealTimeAlert(
                id=f"alert_{int(time.time())}_{random.randint(1000, 9999)}",
                title="Suspicious Port Scanning Detected",
                description=f"Host {source_ip} accessed {len(ports_accessed)} ports on {dest_ip}",
                severity=AlertSeverity.MEDIUM,
                indicator=source_ip,
                indicator_type=IndicatorType.IP,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.8,
                source_ip=source_ip,
                destination_ip=dest_ip,
                timestamp=datetime.datetime.utcnow(),
                tags=['port_scanning', 'reconnaissance'],
                raw_data=connection
            )
            await self.alert_queue.put(alert)
            self.suspicious_ips.add(source_ip)
        
        # Check for data exfiltration
        if bytes_transferred > 100 * 1024 * 1024:  # 100MB
            alert = RealTimeAlert(
                id=f"alert_{int(time.time())}_{random.randint(1000, 9999)}",
                title="Potential Data Exfiltration",
                description=f"Large data transfer ({bytes_transferred // (1024*1024)}MB) from {source_ip} to {dest_ip}",
                severity=AlertSeverity.CRITICAL,
                indicator=dest_ip,
                indicator_type=IndicatorType.IP,
                threat_level=ThreatLevel.HIGH,
                confidence=0.7,
                source_ip=source_ip,
                destination_ip=dest_ip,
                timestamp=datetime.datetime.utcnow(),
                tags=['data_exfiltration', 'data_loss'],
                raw_data=connection
            )
            await self.alert_queue.put(alert)
            self.suspicious_ips.add(dest_ip)
    
    async def _analyze_auth_event(self, event: Dict[str, Any]):
        """Analyze authentication events for threats"""
        if event.get('status') == 'failed':
            source_ip = event.get('source_ip')
            username = event.get('username')
            
            # Count recent failed attempts from this IP
            recent_failures = self._count_recent_failures(source_ip)
            
            if recent_failures >= 5:
                alert = RealTimeAlert(
                    id=f"alert_{int(time.time())}_{random.randint(1000, 9999)}",
                    title="Brute Force Attack Detected",
                    description=f"Multiple failed login attempts ({recent_failures}) from {source_ip} for user {username}",
                    severity=AlertSeverity.HIGH,
                    indicator=source_ip,
                    indicator_type=IndicatorType.IP,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.9,
                    source_ip=source_ip,
                    destination_ip=None,
                    timestamp=datetime.datetime.utcnow(),
                    tags=['brute_force', 'authentication'],
                    raw_data=event
                )
                await self.alert_queue.put(alert)
                self.suspicious_ips.add(source_ip)
    
    async def _check_threat_intelligence(self, ip: str):
        """Check an IP against threat intelligence sources"""
        try:
            if not self.threat_intelligence:
                self.threat_intelligence = EnhancedThreatIntelligence()
                await self.threat_intelligence.__aenter__()
            
            result = await self.threat_intelligence.analyze_indicator(ip, IndicatorType.IP)
            
            if result.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                alert = RealTimeAlert(
                    id=f"alert_{int(time.time())}_{random.randint(1000, 9999)}",
                    title="Known Malicious IP Detected",
                    description=f"Communication detected with known malicious IP {ip}. Sources: {', '.join(result.sources)}",
                    severity=AlertSeverity.CRITICAL if result.threat_level == ThreatLevel.CRITICAL else AlertSeverity.HIGH,
                    indicator=ip,
                    indicator_type=IndicatorType.IP,
                    threat_level=result.threat_level,
                    confidence=result.confidence,
                    source_ip=ip,
                    destination_ip=None,
                    timestamp=datetime.datetime.utcnow(),
                    tags=result.tags + ['threat_intel', 'malicious_ip'],
                    raw_data=result.raw_data
                )
                await self.alert_queue.put(alert)
        
        except Exception as e:
            current_app.logger.error(f"Threat intelligence check error for {ip}: {str(e)}")
    
    async def _process_alerts(self):
        """Process and distribute alerts"""
        while self.is_running:
            try:
                # Get alert from queue (wait up to 1 second)
                alert = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)
                
                # Save alert to database
                await self._save_alert_to_db(alert)
                
                # Send alert to WebSocket clients
                await self._broadcast_alert(alert)
                
                # Log the alert
                current_app.logger.warning(f"SECURITY ALERT: {alert.title} - {alert.description}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                current_app.logger.error(f"Alert processing error: {str(e)}")
    
    async def _save_alert_to_db(self, alert: RealTimeAlert):
        """Save alert to database"""
        try:
            security_event = SecurityEvent(
                event_type=alert.title,
                source=alert.source_ip or 'Unknown',
                destination=alert.destination_ip or 'Unknown',
                description=alert.description,
                severity=alert.severity.value,
                timestamp=alert.timestamp,
                raw_data=alert.raw_data,
                status='active'
            )
            
            db.session.add(security_event)
            db.session.commit()
            
        except Exception as e:
            current_app.logger.error(f"Database save error: {str(e)}")
            db.session.rollback()
    
    async def _broadcast_alert(self, alert: RealTimeAlert):
        """Broadcast alert to all connected WebSocket clients"""
        if self.websocket_clients:
            message = json.dumps({
                'type': 'security_alert',
                'data': alert.to_dict()
            })
            
            # Remove closed connections
            closed_clients = set()
            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    closed_clients.add(client)
            
            self.websocket_clients -= closed_clients
    
    async def _websocket_server(self):
        """WebSocket server for real-time updates"""
        async def handle_client(websocket, path):
            self.websocket_clients.add(websocket)
            current_app.logger.info(f"WebSocket client connected: {websocket.remote_address}")
            
            try:
                # Send initial connection message
                await websocket.send(json.dumps({
                    'type': 'connection_established',
                    'message': 'Connected to SecureNet real-time threat detection'
                }))
                
                # Keep connection alive
                await websocket.wait_closed()
                
            except websockets.exceptions.ConnectionClosed:
                pass
            finally:
                self.websocket_clients.discard(websocket)
                current_app.logger.info(f"WebSocket client disconnected: {websocket.remote_address}")
        
        try:
            start_server = websockets.serve(handle_client, "localhost", 8765)
            await start_server
            current_app.logger.info("WebSocket server started on ws://localhost:8765")
            
            # Keep server running
            while self.is_running:
                await asyncio.sleep(1)
                
        except Exception as e:
            current_app.logger.error(f"WebSocket server error: {str(e)}")
    
    def _generate_network_traffic_data(self) -> List[Dict[str, Any]]:
        """Generate simulated network traffic data"""
        traffic = []
        
        for _ in range(random.randint(1, 5)):
            traffic.append({
                'source_ip': f"192.168.1.{random.randint(10, 254)}",
                'dest_ip': f"10.0.0.{random.randint(1, 254)}" if random.random() > 0.3 else f"{random.randint(1, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'ports': [random.randint(1, 65535) for _ in range(random.randint(1, 20))],
                'bytes': random.randint(1024, 500 * 1024 * 1024),  # 1KB to 500MB
                'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                'timestamp': datetime.datetime.utcnow()
            })
        
        return traffic
    
    def _generate_auth_events(self) -> List[Dict[str, Any]]:
        """Generate simulated authentication events"""
        events = []
        
        for _ in range(random.randint(0, 3)):
            events.append({
                'username': random.choice(['admin', 'user', 'service', 'guest', 'root']),
                'source_ip': f"192.168.1.{random.randint(10, 254)}",
                'status': 'failed' if random.random() > 0.7 else 'success',
                'timestamp': datetime.datetime.utcnow(),
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            })
        
        return events
    
    def _count_recent_failures(self, ip: str) -> int:
        """Count recent authentication failures from an IP"""
        # In a real implementation, this would query actual logs
        return random.randint(1, 10)

# Global threat detector instance
threat_detector = None

def start_threat_detector():
    """Start the threat detector in a background thread"""
    global threat_detector
    
    if threat_detector is None:
        threat_detector = RealTimeThreatDetector()
        
        def run_detector():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(threat_detector.start_monitoring())
        
        thread = threading.Thread(target=run_detector, daemon=True)
        thread.start()
        current_app.logger.info("Real-time threat detector started in background thread")

def get_threat_detector():
    """Get the global threat detector instance"""
    return threat_detector
