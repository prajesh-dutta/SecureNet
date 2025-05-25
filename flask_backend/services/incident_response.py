"""
Automated Incident Response System for SecureNet Dashboard

This module provides comprehensive incident response capabilities including:
- Automated incident classification and prioritization
- Response workflow orchestration
- Threat containment and mitigation
- Evidence collection and forensics
- Notification and escalation management
- Integration with threat intelligence and IDS
"""

import asyncio
import json
import logging
import time
import sqlite3
import smtplib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import subprocess
import os
import hashlib

import requests
import psutil
from twilio.rest import Client as TwilioClient

@dataclass
class SecurityIncident:
    """Represents a security incident"""
    id: str
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # MALWARE, INTRUSION, DATA_BREACH, DDOS, etc.
    status: str    # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    created_at: datetime
    updated_at: datetime
    source: str    # IDS, THREAT_INTEL, VULN_SCAN, USER_REPORT, etc.
    affected_assets: List[str]
    indicators: Dict[str, Any]  # IOCs, signatures, etc.
    response_actions: List[Dict[str, Any]]
    assigned_to: Optional[str] = None
    escalated: bool = False
    evidence_collected: List[str] = None
    timeline: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.evidence_collected is None:
            self.evidence_collected = []
        if self.timeline is None:
            self.timeline = []

@dataclass
class ResponseAction:
    """Represents an automated response action"""
    id: str
    name: str
    description: str
    action_type: str  # ISOLATE, BLOCK, ALERT, COLLECT, ANALYZE, etc.
    parameters: Dict[str, Any]
    prerequisites: List[str]
    estimated_duration: int  # seconds
    priority: int  # 1-10, higher is more urgent
    automated: bool
    reversible: bool

@dataclass
class ResponsePlaybook:
    """Represents an incident response playbook"""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]
    actions: List[ResponseAction]
    escalation_rules: Dict[str, Any]
    approval_required: bool

class NotificationManager:
    """Manages incident notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.smtp_server = config.get('SMTP_SERVER')
        self.smtp_port = config.get('SMTP_PORT', 587)
        self.smtp_username = config.get('SMTP_USERNAME')
        self.smtp_password = config.get('SMTP_PASSWORD')
        self.smtp_use_tls = config.get('SMTP_USE_TLS', True)
        
        # Twilio for SMS
        self.twilio_sid = config.get('TWILIO_ACCOUNT_SID')
        self.twilio_token = config.get('TWILIO_AUTH_TOKEN')
        self.twilio_phone = config.get('TWILIO_PHONE_NUMBER')
        self.alert_phones = config.get('ALERT_PHONE_NUMBERS', [])
        
        # Slack
        self.slack_webhook = config.get('SLACK_WEBHOOK_URL')
        self.slack_channel = config.get('SLACK_CHANNEL', '#security-alerts')
        
        self.logger = logging.getLogger(__name__)
    
    async def send_email_alert(self, incident: SecurityIncident, recipients: List[str]):
        """Send email notification for incident"""
        if not self.smtp_server or not recipients:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[SecureNet Alert] {incident.severity} - {incident.title}"
            
            body = f"""
Security Incident Alert

Incident ID: {incident.id}
Severity: {incident.severity}
Category: {incident.category}
Status: {incident.status}
Created: {incident.created_at}

Description:
{incident.description}

Affected Assets:
{', '.join(incident.affected_assets)}

This is an automated alert from SecureNet Security Operations Center.
Please review and respond according to your incident response procedures.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.smtp_use_tls:
                server.starttls()
            
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for incident {incident.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    async def send_sms_alert(self, incident: SecurityIncident):
        """Send SMS notification for critical incidents"""
        if not self.twilio_sid or not self.alert_phones:
            return
        
        if incident.severity not in ['HIGH', 'CRITICAL']:
            return
        
        try:
            client = TwilioClient(self.twilio_sid, self.twilio_token)
            
            message_body = f"SECURITY ALERT: {incident.severity} incident detected. ID: {incident.id}. {incident.title[:50]}... Check SecureNet dashboard."
            
            for phone in self.alert_phones:
                if phone.strip():
                    client.messages.create(
                        body=message_body,
                        from_=self.twilio_phone,
                        to=phone.strip()
                    )
            
            self.logger.info(f"SMS alerts sent for incident {incident.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send SMS alert: {e}")
    
    async def send_slack_alert(self, incident: SecurityIncident):
        """Send Slack notification"""
        if not self.slack_webhook:
            return
        
        try:
            severity_colors = {
                'LOW': '#36a64f',      # Green
                'MEDIUM': '#ff9900',   # Orange
                'HIGH': '#ff4444',     # Red
                'CRITICAL': '#8b0000'  # Dark Red
            }
            
            payload = {
                "channel": self.slack_channel,
                "username": "SecureNet Alert Bot",
                "icon_emoji": ":warning:",
                "attachments": [{
                    "color": severity_colors.get(incident.severity, '#ff9900'),
                    "title": f"{incident.severity} Security Incident",
                    "title_link": f"http://localhost:3000/incidents/{incident.id}",
                    "text": incident.description,
                    "fields": [
                        {
                            "title": "Incident ID",
                            "value": incident.id,
                            "short": True
                        },
                        {
                            "title": "Category",
                            "value": incident.category,
                            "short": True
                        },
                        {
                            "title": "Status",
                            "value": incident.status,
                            "short": True
                        },
                        {
                            "title": "Affected Assets",
                            "value": ", ".join(incident.affected_assets[:5]),
                            "short": True
                        }
                    ],
                    "ts": int(incident.created_at.timestamp())
                }]
            }
            
            response = requests.post(self.slack_webhook, json=payload)
            response.raise_for_status()
            
            self.logger.info(f"Slack alert sent for incident {incident.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")

class EvidenceCollector:
    """Collects and manages digital evidence"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.evidence_path = config.get('EVIDENCE_PATH', './evidence')
        self.logger = logging.getLogger(__name__)
        
        # Ensure evidence directory exists
        os.makedirs(self.evidence_path, exist_ok=True)
    
    async def collect_network_evidence(self, incident: SecurityIncident) -> List[str]:
        """Collect network-related evidence"""
        evidence_files = []
        incident_dir = os.path.join(self.evidence_path, incident.id)
        os.makedirs(incident_dir, exist_ok=True)
        
        try:
            # Collect network connections
            connections_file = os.path.join(incident_dir, 'network_connections.json')
            connections = []
            
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            with open(connections_file, 'w') as f:
                json.dump(connections, f, indent=2)
            evidence_files.append(connections_file)
            
            # Collect system information
            system_file = os.path.join(incident_dir, 'system_info.json')
            system_info = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': {disk.mountpoint: psutil.disk_usage(disk.mountpoint).percent 
                              for disk in psutil.disk_partitions()},
                'boot_time': psutil.boot_time(),
                'users': [user.name for user in psutil.users()]
            }
            
            with open(system_file, 'w') as f:
                json.dump(system_info, f, indent=2)
            evidence_files.append(system_file)
            
            # Collect process information
            processes_file = os.path.join(incident_dir, 'processes.json')
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time', 'cmdline']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            with open(processes_file, 'w') as f:
                json.dump(processes, f, indent=2)
            evidence_files.append(processes_file)
            
            self.logger.info(f"Network evidence collected for incident {incident.id}")
            
        except Exception as e:
            self.logger.error(f"Failed to collect network evidence: {e}")
        
        return evidence_files
    
    async def collect_log_evidence(self, incident: SecurityIncident, log_paths: List[str]) -> List[str]:
        """Collect relevant log files"""
        evidence_files = []
        incident_dir = os.path.join(self.evidence_path, incident.id)
        os.makedirs(incident_dir, exist_ok=True)
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                try:
                    evidence_file = os.path.join(incident_dir, f"logs_{os.path.basename(log_path)}")
                    
                    # Copy last 1000 lines of log
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as src:
                        lines = src.readlines()
                        
                    with open(evidence_file, 'w') as dst:
                        dst.writelines(lines[-1000:])
                    
                    evidence_files.append(evidence_file)
                    
                except Exception as e:
                    self.logger.error(f"Failed to collect log evidence from {log_path}: {e}")
        
        return evidence_files
    
    def create_evidence_hash(self, file_path: str) -> str:
        """Create hash of evidence file for integrity"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to create hash for {file_path}: {e}")
            return ""

class ThreatContainment:
    """Handles threat containment and mitigation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def block_ip_address(self, ip_address: str, duration: int = 3600) -> bool:
        """Block IP address using firewall rules"""
        try:
            # Add iptables rule (Linux)
            if os.name == 'posix':
                cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Blocked IP address: {ip_address}")
                    
                    # Schedule rule removal
                    asyncio.create_task(self.schedule_unblock_ip(ip_address, duration))
                    return True
                else:
                    self.logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
            
            # Windows firewall
            elif os.name == 'nt':
                cmd = f'netsh advfirewall firewall add rule name="SecureNet Block {ip_address}" dir=in action=block remoteip={ip_address}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Blocked IP address: {ip_address}")
                    asyncio.create_task(self.schedule_unblock_ip(ip_address, duration))
                    return True
                else:
                    self.logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    async def schedule_unblock_ip(self, ip_address: str, duration: int):
        """Schedule automatic unblocking of IP address"""
        await asyncio.sleep(duration)
        await self.unblock_ip_address(ip_address)
    
    async def unblock_ip_address(self, ip_address: str) -> bool:
        """Remove IP address block"""
        try:
            if os.name == 'posix':
                cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Unblocked IP address: {ip_address}")
                    return True
            
            elif os.name == 'nt':
                cmd = f'netsh advfirewall firewall delete rule name="SecureNet Block {ip_address}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Unblocked IP address: {ip_address}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    async def isolate_host(self, host_ip: str) -> bool:
        """Isolate compromised host from network"""
        try:
            # Block all traffic to/from host
            if os.name == 'posix':
                commands = [
                    f"sudo iptables -A INPUT -s {host_ip} -j DROP",
                    f"sudo iptables -A OUTPUT -d {host_ip} -j DROP"
                ]
                
                for cmd in commands:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.logger.error(f"Failed to isolate host {host_ip}: {result.stderr}")
                        return False
                
                self.logger.info(f"Isolated host: {host_ip}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error isolating host {host_ip}: {e}")
            return False
    
    async def kill_suspicious_process(self, pid: int) -> bool:
        """Terminate suspicious process"""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for termination
            await asyncio.sleep(2)
            
            if process.is_running():
                process.kill()  # Force kill if terminate didn't work
            
            self.logger.info(f"Terminated suspicious process: {pid}")
            return True
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
            return True
        except Exception as e:
            self.logger.error(f"Error terminating process {pid}: {e}")
            return False

class IncidentResponseOrchestrator:
    """Main incident response orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.notification_manager = NotificationManager(config)
        self.evidence_collector = EvidenceCollector(config)
        self.threat_containment = ThreatContainment(config)
        
        # Database
        self.db_path = config.get('incident_db_path', './incidents.db')
        self.init_database()
        
        # Playbooks
        self.playbooks = {}
        self.load_default_playbooks()
        
        # Active incidents
        self.active_incidents = {}
        self.incident_queue = asyncio.Queue()
        
        # Response statistics
        self.response_stats = defaultdict(int)
        
        # Worker threads
        self.is_running = False
        self.worker_tasks = []
        
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize incident database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                severity TEXT,
                category TEXT,
                status TEXT,
                created_at TEXT,
                updated_at TEXT,
                source TEXT,
                affected_assets TEXT,
                indicators TEXT,
                response_actions TEXT,
                assigned_to TEXT,
                escalated INTEGER,
                evidence_collected TEXT,
                timeline TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                action_type TEXT,
                description TEXT,
                executed_at TEXT,
                status TEXT,
                result TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_default_playbooks(self):
        """Load default incident response playbooks"""
        
        # Malware incident playbook
        malware_playbook = ResponsePlaybook(
            id="malware_response",
            name="Malware Incident Response",
            description="Automated response for malware detection",
            trigger_conditions={"category": "MALWARE", "severity": ["HIGH", "CRITICAL"]},
            actions=[
                ResponseAction(
                    id="isolate_host",
                    name="Isolate Infected Host",
                    description="Isolate the infected host from network",
                    action_type="ISOLATE",
                    parameters={"method": "firewall"},
                    prerequisites=[],
                    estimated_duration=30,
                    priority=9,
                    automated=True,
                    reversible=True
                ),
                ResponseAction(
                    id="collect_evidence",
                    name="Collect Digital Evidence",
                    description="Collect system and network evidence",
                    action_type="COLLECT",
                    parameters={"types": ["network", "system", "logs"]},
                    prerequisites=[],
                    estimated_duration=300,
                    priority=7,
                    automated=True,
                    reversible=False
                ),
                ResponseAction(
                    id="notify_team",
                    name="Notify Security Team",
                    description="Send notifications to security team",
                    action_type="ALERT",
                    parameters={"channels": ["email", "slack", "sms"]},
                    prerequisites=[],
                    estimated_duration=10,
                    priority=8,
                    automated=True,
                    reversible=False
                )
            ],
            escalation_rules={"time_threshold": 1800, "severity_threshold": "CRITICAL"},
            approval_required=False
        )
        
        # Intrusion detection playbook
        intrusion_playbook = ResponsePlaybook(
            id="intrusion_response",
            name="Intrusion Detection Response",
            description="Automated response for intrusion attempts",
            trigger_conditions={"category": "INTRUSION", "source": "IDS"},
            actions=[
                ResponseAction(
                    id="block_source_ip",
                    name="Block Source IP",
                    description="Block the attacking IP address",
                    action_type="BLOCK",
                    parameters={"duration": 3600},
                    prerequisites=[],
                    estimated_duration=10,
                    priority=8,
                    automated=True,
                    reversible=True
                ),
                ResponseAction(
                    id="enhance_monitoring",
                    name="Enhance Monitoring",
                    description="Increase monitoring on affected assets",
                    action_type="MONITOR",
                    parameters={"duration": 7200},
                    prerequisites=[],
                    estimated_duration=60,
                    priority=6,
                    automated=True,
                    reversible=True
                )
            ],
            escalation_rules={"repeated_attempts": 3},
            approval_required=False
        )
        
        # DDoS response playbook
        ddos_playbook = ResponsePlaybook(
            id="ddos_response",
            name="DDoS Attack Response",
            description="Automated response for DDoS attacks",
            trigger_conditions={"category": "DDOS"},
            actions=[
                ResponseAction(
                    id="enable_rate_limiting",
                    name="Enable Rate Limiting",
                    description="Enable aggressive rate limiting",
                    action_type="MITIGATE",
                    parameters={"rate_limit": 10},
                    prerequisites=[],
                    estimated_duration=30,
                    priority=9,
                    automated=True,
                    reversible=True
                ),
                ResponseAction(
                    id="block_attack_sources",
                    name="Block Attack Sources",
                    description="Block identified attack source IPs",
                    action_type="BLOCK",
                    parameters={"duration": 7200},
                    prerequisites=[],
                    estimated_duration=60,
                    priority=8,
                    automated=True,
                    reversible=True
                )
            ],
            escalation_rules={"traffic_threshold": "1GB/min"},
            approval_required=False
        )
        
        self.playbooks = {
            "malware_response": malware_playbook,
            "intrusion_response": intrusion_playbook,
            "ddos_response": ddos_playbook
        }
    
    async def create_incident(self, title: str, description: str, severity: str, 
                            category: str, source: str, affected_assets: List[str],
                            indicators: Dict[str, Any] = None) -> SecurityIncident:
        """Create a new security incident"""
        
        incident_id = str(uuid.uuid4())[:8]
        incident = SecurityIncident(
            id=incident_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            status="OPEN",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            source=source,
            affected_assets=affected_assets,
            indicators=indicators or {},
            response_actions=[],
            timeline=[{
                'timestamp': datetime.now().isoformat(),
                'action': 'INCIDENT_CREATED',
                'description': f'Incident created from {source}'
            }]
        )
        
        # Store in database
        self.store_incident(incident)
        
        # Add to active incidents
        self.active_incidents[incident_id] = incident
        
        # Queue for automated response
        await self.incident_queue.put(incident)
        
        self.logger.info(f"Created incident {incident_id}: {title}")
        return incident
    
    def store_incident(self, incident: SecurityIncident):
        """Store incident in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO incidents
            (id, title, description, severity, category, status, created_at, updated_at,
             source, affected_assets, indicators, response_actions, assigned_to, escalated,
             evidence_collected, timeline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident.id,
            incident.title,
            incident.description,
            incident.severity,
            incident.category,
            incident.status,
            incident.created_at.isoformat(),
            incident.updated_at.isoformat(),
            incident.source,
            json.dumps(incident.affected_assets),
            json.dumps(incident.indicators),
            json.dumps(incident.response_actions),
            incident.assigned_to,
            int(incident.escalated),
            json.dumps(incident.evidence_collected),
            json.dumps(incident.timeline)
        ))
        
        conn.commit()
        conn.close()
    
    async def execute_response_action(self, incident: SecurityIncident, action: ResponseAction) -> bool:
        """Execute a response action"""
        try:
            self.logger.info(f"Executing action {action.name} for incident {incident.id}")
            
            result = False
            action_details = {}
            
            if action.action_type == "ISOLATE":
                if incident.affected_assets:
                    for asset in incident.affected_assets:
                        result = await self.threat_containment.isolate_host(asset)
                        action_details[asset] = result
            
            elif action.action_type == "BLOCK":
                if 'source_ip' in incident.indicators:
                    source_ip = incident.indicators['source_ip']
                    duration = action.parameters.get('duration', 3600)
                    result = await self.threat_containment.block_ip_address(source_ip, duration)
                    action_details['blocked_ip'] = source_ip
            
            elif action.action_type == "COLLECT":
                evidence_types = action.parameters.get('types', ['network'])
                evidence_files = []
                
                if 'network' in evidence_types:
                    files = await self.evidence_collector.collect_network_evidence(incident)
                    evidence_files.extend(files)
                
                if 'logs' in evidence_types:
                    log_paths = ['/var/log/auth.log', '/var/log/syslog', './logs/securenet.log']
                    files = await self.evidence_collector.collect_log_evidence(incident, log_paths)
                    evidence_files.extend(files)
                
                incident.evidence_collected.extend(evidence_files)
                action_details['evidence_files'] = evidence_files
                result = len(evidence_files) > 0
            
            elif action.action_type == "ALERT":
                channels = action.parameters.get('channels', ['email'])
                
                if 'email' in channels:
                    recipients = self.config.get('ALERT_EMAIL_RECIPIENTS', [])
                    await self.notification_manager.send_email_alert(incident, recipients)
                
                if 'slack' in channels:
                    await self.notification_manager.send_slack_alert(incident)
                
                if 'sms' in channels:
                    await self.notification_manager.send_sms_alert(incident)
                
                result = True
                action_details['channels'] = channels
            
            # Record action execution
            action_record = {
                'id': str(uuid.uuid4())[:8],
                'action_id': action.id,
                'name': action.name,
                'executed_at': datetime.now().isoformat(),
                'status': 'SUCCESS' if result else 'FAILED',
                'details': action_details
            }
            
            incident.response_actions.append(action_record)
            incident.timeline.append({
                'timestamp': datetime.now().isoformat(),
                'action': f'ACTION_EXECUTED',
                'description': f'Executed {action.name}',
                'result': action_record['status']
            })
            
            # Update incident
            incident.updated_at = datetime.now()
            self.store_incident(incident)
            
            self.response_stats[action.action_type] += 1
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to execute action {action.name}: {e}")
            return False
    
    async def process_incident(self, incident: SecurityIncident):
        """Process incident using appropriate playbook"""
        try:
            # Find matching playbook
            playbook = self.find_matching_playbook(incident)
            
            if not playbook:
                self.logger.warning(f"No matching playbook for incident {incident.id}")
                return
            
            self.logger.info(f"Processing incident {incident.id} with playbook {playbook.name}")
            
            # Update incident status
            incident.status = "INVESTIGATING"
            incident.timeline.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'PLAYBOOK_STARTED',
                'description': f'Started playbook: {playbook.name}'
            })
            
            # Execute actions in priority order
            actions = sorted(playbook.actions, key=lambda x: x.priority, reverse=True)
            
            for action in actions:
                if action.automated:
                    success = await self.execute_response_action(incident, action)
                    
                    if not success:
                        self.logger.error(f"Failed to execute action {action.name}")
                        
                        # Escalate if critical action fails
                        if action.priority >= 8:
                            await self.escalate_incident(incident, f"Critical action {action.name} failed")
            
            # Check if incident should be escalated
            await self.check_escalation_rules(incident, playbook)
            
            # Update incident status
            if incident.status == "INVESTIGATING":
                incident.status = "CONTAINED"
            
            incident.updated_at = datetime.now()
            self.store_incident(incident)
            
        except Exception as e:
            self.logger.error(f"Error processing incident {incident.id}: {e}")
    
    def find_matching_playbook(self, incident: SecurityIncident) -> Optional[ResponsePlaybook]:
        """Find the best matching playbook for an incident"""
        best_match = None
        best_score = 0
        
        for playbook in self.playbooks.values():
            score = 0
            conditions = playbook.trigger_conditions
            
            # Check category match
            if conditions.get('category') == incident.category:
                score += 3
            
            # Check severity match
            if 'severity' in conditions:
                if isinstance(conditions['severity'], list):
                    if incident.severity in conditions['severity']:
                        score += 2
                elif conditions['severity'] == incident.severity:
                    score += 2
            
            # Check source match
            if conditions.get('source') == incident.source:
                score += 1
            
            if score > best_score:
                best_score = score
                best_match = playbook
        
        return best_match
    
    async def escalate_incident(self, incident: SecurityIncident, reason: str):
        """Escalate incident to higher severity or manual intervention"""
        if incident.escalated:
            return
        
        incident.escalated = True
        incident.timeline.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'INCIDENT_ESCALATED',
            'description': f'Escalated: {reason}'
        })
        
        # Upgrade severity if possible
        severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        current_index = severity_levels.index(incident.severity)
        if current_index < len(severity_levels) - 1:
            incident.severity = severity_levels[current_index + 1]
        
        # Send high-priority notifications
        recipients = self.config.get('ESCALATION_EMAIL_RECIPIENTS', [])
        await self.notification_manager.send_email_alert(incident, recipients)
        await self.notification_manager.send_sms_alert(incident)
        
        self.logger.warning(f"Escalated incident {incident.id}: {reason}")
    
    async def check_escalation_rules(self, incident: SecurityIncident, playbook: ResponsePlaybook):
        """Check if incident meets escalation criteria"""
        rules = playbook.escalation_rules
        
        # Time-based escalation
        if 'time_threshold' in rules:
            incident_age = (datetime.now() - incident.created_at).total_seconds()
            if incident_age > rules['time_threshold']:
                await self.escalate_incident(incident, "Time threshold exceeded")
        
        # Severity-based escalation
        if 'severity_threshold' in rules:
            if incident.severity == rules['severity_threshold']:
                await self.escalate_incident(incident, f"Severity reached {incident.severity}")
    
    async def start_response_engine(self):
        """Start the incident response engine"""
        self.is_running = True
        self.logger.info("Starting Incident Response Engine...")
        
        # Start worker tasks
        for i in range(3):  # 3 worker threads
            task = asyncio.create_task(self.incident_worker())
            self.worker_tasks.append(task)
        
        # Wait for all workers
        await asyncio.gather(*self.worker_tasks)
    
    async def incident_worker(self):
        """Worker task for processing incidents"""
        while self.is_running:
            try:
                # Get incident from queue with timeout
                incident = await asyncio.wait_for(
                    self.incident_queue.get(),
                    timeout=1.0
                )
                
                # Process the incident
                await self.process_incident(incident)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in incident worker: {e}")
    
    def stop_response_engine(self):
        """Stop the incident response engine"""
        self.is_running = False
        for task in self.worker_tasks:
            task.cancel()
        self.logger.info("Incident Response Engine stopped")
    
    def get_incidents(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get incidents from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT * FROM incidents
                WHERE status = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (status, limit))
        else:
            cursor.execute('''
                SELECT * FROM incidents
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        incidents = []
        
        for row in cursor.fetchall():
            incident_dict = dict(zip(columns, row))
            
            # Parse JSON fields
            for field in ['affected_assets', 'indicators', 'response_actions', 'evidence_collected', 'timeline']:
                if incident_dict[field]:
                    incident_dict[field] = json.loads(incident_dict[field])
                else:
                    incident_dict[field] = []
            
            incidents.append(incident_dict)
        
        conn.close()
        return incidents
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics"""
        return {
            'active_incidents': len(self.active_incidents),
            'total_incidents': len(self.get_incidents()),
            'response_actions': dict(self.response_stats),
            'is_running': self.is_running,
            'playbooks_loaded': len(self.playbooks)
        }

class IncidentResponseSystem:
    """Main incident response system that wraps the orchestrator"""
    
    def __init__(self, config: Dict[str, Any], security_logger):
        self.config = config
        self.security_logger = security_logger
        self.orchestrator = IncidentResponseOrchestrator(config)
        self.logger = logging.getLogger(__name__)
    
    def get_active_incidents(self) -> List[Dict[str, Any]]:
        """Get all active incidents"""
        return self.orchestrator.get_incidents(status='OPEN') + \
               self.orchestrator.get_incidents(status='INVESTIGATING')
    
    def get_incident_history(self, page: int = 1, per_page: int = 20, 
                           severity: str = None, status: str = None) -> Dict[str, Any]:
        """Get incident history with pagination"""
        all_incidents = self.orchestrator.get_incidents(limit=1000)  # Get more for filtering
        
        # Filter by severity and status if provided
        filtered_incidents = []
        for incident in all_incidents:
            if severity and incident.get('severity') != severity.upper():
                continue
            if status and incident.get('status') != status.upper():
                continue
            filtered_incidents.append(incident)
        
        # Pagination
        total = len(filtered_incidents)
        start = (page - 1) * per_page
        end = start + per_page
        incidents = filtered_incidents[start:end]
        
        return {
            'incidents': incidents,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    
    def get_incident_details(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific incident"""
        incidents = self.orchestrator.get_incidents(limit=1000)
        for incident in incidents:
            if incident['id'] == incident_id:
                return incident
        return None
    
    def update_incident(self, incident_id: str, status: str = None, 
                       notes: str = None, user_id: str = None) -> Dict[str, Any]:
        """Update incident status and add notes"""
        try:
            # Get incident details
            incident_data = self.get_incident_details(incident_id)
            if not incident_data:
                return {'success': False, 'error': 'Incident not found'}
            
            # Update fields if provided
            if status:
                incident_data['status'] = status.upper()
            
            # Add notes to timeline
            if notes:
                timeline = incident_data.get('timeline', [])
                timeline.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'NOTE_ADDED',
                    'description': notes,
                    'user_id': user_id
                })
                incident_data['timeline'] = timeline
            
            incident_data['updated_at'] = datetime.now().isoformat()
            
            # Recreate incident object and store
            incident = SecurityIncident(
                id=incident_data['id'],
                title=incident_data['title'],
                description=incident_data['description'],
                severity=incident_data['severity'],
                category=incident_data['category'],
                status=incident_data['status'],
                created_at=datetime.fromisoformat(incident_data['created_at']),
                updated_at=datetime.fromisoformat(incident_data['updated_at']),
                source=incident_data['source'],
                affected_assets=incident_data['affected_assets'],
                indicators=incident_data['indicators'],
                response_actions=incident_data['response_actions'],
                assigned_to=incident_data.get('assigned_to'),
                escalated=bool(incident_data.get('escalated', False)),
                evidence_collected=incident_data.get('evidence_collected', []),
                timeline=incident_data.get('timeline', [])
            )
            
            self.orchestrator.store_incident(incident)
            return {'success': True}
            
        except Exception as e:
            self.logger.error(f"Error updating incident {incident_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    async def create_manual_incident(self, title: str, description: str, severity: str = 'medium',
                                   category: str = 'manual', user_id: str = None,
                                   evidence: List[str] = None) -> str:
        """Create a manual incident report"""
        incident = await self.orchestrator.create_incident(
            title=title,
            description=description,
            severity=severity.upper(),
            category=category.upper(),
            source='USER_REPORT',
            affected_assets=[],
            indicators={'reported_by': user_id}
        )
        
        if evidence:
            incident.evidence_collected.extend(evidence)
            self.orchestrator.store_incident(incident)
        
        return incident.id
    
    def get_incident_statistics(self, time_range: str = '24h') -> Dict[str, Any]:
        """Get incident statistics and metrics"""
        try:
            # Parse time range
            if time_range == '24h':
                delta = timedelta(hours=24)
            elif time_range == '7d':
                delta = timedelta(days=7)
            elif time_range == '30d':
                delta = timedelta(days=30)
            else:
                delta = timedelta(hours=24)
            
            cutoff_time = datetime.now() - delta
            all_incidents = self.orchestrator.get_incidents(limit=1000)
            
            # Filter incidents by time range
            recent_incidents = []
            for incident in all_incidents:
                created_at = datetime.fromisoformat(incident['created_at'])
                if created_at >= cutoff_time:
                    recent_incidents.append(incident)
            
            # Calculate statistics
            stats = {
                'total_incidents': len(recent_incidents),
                'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                'by_status': {'OPEN': 0, 'INVESTIGATING': 0, 'CONTAINED': 0, 'RESOLVED': 0, 'CLOSED': 0},
                'by_category': {},
                'response_times': [],
                'escalated_count': 0,
                'resolved_count': 0
            }
            
            for incident in recent_incidents:
                # By severity
                severity = incident.get('severity', 'MEDIUM')
                if severity in stats['by_severity']:
                    stats['by_severity'][severity] += 1
                
                # By status
                status = incident.get('status', 'OPEN')
                if status in stats['by_status']:
                    stats['by_status'][status] += 1
                
                # By category
                category = incident.get('category', 'UNKNOWN')
                stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
                
                # Escalated incidents
                if incident.get('escalated'):
                    stats['escalated_count'] += 1
                
                # Resolved incidents
                if status in ['RESOLVED', 'CLOSED']:
                    stats['resolved_count'] += 1
                    
                    # Calculate response time if available
                    created_at = datetime.fromisoformat(incident['created_at'])
                    updated_at = datetime.fromisoformat(incident['updated_at'])
                    response_time = (updated_at - created_at).total_seconds()
                    stats['response_times'].append(response_time)
            
            # Calculate average response time
            if stats['response_times']:
                stats['avg_response_time'] = sum(stats['response_times']) / len(stats['response_times'])
            else:
                stats['avg_response_time'] = 0
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error calculating incident statistics: {e}")
            return {}
    
    def add_evidence(self, incident_id: str, evidence: Dict[str, Any], 
                    user_id: str = None) -> Dict[str, Any]:
        """Add evidence to an existing incident"""
        try:
            incident_data = self.get_incident_details(incident_id)
            if not incident_data:
                return {'success': False, 'error': 'Incident not found'}
            
            # Add evidence
            evidence_item = {
                'id': str(uuid.uuid4())[:8],
                'type': evidence.get('type', 'unknown'),
                'description': evidence.get('description', ''),
                'data': evidence.get('data', ''),
                'collected_by': user_id,
                'collected_at': datetime.now().isoformat()
            }
            
            evidence_collected = incident_data.get('evidence_collected', [])
            evidence_collected.append(evidence_item)
            incident_data['evidence_collected'] = evidence_collected
            
            # Update timeline
            timeline = incident_data.get('timeline', [])
            timeline.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'EVIDENCE_ADDED',
                'description': f'Evidence added: {evidence.get("type", "unknown")}',
                'user_id': user_id
            })
            incident_data['timeline'] = timeline
            incident_data['updated_at'] = datetime.now().isoformat()
            
            # Store updated incident
            incident = SecurityIncident(
                id=incident_data['id'],
                title=incident_data['title'],
                description=incident_data['description'],
                severity=incident_data['severity'],
                category=incident_data['category'],
                status=incident_data['status'],
                created_at=datetime.fromisoformat(incident_data['created_at']),
                updated_at=datetime.fromisoformat(incident_data['updated_at']),
                source=incident_data['source'],
                affected_assets=incident_data['affected_assets'],
                indicators=incident_data['indicators'],
                response_actions=incident_data['response_actions'],
                assigned_to=incident_data.get('assigned_to'),
                escalated=bool(incident_data.get('escalated', False)),
                evidence_collected=evidence_collected,
                timeline=timeline
            )
            
            self.orchestrator.store_incident(incident)
            return {'success': True}
            
        except Exception as e:
            self.logger.error(f"Error adding evidence to incident {incident_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def execute_response_action(self, incident_id: str, action: str, 
                              parameters: Dict[str, Any] = None, 
                              user_id: str = None) -> Dict[str, Any]:
        """Execute a response action for an incident"""
        try:
            # This is a simplified version - in a real implementation,
            # you would have predefined response actions
            incident_data = self.get_incident_details(incident_id)
            if not incident_data:
                return {'success': False, 'error': 'Incident not found'}
            
            # Log the action
            timeline = incident_data.get('timeline', [])
            timeline.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'MANUAL_ACTION_EXECUTED',
                'description': f'Manual action executed: {action}',
                'user_id': user_id,
                'parameters': parameters or {}
            })
            
            # Update incident
            incident_data['timeline'] = timeline
            incident_data['updated_at'] = datetime.now().isoformat()
            
            # Store updated incident
            incident = SecurityIncident(
                id=incident_data['id'],
                title=incident_data['title'],
                description=incident_data['description'],
                severity=incident_data['severity'],
                category=incident_data['category'],
                status=incident_data['status'],
                created_at=datetime.fromisoformat(incident_data['created_at']),
                updated_at=datetime.fromisoformat(incident_data['updated_at']),
                source=incident_data['source'],
                affected_assets=incident_data['affected_assets'],
                indicators=incident_data['indicators'],
                response_actions=incident_data['response_actions'],
                assigned_to=incident_data.get('assigned_to'),
                escalated=bool(incident_data.get('escalated', False)),
                evidence_collected=incident_data.get('evidence_collected', []),
                timeline=timeline
            )
            
            self.orchestrator.store_incident(incident)
            
            # Simulate action execution result
            result = {
                'action': action,
                'executed_at': datetime.now().isoformat(),
                'status': 'completed',
                'parameters': parameters or {}
            }
            
            return {'success': True, 'result': result}
            
        except Exception as e:
            self.logger.error(f"Error executing response action for incident {incident_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_monitoring(self):
        """Start the incident response system monitoring"""
        try:
            # Start the response engine
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.orchestrator.start_response_engine())
        except Exception as e:
            self.logger.error(f"Error starting incident response monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop the incident response system monitoring"""
        try:
            self.orchestrator.stop_response_engine()
        except Exception as e:
            self.logger.error(f"Error stopping incident response monitoring: {e}")

# Global response orchestrator instance
response_orchestrator = None

def get_response_orchestrator(config=None):
    """Get or create response orchestrator instance"""
    global response_orchestrator
    if response_orchestrator is None:
        response_orchestrator = IncidentResponseOrchestrator(config or {})
    return response_orchestrator
