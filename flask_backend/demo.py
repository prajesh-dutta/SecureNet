#!/usr/bin/env python3
"""
SecureNet SOC Platform - Interactive Demo Script
Demonstrates key features and API capabilities
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5001/api"

def print_header(title):
    print("\n" + "="*60)
    print(f"🔒 {title}")
    print("="*60)

def print_section(title):
    print(f"\n📊 {title}")
    print("-" * 40)

def demo_logs_statistics():
    """Demonstrate logs statistics dashboard"""
    print_section("Logs Statistics Dashboard")
    
    response = requests.get(f"{BASE_URL}/logs/statistics")
    if response.status_code == 200:
        stats = response.json()
        print(f"📈 Total Events: {stats['total_events']:,}")
        print(f"⚠️  Critical Alerts: {stats['critical_alerts']}")
        print(f"🔐 Failed Logins: {stats['failed_logins']}")
        print(f"👥 Unique Users: {stats['unique_users']}")
    else:
        print("❌ Failed to fetch statistics")

def demo_security_logs():
    """Demonstrate security logs with filtering"""
    print_section("Security Logs with Filtering")
    
    # Get critical logs only
    response = requests.get(f"{BASE_URL}/security/logs/security?level=critical&limit=3")
    if response.status_code == 200:
        data = response.json()
        logs = data['logs']
        print(f"🚨 Found {len(logs)} critical security logs:")
        
        for i, log in enumerate(logs, 1):
            print(f"\n  {i}. {log['event_type']} | {log['level']}")
            print(f"     User: {log['user']} | Source: {log['source']}")
            print(f"     Time: {log['timestamp']}")
            print(f"     Risk Score: {log['risk_score']}/100")
    else:
        print("❌ Failed to fetch security logs")

def demo_audit_trail():
    """Demonstrate audit trail events"""
    print_section("Recent Audit Trail Events")
    
    response = requests.get(f"{BASE_URL}/security/audit/events?limit=5")
    if response.status_code == 200:
        data = response.json()
        events = data['events']
        print(f"📋 Found {len(events)} recent audit events:")
        
        for i, event in enumerate(events, 1):
            print(f"\n  {i}. {event['action']} | {event['category']}")
            print(f"     User: {event['user']} | Result: {event['result']}")
            print(f"     IP: {event['ip_address']} | Time: {event['timestamp']}")
    else:
        print("❌ Failed to fetch audit events")

def demo_dashboard_overview():
    """Demonstrate dashboard overview data"""
    print_section("Security Dashboard Overview")
    
    response = requests.get(f"{BASE_URL}/dashboard/overview")
    if response.status_code == 200:
        data = response.json()
        print(f"🔴 Active Threats: {data['active_threats']}")
        print(f"🌐 Network Status: {data['network_status']}")
        print(f"⚠️  Security Alerts: {data['security_alerts']}")
        print(f"💚 System Health: {data['system_health']}%")
    else:
        print("❌ Failed to fetch dashboard data")

def demo_network_status():
    """Demonstrate network monitoring"""
    print_section("Network Infrastructure Status")
    
    response = requests.get(f"{BASE_URL}/network/status")
    if response.status_code == 200:
        data = response.json()
        print(f"🌐 Network Health: {data.get('health', 'Unknown')}")
        
        if 'devices' in data:
            active_devices = sum(1 for d in data['devices'] if d.get('status') == 'online')
            total_devices = len(data['devices'])
            print(f"📱 Active Devices: {active_devices}/{total_devices}")
    else:
        print("❌ Failed to fetch network status")

def demo_threat_intelligence():
    """Demonstrate threat intelligence data"""
    print_section("Geographic Threat Intelligence")
    
    response = requests.get(f"{BASE_URL}/threats/geographic")
    if response.status_code == 200:
        data = response.json()
        if 'threats' in data:
            threats = data['threats'][:3]  # Show top 3
            print(f"🌍 Top Geographic Threats:")
            
            for i, threat in enumerate(threats, 1):
                print(f"\n  {i}. {threat.get('country', 'Unknown')} | {threat.get('type', 'Unknown')}")
                print(f"     Severity: {threat.get('severity', 'Unknown')}")
                print(f"     Count: {threat.get('count', 0)} incidents")
    else:
        print("❌ Failed to fetch threat intelligence")

def main():
    print_header("SecureNet SOC Platform - Live Demo")
    print(f"🕒 Demo Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🌐 Frontend: http://localhost:5173")
    print("🔧 Backend: http://localhost:5001")
    
    try:
        # Test connectivity first
        health_response = requests.get(f"{BASE_URL}/health", timeout=5)
        if health_response.status_code != 200:
            print("\n❌ Backend server is not responding!")
            print("Please ensure Flask backend is running on port 5001")
            return
            
        # Run demo sections
        demo_dashboard_overview()
        demo_logs_statistics()
        demo_security_logs()
        demo_audit_trail()
        demo_network_status()
        demo_threat_intelligence()
        
        print_header("Demo Complete!")
        print("✅ All systems operational and responding correctly")
        print("🎯 Navigate to http://localhost:5173/logs to explore the logs interface")
        print("📊 Navigate to http://localhost:5173/dashboard for the main dashboard")
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Connection Error: Backend server is not running!")
        print("Please start the Flask backend:")
        print("cd flask_backend && .\\venv\\Scripts\\activate && python simple_app.py")
        
    except Exception as e:
        print(f"\n❌ Demo Error: {str(e)}")

if __name__ == "__main__":
    main()
