#!/usr/bin/env python3
"""
Comprehensive API Endpoint Testing Script for SecureNet SOC Platform
Tests all major endpoints to verify full-stack integration
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:5001/api"

def test_endpoint(name, url, expected_keys=None):
    """Test a single endpoint and validate response"""
    try:
        response = requests.get(f"{BASE_URL}{url}")
        if response.status_code == 200:
            data = response.json()
            if expected_keys:
                missing_keys = set(expected_keys) - set(data.keys())
                if missing_keys:
                    print(f"❌ {name}: Missing keys {missing_keys}")
                else:
                    print(f"✅ {name}: All expected keys present")
            else:
                print(f"✅ {name}: Status {response.status_code}")
            
            # Show sample data size
            if isinstance(data, dict):
                if 'logs' in data:
                    print(f"   📊 Contains {len(data['logs'])} logs")
                elif 'events' in data:
                    print(f"   📊 Contains {len(data['events'])} events")
                elif 'threats' in data:
                    print(f"   📊 Contains {len(data['threats'])} threats")
        else:
            print(f"❌ {name}: Status {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print(f"❌ {name}: Connection refused - server may be down")
    except Exception as e:
        print(f"❌ {name}: Error - {str(e)}")

def main():
    print("🔒 SecureNet SOC Platform - API Endpoint Testing")
    print("=" * 50)
    print(f"Testing at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Core health check
    test_endpoint("Health Check", "/health", ["status", "timestamp"])
    
    print("\n📊 Dashboard Endpoints:")
    test_endpoint("Dashboard Overview", "/dashboard/overview", 
                 ["active_threats", "network_status", "security_alerts", "system_health"])
    test_endpoint("Dashboard Metrics", "/dashboard/metrics")
    test_endpoint("Dashboard Traffic", "/dashboard/traffic")
    
    print("\n🔒 Security Endpoints:")
    test_endpoint("Security Events", "/security/events")
    test_endpoint("Security Logs", "/security/logs/security")
    test_endpoint("Audit Events", "/security/audit/events")
    
    print("\n📋 Logs Endpoints:")
    test_endpoint("Logs Statistics", "/logs/statistics", 
                 ["critical_alerts", "failed_logins", "total_events", "unique_users"])
    
    print("\n🌐 Network Endpoints:")
    test_endpoint("Network Status", "/network/status")
    test_endpoint("Network Topology", "/network/topology")
    
    print("\n⚠️ Threat Endpoints:")
    test_endpoint("Geographic Threats", "/threats/geographic")
    
    print("\n🎯 Filtered Endpoints:")
    test_endpoint("Critical Security Logs", "/security/logs/security?level=critical&limit=5")
    test_endpoint("Recent Audit Events", "/security/audit/events?limit=10")
    
    print("\n" + "=" * 50)
    print("✅ API Testing Complete!")
    print("🌐 Frontend URL: http://localhost:5173")
    print("🔧 Backend URL: http://localhost:5001")

if __name__ == "__main__":
    main()
