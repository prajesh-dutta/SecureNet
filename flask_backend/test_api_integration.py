#!/usr/bin/env python3
"""
API Integration Test Script for SecureNet Dashboard

This script tests all the newly implemented API endpoints to ensure
they work correctly with the enhanced services.
"""

import requests
import json
import time
from datetime import datetime, timedelta
import uuid

class SecureNetAPITester:
    def __init__(self, base_url="http://localhost:5000", username="admin", password="admin"):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
    
    def authenticate(self):
        """Authenticate and get JWT token"""
        try:
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = self.session.post(f"{self.base_url}/auth/login", json=auth_data)
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('access_token')
                self.session.headers.update({
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json'
                })
                print("✓ Authentication successful")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def test_security_alerts(self):
        """Test security alerts endpoints"""
        print("\n--- Testing Security Alerts ---")
        
        try:
            # Get security alerts
            response = self.session.get(f"{self.base_url}/api/security/alerts")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved {data.get('count', 0)} security alerts")
                
                # Test acknowledging an alert if any exist
                alerts = data.get('alerts', [])
                if alerts:
                    alert_id = alerts[0].get('id')
                    ack_response = self.session.post(f"{self.base_url}/api/security/alerts/{alert_id}/acknowledge")
                    if ack_response.status_code == 200:
                        print("✓ Alert acknowledgment successful")
                    else:
                        print(f"✗ Alert acknowledgment failed: {ack_response.status_code}")
                        
            else:
                print(f"✗ Failed to retrieve security alerts: {response.status_code}")
                
        except Exception as e:
            print(f"✗ Security alerts test error: {e}")
    
    def test_ids_management(self):
        """Test IDS management endpoints"""
        print("\n--- Testing IDS Management ---")
        
        try:
            # Get IDS status
            response = self.session.get(f"{self.base_url}/api/security/ids/status")
            if response.status_code == 200:
                data = response.json()
                print("✓ IDS status retrieved successfully")
                print(f"  Status: {data.get('ids_status', {}).get('status', 'unknown')}")
            else:
                print(f"✗ Failed to get IDS status: {response.status_code}")
            
            # Get detection rules
            response = self.session.get(f"{self.base_url}/api/security/ids/rules")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved {data.get('count', 0)} detection rules")
            else:
                print(f"✗ Failed to get detection rules: {response.status_code}")
            
            # Add a new detection rule
            new_rule = {
                "name": "Test Rule",
                "pattern": "test.*pattern",
                "action": "alert",
                "severity": "medium",
                "description": "Test detection rule for API testing"
            }
            
            response = self.session.post(f"{self.base_url}/api/security/ids/rules", json=new_rule)
            if response.status_code == 200:
                rule_data = response.json()
                rule_id = rule_data.get('rule_id')
                print(f"✓ Added new detection rule: {rule_id}")
                
                # Update the rule
                update_data = {
                    "description": "Updated test detection rule",
                    "severity": "high"
                }
                response = self.session.put(f"{self.base_url}/api/security/ids/rules/{rule_id}", json=update_data)
                if response.status_code == 200:
                    print("✓ Detection rule updated successfully")
                else:
                    print(f"✗ Failed to update detection rule: {response.status_code}")
                
                # Delete the rule
                response = self.session.delete(f"{self.base_url}/api/security/ids/rules/{rule_id}")
                if response.status_code == 200:
                    print("✓ Detection rule deleted successfully")
                else:
                    print(f"✗ Failed to delete detection rule: {response.status_code}")
            else:
                print(f"✗ Failed to add detection rule: {response.status_code}")
                
        except Exception as e:
            print(f"✗ IDS management test error: {e}")
    
    def test_security_logging(self):
        """Test security logging endpoints"""
        print("\n--- Testing Security Logging ---")
        
        try:
            # Get security logs
            response = self.session.get(f"{self.base_url}/api/security/logs/security")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved security logs (total: {data.get('pagination', {}).get('total', 0)})")
            else:
                print(f"✗ Failed to get security logs: {response.status_code}")
            
            # Get audit events
            response = self.session.get(f"{self.base_url}/api/security/audit/events")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved audit events (total: {data.get('pagination', {}).get('total', 0)})")
            else:
                print(f"✗ Failed to get audit events: {response.status_code}")
                
        except Exception as e:
            print(f"✗ Security logging test error: {e}")
    
    def test_middleware_management(self):
        """Test security middleware endpoints"""
        print("\n--- Testing Security Middleware ---")
        
        try:
            # Get middleware statistics
            response = self.session.get(f"{self.base_url}/api/security/middleware/stats")
            if response.status_code == 200:
                data = response.json()
                print("✓ Retrieved middleware statistics")
                stats = data.get('statistics', {})
                print(f"  Total requests tracked: {stats.get('total_requests_tracked', 0)}")
            else:
                print(f"✗ Failed to get middleware stats: {response.status_code}")
            
            # Get blocked IPs
            response = self.session.get(f"{self.base_url}/api/security/blocked-ips")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved {data.get('count', 0)} blocked IPs")
            else:
                print(f"✗ Failed to get blocked IPs: {response.status_code}")
            
            # Test IP blocking (use a test IP)
            test_ip = "192.0.2.100"  # RFC 5737 test IP
            block_data = {
                "ip_address": test_ip,
                "reason": "API test block",
                "duration": 300  # 5 minutes
            }
            
            response = self.session.post(f"{self.base_url}/api/security/block-ip", json=block_data)
            if response.status_code == 200:
                print(f"✓ Successfully blocked test IP: {test_ip}")
                
                # Unblock the IP
                unblock_data = {"ip_address": test_ip}
                response = self.session.post(f"{self.base_url}/api/security/unblock-ip", json=unblock_data)
                if response.status_code == 200:
                    print(f"✓ Successfully unblocked test IP: {test_ip}")
                else:
                    print(f"✗ Failed to unblock test IP: {response.status_code}")
            else:
                print(f"✗ Failed to block test IP: {response.status_code}")
                
        except Exception as e:
            print(f"✗ Security middleware test error: {e}")
    
    def test_incident_management(self):
        """Test incident management endpoints"""
        print("\n--- Testing Incident Management ---")
        
        try:
            # Get active incidents
            response = self.session.get(f"{self.base_url}/api/incidents/active")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved {len(data.get('incidents', []))} active incidents")
            else:
                print(f"✗ Failed to get active incidents: {response.status_code}")
            
            # Get incident history
            response = self.session.get(f"{self.base_url}/api/incidents/history")
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Retrieved incident history (total: {data.get('pagination', {}).get('total', 0)})")
            else:
                print(f"✗ Failed to get incident history: {response.status_code}")
            
            # Create a test incident
            test_incident = {
                "title": "API Test Incident",
                "description": "Test incident created by API integration test",
                "severity": "medium",
                "category": "test",
                "source": "api_test"
            }
            
            response = self.session.post(f"{self.base_url}/api/incidents/create", json=test_incident)
            if response.status_code == 200 or response.status_code == 201:
                incident_data = response.json()
                incident_id = incident_data.get('incident_id')
                print(f"✓ Created test incident: {incident_id}")
                
                # Get incident details
                response = self.session.get(f"{self.base_url}/api/incidents/{incident_id}")
                if response.status_code == 200:
                    print("✓ Retrieved incident details")
                else:
                    print(f"✗ Failed to get incident details: {response.status_code}")
                
                # Update incident status
                update_data = {
                    "status": "investigating",
                    "notes": "Updated by API test"
                }
                response = self.session.post(f"{self.base_url}/api/incidents/{incident_id}/status", json=update_data)
                if response.status_code == 200:
                    print("✓ Updated incident status")
                else:
                    print(f"✗ Failed to update incident status: {response.status_code}")
                    
            else:
                print(f"✗ Failed to create test incident: {response.status_code}")
            
            # Get incident statistics
            response = self.session.get(f"{self.base_url}/api/incidents/stats")
            if response.status_code == 200:
                data = response.json()
                print("✓ Retrieved incident statistics")
                stats = data.get('statistics', {})
                print(f"  Total incidents: {stats.get('total', 0)}")
            else:
                print(f"✗ Failed to get incident statistics: {response.status_code}")
                
        except Exception as e:
            print(f"✗ Incident management test error: {e}")
    
    def run_all_tests(self):
        """Run all API tests"""
        print("SecureNet Dashboard API Integration Test")
        print("=" * 50)
        
        if not self.authenticate():
            print("Authentication failed, stopping tests")
            return False
        
        # Run all test suites
        self.test_security_alerts()
        self.test_ids_management()
        self.test_security_logging()
        self.test_middleware_management()
        self.test_incident_management()
        
        print("\n" + "=" * 50)
        print("API Integration Tests Completed")
        print("Note: Some tests may fail if the services are not fully initialized")
        print("Start the Flask application first with: python app.py")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test SecureNet Dashboard APIs")
    parser.add_argument("--url", default="http://localhost:5000", help="Base URL of the API")
    parser.add_argument("--username", default="admin", help="Username for authentication")
    parser.add_argument("--password", default="admin", help="Password for authentication")
    
    args = parser.parse_args()
    
    tester = SecureNetAPITester(
        base_url=args.url,
        username=args.username,
        password=args.password
    )
    
    tester.run_all_tests()
