#!/usr/bin/env python3
"""
API Keys Testing Script for SecureNet SOC Platform
Tests all configured API keys to ensure they're working correctly
"""

import os
import sys
import requests
import json
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables from parent directory
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(env_path)

# Check if .env file exists
if not os.path.exists(env_path):
    print("❌ .env file not found!")
    print(f"📁 Looking for: {os.path.abspath(env_path)}")
    print("📝 Please create .env file with your API keys")
    print("💡 You can copy .env.example and rename it to .env")
    sys.exit(1)

class APIKeyTester:
    def __init__(self):
        self.results = {}
        self.total_tests = 0
        self.passed_tests = 0
        
    def test_virustotal(self):
        """Test VirusTotal API"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key or api_key == 'your_virustotal_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'x-apikey': api_key}
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/file/report',
                params={'apikey': api_key, 'resource': 'test'},
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_abuseipdb(self):
        """Test AbuseIPDB API"""
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key or api_key == 'your_abuseipdb_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'Key': api_key, 'Accept': 'application/json'}
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 90},
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_shodan(self):
        """Test Shodan API"""
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key or api_key == 'your_shodan_api_key_here':
            return False, "API key not configured"
            
        try:
            response = requests.get(
                f'https://api.shodan.io/api-info?key={api_key}',
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_alienvault(self):
        """Test AlienVault OTX API"""
        api_key = os.getenv('ALIENVAULT_API_KEY')
        if not api_key or api_key == 'your_alienvault_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'X-OTX-API-KEY': api_key}
            response = requests.get(
                'https://otx.alienvault.com/api/v1/indicators/domain/google.com/general',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_urlscan(self):
        """Test URLScan.io API"""
        api_key = os.getenv('URLSCAN_API_KEY')
        if not api_key or api_key == 'your_urlscan_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'API-Key': api_key}
            response = requests.get(
                'https://urlscan.io/api/v1/search/?q=domain:google.com',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_greynoise(self):
        """Test GreyNoise API"""
        api_key = os.getenv('GREYNOISE_API_KEY')
        if not api_key or api_key == 'your_greynoise_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'key': api_key}
            response = requests.get(
                'https://api.greynoise.io/v3/community/8.8.8.8',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_securitytrails(self):
        """Test SecurityTrails API"""
        api_key = os.getenv('SECURITYTRAILS_API_KEY')
        if not api_key or api_key == 'your_securitytrails_api_key_here':
            return False, "API key not configured"
            
        try:
            headers = {'APIKEY': api_key}
            response = requests.get(
                'https://api.securitytrails.com/v1/domain/google.com',
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def test_phishtank(self):
        """Test PhishTank API"""
        api_key = os.getenv('PHISHTANK_API_KEY')
        if not api_key or api_key == 'your_phishtank_api_key_here':
            return False, "API key not configured"
            
        try:
            # PhishTank doesn't require API key for basic queries
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={'url': 'http://google.com', 'format': 'json'},
                timeout=10
            )
            if response.status_code == 200:
                return True, "Connected successfully"
            else:
                return False, f"Status code: {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def run_test(self, name, test_func):
        """Run a single API test"""
        self.total_tests += 1
        print(f"Testing {name}... ", end="")
        
        try:
            success, message = test_func()
            if success:
                print(f"✅ {message}")
                self.passed_tests += 1
                self.results[name] = {"status": "✅ PASS", "message": message}
            else:
                print(f"❌ {message}")
                self.results[name] = {"status": "❌ FAIL", "message": message}
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            self.results[name] = {"status": "❌ ERROR", "message": str(e)}
    
    def run_all_tests(self):
        """Run all API tests"""
        print("🔑 SecureNet SOC Platform - API Keys Testing")
        print("=" * 50)
        print(f"Testing at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Test all APIs
        self.run_test("VirusTotal", self.test_virustotal)
        self.run_test("AbuseIPDB", self.test_abuseipdb)
        self.run_test("Shodan", self.test_shodan)
        self.run_test("AlienVault OTX", self.test_alienvault)
        self.run_test("URLScan.io", self.test_urlscan)
        self.run_test("GreyNoise", self.test_greynoise)
        self.run_test("SecurityTrails", self.test_securitytrails)
        self.run_test("PhishTank", self.test_phishtank)
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"📊 Test Results: {self.passed_tests}/{self.total_tests} APIs working")
        
        if self.passed_tests == self.total_tests:
            print("🎉 All API keys are configured and working!")
        elif self.passed_tests > 0:
            print("⚠️  Some API keys need attention")
        else:
            print("❌ No API keys are configured yet")
        
        print("\n📋 Detailed Results:")
        for name, result in self.results.items():
            print(f"  {result['status']} {name}: {result['message']}")
        
        print("\n🔗 API Key Registration Links:")
        print("  VirusTotal: https://www.virustotal.com/gui/join-us")
        print("  AbuseIPDB: https://www.abuseipdb.com/register")
        print("  Shodan: https://account.shodan.io/register")
        print("  AlienVault: https://otx.alienvault.com/registration")
        print("  URLScan.io: https://urlscan.io/user/signup")
        print("  GreyNoise: https://www.greynoise.io/signup")
        print("  SecurityTrails: https://securitytrails.com/corp/signup")
        print("  PhishTank: https://www.phishtank.com/register.php")
        
        return self.passed_tests == self.total_tests

def main():
    # Run tests
    tester = APIKeyTester()
    success = tester.run_all_tests()
    
    if success:
        print("\n🚀 Ready to deploy with real threat intelligence!")
        sys.exit(0)
    else:
        print("\n🔧 Please configure missing API keys and run test again")
        sys.exit(1)

if __name__ == "__main__":
    main()
