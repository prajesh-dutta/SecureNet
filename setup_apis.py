#!/usr/bin/env python3
"""
Quick API Setup Helper for SecureNet SOC Platform
Helps you create .env file and provides direct links to get API keys
"""

import os
import webbrowser
import sys

def create_env_file():
    """Create .env file from template"""
    template_file = '.env.template'
    env_file = '.env'
    
    if os.path.exists(env_file):
        response = input(f"📁 {env_file} already exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("✅ Keeping existing .env file")
            return True
    
    if os.path.exists(template_file):
        with open(template_file, 'r') as template:
            content = template.read()
        
        with open(env_file, 'w') as env:
            env.write(content)
        
        print(f"✅ Created {env_file} from template")
        return True
    else:
        print(f"❌ Template file {template_file} not found")
        return False

def open_registration_pages():
    """Open all API registration pages in browser"""
    apis = {
        "VirusTotal": "https://www.virustotal.com/gui/join-us",
        "AbuseIPDB": "https://www.abuseipdb.com/register", 
        "Shodan": "https://account.shodan.io/register",
        "AlienVault OTX": "https://otx.alienvault.com/registration",
        "URLScan.io": "https://urlscan.io/user/signup",
        "GreyNoise": "https://www.greynoise.io/signup",
        "SecurityTrails": "https://securitytrails.com/corp/signup",
        "PhishTank": "https://www.phishtank.com/register.php"
    }
    
    print("🌐 Opening API registration pages in your browser...")
    print("💡 Tip: Use the same email for all services to keep things organized")
    print()
    
    for name, url in apis.items():
        print(f"Opening {name}...")
        webbrowser.open(url)
    
    print("\n✅ All registration pages opened!")
    print("📝 Create accounts and collect your API keys")

def show_quick_guide():
    """Show quick setup guide"""
    print("🔑 SecureNet SOC - Quick API Setup Guide")
    print("=" * 45)
    print()
    print("📋 STEP 1: Create accounts (5-10 minutes)")
    print("  - Use the same email for all services")
    print("  - Write down your passwords")
    print("  - Verify email addresses when required")
    print()
    print("🔑 STEP 2: Collect API keys (5 minutes)")
    print("  - Login to each service")
    print("  - Find API/Developer section")
    print("  - Generate/copy your API key")
    print()
    print("📝 STEP 3: Update .env file (2 minutes)")
    print("  - Replace 'your_*_api_key_here' with real keys")
    print("  - Save the file")
    print()
    print("🧪 STEP 4: Test API keys")
    print("  - Run: python flask_backend/test_api_keys.py")
    print()
    print("🚀 STEP 5: Restart servers with real data!")
    print()

def main():
    print("🔧 SecureNet SOC Platform - API Setup Helper")
    print("=" * 50)
    print()
    
    while True:
        print("What would you like to do?")
        print("1. 📁 Create .env file from template")
        print("2. 🌐 Open all API registration pages")
        print("3. 📋 Show quick setup guide")
        print("4. 🧪 Test existing API keys")
        print("5. ❌ Exit")
        print()
        
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == '1':
            print()
            create_env_file()
            print("📝 Next: Edit .env file and add your API keys")
            
        elif choice == '2':
            print()
            open_registration_pages()
            
        elif choice == '3':
            print()
            show_quick_guide()
            
        elif choice == '4':
            print()
            print("🧪 Running API key tests...")
            os.system('python flask_backend/test_api_keys.py')
            
        elif choice == '5':
            print("👋 Good luck with your API setup!")
            sys.exit(0)
            
        else:
            print("❌ Invalid choice. Please enter 1-5.")
        
        print("\n" + "-" * 50 + "\n")

if __name__ == "__main__":
    main()
