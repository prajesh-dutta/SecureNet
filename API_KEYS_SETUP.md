# API Keys Setup Guide for SecureNet SOC Platform 🔑

## 🎯 Overview
This guide will help you obtain and configure free API keys for real cybersecurity threat intelligence services to replace the mock data in your SecureNet SOC Platform.

---

## 🔐 Required API Keys (All FREE Tiers Available)

### 1. **VirusTotal API** 🦠
- **Purpose**: Malware detection, file/URL scanning
- **Free Tier**: 1,000 requests/day
- **How to Get**:
  1. Go to https://www.virustotal.com/gui/join-us
  2. Create free account
  3. Go to https://www.virustotal.com/gui/my-apikey
  4. Copy your API key

### 2. **AbuseIPDB API** 🛡️
- **Purpose**: IP reputation checking, malicious IP detection
- **Free Tier**: 1,000 requests/day
- **How to Get**:
  1. Go to https://www.abuseipdb.com/register
  2. Create free account
  3. Go to https://www.abuseipdb.com/api
  4. Generate API key

### 3. **Shodan API** 🔍
- **Purpose**: Internet-connected device scanning, vulnerability discovery
- **Free Tier**: 100 queries/month
- **How to Get**:
  1. Go to https://account.shodan.io/register
  2. Create free account
  3. Go to https://account.shodan.io/
  4. Copy your API key

### 4. **AlienVault OTX API** 👽
- **Purpose**: Threat intelligence, IOCs (Indicators of Compromise)
- **Free Tier**: Unlimited (with registration)
- **How to Get**:
  1. Go to https://otx.alienvault.com/registration
  2. Create free account
  3. Go to https://otx.alienvault.com/api
  4. Copy your API key

### 5. **URLScan.io API** 🌐
- **Purpose**: URL analysis, website security scanning
- **Free Tier**: 5,000 scans/month
- **How to Get**:
  1. Go to https://urlscan.io/user/signup
  2. Create free account
  3. Go to https://urlscan.io/user/profile/
  4. Generate API key

### 6. **GreyNoise API** 📡
- **Purpose**: Internet background noise analysis, threat hunting
- **Free Tier**: 1,000 queries/month
- **How to Get**:
  1. Go to https://www.greynoise.io/signup
  2. Create free account
  3. Go to https://www.greynoise.io/account/
  4. Copy your API key

### 7. **SecurityTrails API** 🔒
- **Purpose**: DNS intelligence, domain research
- **Free Tier**: 50 queries/month
- **How to Get**:
  1. Go to https://securitytrails.com/corp/signup
  2. Create free account
  3. Go to https://securitytrails.com/corp/api
  4. Generate API key

### 8. **PhishTank API** 🎣
- **Purpose**: Phishing URL detection
- **Free Tier**: Unlimited (with registration)
- **How to Get**:
  1. Go to https://www.phishtank.com/register.php
  2. Create free account
  3. Go to https://www.phishtank.com/api_info.php
  4. Request API key

---

## 📝 Step-by-Step Setup Process

### Step 1: Create Environment File
```bash
# Navigate to your project directory
cd "d:\Downloads\SecureNetDashboard\SecureNetDashboard"

# Create .env file for API keys
New-Item -ItemType File -Name ".env" -Force
```

### Step 2: Add API Keys to .env File
Copy this template and fill in your actual API keys:

```env
# SecureNet SOC Platform - API Configuration
# ==========================================

# Development/Production Mode
NODE_ENV=development
FLASK_ENV=development

# Server Configuration
FRONTEND_URL=http://localhost:5174
BACKEND_URL=http://localhost:5001
API_BASE_URL=http://localhost:5001/api

# Database Configuration
DATABASE_URL=sqlite:///securenet.db

# === CYBERSECURITY API KEYS ===

# VirusTotal API (Malware Detection)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB API (IP Reputation)
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Shodan API (Device Scanning)
SHODAN_API_KEY=your_shodan_api_key_here

# AlienVault OTX API (Threat Intelligence)
ALIENVAULT_API_KEY=your_alienvault_api_key_here

# URLScan.io API (URL Analysis)
URLSCAN_API_KEY=your_urlscan_api_key_here

# GreyNoise API (Internet Noise Analysis)
GREYNOISE_API_KEY=your_greynoise_api_key_here

# SecurityTrails API (DNS Intelligence)
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here

# PhishTank API (Phishing Detection)
PHISHTANK_API_KEY=your_phishtank_api_key_here

# === OPTIONAL ENHANCED APIS ===

# Google Safe Browsing API (URL Safety)
GOOGLE_SAFEBROWSING_API_KEY=your_google_api_key_here

# IPGeolocation API (Location Services)
IPGEOLOCATION_API_KEY=your_ipgeolocation_api_key_here

# === RATE LIMITING ===
API_RATE_LIMIT=100
API_RATE_WINDOW=3600

# === SECURITY SETTINGS ===
SECRET_KEY=your_flask_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_here
```

### Step 3: Install Required Python Packages
```bash
cd flask_backend
.\venv\Scripts\activate
pip install python-dotenv requests
```

### Step 4: Update Flask Backend Configuration
The backend will automatically load these API keys and use real threat intelligence services.

---

## 🚀 Quick Start Commands

### Get All API Keys at Once:
1. **Open all registration pages** (copy-paste these URLs):
   ```
   https://www.virustotal.com/gui/join-us
   https://www.abuseipdb.com/register
   https://account.shodan.io/register
   https://otx.alienvault.com/registration
   https://urlscan.io/user/signup
   https://www.greynoise.io/signup
   https://securitytrails.com/corp/signup
   https://www.phishtank.com/register.php
   ```

2. **Create accounts** (use same email for all)

3. **Collect API keys** from each service

4. **Fill the .env file** with your keys

---

## ⚡ Automated Setup Script

I'll create a script to help you test your API keys once you have them:

```bash
# Test all API connections
python flask_backend/test_api_keys.py
```

---

## 🔄 Next Steps After Adding API Keys

1. **Restart backend server** to load new environment variables
2. **Test API connections** using the test script
3. **Verify real data** is flowing in the dashboard
4. **Deploy to production** with real threat intelligence

---

## 📋 Priority Order (Start with these)

If you want to start with the most important APIs first:

1. **VirusTotal** - Essential for malware detection
2. **AbuseIPDB** - Critical for IP reputation
3. **URLScan.io** - Important for URL analysis
4. **AlienVault OTX** - Great for threat intelligence
5. **Shodan** - Valuable for network discovery

---

## 🛡️ Security Notes

- **Never commit .env file** to version control
- **Use different API keys** for development vs production
- **Monitor your usage** to stay within free tier limits
- **Rotate keys regularly** for security

---

**Ready to proceed? Start by creating accounts and collecting your first API key!** 🚀
