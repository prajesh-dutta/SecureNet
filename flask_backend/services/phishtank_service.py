import os
import requests
import json
from flask import current_app

def check_phishing_url(url):
    """Check if a URL is a known phishing site using PhishTank API"""
    api_key = current_app.config.get('PHISHTANK_API_KEY')
    
    if not api_key:
        raise ValueError("PhishTank API key is not configured")
    
    # PhishTank API endpoint for URL checks
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    
    headers = {
        "User-Agent": "SecureNet Cybersecurity Dashboard",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    data = {
        "url": url,
        "format": "json",
        "app_key": api_key
    }
    
    try:
        response = requests.post(endpoint, data=data, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        # Create a summary of the results
        result_summary = {
            "url": url,
            "is_phishing": result.get("results", {}).get("in_database", False),
            "verified": result.get("results", {}).get("verified", False),
            "verification_time": result.get("results", {}).get("verification_time", None),
            "phish_detail_url": result.get("results", {}).get("phish_detail_url", None)
        }
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"PhishTank API request failed: {str(e)}",
            "url": url,
            "is_phishing": False
        }