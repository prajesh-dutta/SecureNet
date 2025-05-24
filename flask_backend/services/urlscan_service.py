import os
import requests
import json
import time
from flask import current_app

def analyze_url(url):
    """Analyze a URL using URLScan.io API"""
    api_key = current_app.config.get('URLSCAN_API_KEY')
    
    if not api_key:
        raise ValueError("URLScan.io API key is not configured")
    
    # URLScan.io API endpoint for submitting URLs
    submit_endpoint = "https://urlscan.io/api/v1/scan/"
    
    headers = {
        "Content-Type": "application/json",
        "API-Key": api_key
    }
    
    # Payload for the scan request
    payload = {
        "url": url,
        "visibility": "private"  # Options: public, unlisted, private
    }
    
    try:
        # Submit URL for scanning
        submit_response = requests.post(submit_endpoint, headers=headers, json=payload)
        submit_response.raise_for_status()
        
        submit_result = submit_response.json()
        scan_uuid = submit_result.get("uuid")
        result_url = submit_result.get("api")
        
        if not scan_uuid or not result_url:
            return {
                "error": "Failed to get scan UUID from URLScan.io",
                "url": url
            }
        
        # Wait for scan to complete (typically takes 10-30 seconds)
        # In a production environment, this would be done asynchronously
        max_retries = 10
        retry_delay = 3  # seconds
        
        for _ in range(max_retries):
            time.sleep(retry_delay)
            
            # Check if results are available
            result_response = requests.get(result_url)
            
            if result_response.status_code == 200:
                # Results are available
                result_data = result_response.json()
                
                # Create a summary of the scan results
                verdicts = result_data.get("verdicts", {})
                page = result_data.get("page", {})
                
                result_summary = {
                    "url": url,
                    "scan_id": scan_uuid,
                    "scan_date": result_data.get("task", {}).get("time"),
                    "malicious": verdicts.get("overall", {}).get("malicious", False),
                    "suspicious": verdicts.get("overall", {}).get("suspicious", False),
                    "score": verdicts.get("overall", {}).get("score", 0),
                    "categories": verdicts.get("overall", {}).get("categories", []),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "country": page.get("country"),
                    "server": page.get("server"),
                    "screenshot_url": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                    "report_url": f"https://urlscan.io/result/{scan_uuid}/",
                    "security_issues": extract_security_issues(result_data)
                }
                
                return result_summary
        
        # If we reached here, the scan is taking too long
        return {
            "url": url,
            "scan_id": scan_uuid,
            "status": "pending",
            "message": "Scan is still in progress. Check back later.",
            "report_url": f"https://urlscan.io/result/{scan_uuid}/"
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"URLScan.io API request failed: {str(e)}",
            "url": url
        }

def extract_security_issues(result_data):
    """Extract security issues from URLScan.io results"""
    security_issues = []
    
    # Check for malicious resources
    resources = result_data.get("lists", {}).get("urls", [])
    for resource in resources:
        if resource.get("malicious"):
            security_issues.append({
                "type": "malicious_resource",
                "resource": resource.get("url"),
                "threat": "Malicious resource detected"
            })
    
    # Check for suspicious cookies
    cookies = result_data.get("lists", {}).get("cookies", [])
    for cookie in cookies:
        if not cookie.get("secure") and not cookie.get("httpOnly"):
            security_issues.append({
                "type": "insecure_cookie",
                "name": cookie.get("name"),
                "threat": "Insecure cookie (missing Secure and HttpOnly flags)"
            })
    
    # Check for vulnerable JavaScript libraries
    scripts = result_data.get("lists", {}).get("scripts", [])
    for script in scripts:
        if "jquery-1." in script or "jquery-2.0" in script:
            security_issues.append({
                "type": "outdated_library",
                "library": script,
                "threat": "Potentially outdated JavaScript library"
            })
    
    return security_issues