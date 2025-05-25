import os
import requests
import json
import time
from flask import current_app
from datetime import datetime

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

def analyze_url_comprehensive(url):
    """Comprehensive URL analysis including security assessment"""
    try:
        # Get basic URL scan
        scan_result = analyze_url(url)
        
        if scan_result.get("error"):
            return scan_result
        
        # Enhance with additional analysis
        comprehensive_result = {
            "url": url,
            "scan_timestamp": datetime.now().isoformat(),
            "basic_scan": scan_result,
            "security_assessment": {},
            "risk_factors": [],
            "recommendations": []
        }
        
        # Analyze scan results for security issues
        if "result" in scan_result:
            result_data = scan_result.get("result", {})
            
            # Extract security indicators
            security_issues = extract_security_issues(result_data)
            comprehensive_result["security_assessment"]["issues"] = security_issues
            
            # Calculate risk score
            risk_score = calculate_url_risk_score(result_data, security_issues)
            comprehensive_result["security_assessment"]["risk_score"] = risk_score
            
            # Generate recommendations
            recommendations = generate_security_recommendations(security_issues, risk_score)
            comprehensive_result["recommendations"] = recommendations
            
            # Determine overall threat level
            if risk_score >= 80:
                threat_level = "high"
                comprehensive_result["risk_factors"].append("High risk score based on multiple indicators")
            elif risk_score >= 60:
                threat_level = "medium"
                comprehensive_result["risk_factors"].append("Moderate risk score")
            elif risk_score >= 40:
                threat_level = "low"
            else:
                threat_level = "minimal"
            
            comprehensive_result["security_assessment"]["threat_level"] = threat_level
        
        return comprehensive_result
        
    except Exception as e:
        return {"error": f"Comprehensive URL analysis failed: {str(e)}"}

def calculate_url_risk_score(result_data, security_issues):
    """Calculate a risk score based on URLScan.io results"""
    score = 0
    
    # Base score adjustments
    if result_data.get("verdicts", {}).get("overall", {}).get("malicious"):
        score += 50
    
    # Check for specific threat indicators
    for issue in security_issues:
        issue_type = issue.get("type", "")
        
        if issue_type == "malicious_resource":
            score += 30
        elif issue_type == "insecure_cookie":
            score += 5
        elif issue_type == "outdated_library":
            score += 10
        elif issue_type == "suspicious_redirect":
            score += 20
        elif issue_type == "phishing_indicator":
            score += 40
    
    # Check for HTTPS usage
    if not result_data.get("task", {}).get("url", "").startswith("https://"):
        score += 10
    
    # Check for suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
    url = result_data.get("task", {}).get("url", "")
    if any(tld in url for tld in suspicious_tlds):
        score += 15
    
    return min(score, 100)  # Cap at 100

def generate_security_recommendations(security_issues, risk_score):
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    if risk_score >= 70:
        recommendations.append("CRITICAL: Do not visit this URL - high risk of malware or phishing")
        recommendations.append("Block this URL in your security appliances")
        recommendations.append("Report to threat intelligence feeds")
    elif risk_score >= 50:
        recommendations.append("CAUTION: Exercise extreme caution when visiting this URL")
        recommendations.append("Use isolated environment for investigation")
        recommendations.append("Monitor for additional threat indicators")
    elif risk_score >= 30:
        recommendations.append("Monitor this URL for changes")
        recommendations.append("Consider additional security controls")
    
    # Issue-specific recommendations
    issue_types = [issue.get("type") for issue in security_issues]
    
    if "insecure_cookie" in issue_types:
        recommendations.append("Website uses insecure cookies - avoid entering sensitive information")
    
    if "outdated_library" in issue_types:
        recommendations.append("Website uses outdated JavaScript libraries - potential vulnerability")
    
    if "malicious_resource" in issue_types:
        recommendations.append("Website loads resources from malicious domains")
    
    return recommendations

def batch_url_analysis(urls):
    """Analyze multiple URLs in batch"""
    results = {
        "batch_id": f"batch_{int(time.time())}",
        "timestamp": datetime.now().isoformat(),
        "total_urls": len(urls),
        "results": [],
        "summary": {
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "minimal_risk": 0,
            "errors": 0
        }
    }
    
    for url in urls[:50]:  # Limit to 50 URLs to prevent rate limiting
        try:
            analysis = analyze_url_comprehensive(url)
            
            if not analysis.get("error"):
                threat_level = analysis.get("security_assessment", {}).get("threat_level", "unknown")
                
                if threat_level == "high":
                    results["summary"]["high_risk"] += 1
                elif threat_level == "medium":
                    results["summary"]["medium_risk"] += 1
                elif threat_level == "low":
                    results["summary"]["low_risk"] += 1
                else:
                    results["summary"]["minimal_risk"] += 1
            else:
                results["summary"]["errors"] += 1
            
            results["results"].append(analysis)
            
            # Rate limiting - wait between requests
            time.sleep(2)
            
        except Exception as e:
            error_result = {"url": url, "error": str(e)}
            results["results"].append(error_result)
            results["summary"]["errors"] += 1
    
    return results

def get_url_reputation_history(url):
    """Get historical reputation data for a URL"""
    api_key = current_app.config.get('URLSCAN_API_KEY')
    
    if not api_key:
        return {"error": "URLScan.io API key is not configured"}
    
    # Search for historical scans of this URL
    search_url = "https://urlscan.io/api/v1/search/"
    headers = {"API-Key": api_key}
    params = {
        "q": f"domain:{url}",
        "size": 100
    }
    
    try:
        response = requests.get(search_url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        results = data.get("results", [])
        
        # Analyze historical patterns
        history_analysis = {
            "url": url,
            "total_scans": len(results),
            "scan_timeline": [],
            "reputation_trend": "stable",
            "malicious_detections": 0,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        malicious_count = 0
        for result in results[-20:]:  # Last 20 scans
            scan_time = result.get("task", {}).get("time")
            verdict = result.get("verdicts", {}).get("overall", {})
            
            is_malicious = verdict.get("malicious", False)
            if is_malicious:
                malicious_count += 1
            
            history_analysis["scan_timeline"].append({
                "scan_time": scan_time,
                "malicious": is_malicious,
                "scan_id": result.get("_id")
            })
        
        history_analysis["malicious_detections"] = malicious_count
        
        # Determine reputation trend
        if malicious_count > len(results) * 0.5:
            history_analysis["reputation_trend"] = "deteriorating"
        elif malicious_count > 0:
            history_analysis["reputation_trend"] = "concerning"
        else:
            history_analysis["reputation_trend"] = "stable"
        
        return history_analysis
        
    except requests.exceptions.RequestException as e:
        return {"error": f"URLScan.io history lookup failed: {str(e)}"}