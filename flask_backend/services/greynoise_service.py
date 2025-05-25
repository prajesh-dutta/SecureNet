import os
import requests
import json
from flask import current_app
from datetime import datetime, timedelta

def get_noise_analysis(ip):
    """Analyze an IP address using GreyNoise API"""
    api_key = current_app.config.get('GREYNOISE_API_KEY')
    
    if not api_key:
        raise ValueError("GreyNoise API key is not configured")
    
    # GreyNoise API endpoint for IP lookups
    endpoint = f"https://api.greynoise.io/v3/community/{ip}"
    
    headers = {
        "Accept": "application/json",
        "key": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a summary of the results
        result_summary = {
            "ip": ip,
            "seen": data.get("seen", False),
            "classification": data.get("classification"),
            "last_seen": data.get("last_seen"),
            "actor": data.get("actor"),
            "tags": data.get("tags", []),
            "vpn": data.get("vpn", False),
            "vpn_service": data.get("vpn_service"),
            "raw": data,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False)  # RIOT = Rule It OuT (legitimate services)
        }
        
        # For premium API users, get more detailed context
        if api_key.startswith("gna_"):  # Premium API key format
            context_endpoint = f"https://api.greynoise.io/v2/noise/context/{ip}"
            
            context_response = requests.get(context_endpoint, headers=headers)
            
            if context_response.status_code == 200:
                context_data = context_response.json()
                
                # Add detailed context to the summary
                result_summary.update({
                    "first_seen": context_data.get("first_seen"),
                    "last_seen": context_data.get("last_seen"),
                    "metadata": context_data.get("metadata"),
                    "asn": context_data.get("metadata", {}).get("asn"),
                    "organization": context_data.get("metadata", {}).get("organization"),
                    "category": context_data.get("metadata", {}).get("category"),
                    "tor": context_data.get("metadata", {}).get("tor", False),
                    "raw_data": context_data.get("raw_data", {})
                })
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"GreyNoise API request failed: {str(e)}",
            "ip": ip
        }

def get_ip_reputation_score(ip):
    """Get comprehensive IP reputation score from GreyNoise"""
    try:
        noise_analysis = get_noise_analysis(ip)
        
        if noise_analysis.get("error"):
            return noise_analysis
        
        score = 100  # Start with neutral score
        risk_factors = []
        
        # Adjust score based on GreyNoise classification
        classification = noise_analysis.get("classification")
        if classification == "malicious":
            score = 10
            risk_factors.append("Classified as malicious by GreyNoise")
        elif classification == "benign":
            score = 90
        elif classification == "unknown":
            score = 50
        
        # Check for VPN usage
        if noise_analysis.get("vpn"):
            score -= 20
            risk_factors.append(f"VPN traffic detected ({noise_analysis.get('vpn_service', 'Unknown provider')})")
        
        # Check for Tor usage
        if noise_analysis.get("metadata", {}).get("tor"):
            score -= 30
            risk_factors.append("Tor network traffic detected")
        
        # Check for scanning activity
        tags = noise_analysis.get("tags", [])
        if any("scan" in tag.lower() for tag in tags):
            score -= 25
            risk_factors.append("Scanning activity detected")
        
        # Check for bot activity
        if any("bot" in tag.lower() for tag in tags):
            score -= 15
            risk_factors.append("Bot activity detected")
        
        # Determine reputation category
        if score >= 80:
            reputation = "Trusted"
        elif score >= 60:
            reputation = "Moderate"
        elif score >= 40:
            reputation = "Suspicious"
        else:
            reputation = "Malicious"
        
        return {
            "ip": ip,
            "reputation_score": max(0, score),
            "reputation": reputation,
            "classification": classification,
            "risk_factors": risk_factors,
            "last_seen": noise_analysis.get("last_seen"),
            "actor": noise_analysis.get("actor"),
            "tags": tags,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {"error": f"IP reputation analysis failed: {str(e)}"}

def bulk_ip_lookup(ip_list):
    """Perform bulk IP lookups for threat hunting"""
    api_key = current_app.config.get('GREYNOISE_API_KEY')
    
    if not api_key:
        return {"error": "GreyNoise API key is not configured"}
    
    # GreyNoise bulk lookup endpoint (premium feature)
    endpoint = "https://api.greynoise.io/v2/noise/multi/quick"
    
    headers = {
        "Accept": "application/json",
        "key": api_key,
        "Content-Type": "application/json"
    }
    
    # Limit to 1000 IPs per request
    ip_batch = ip_list[:1000] if len(ip_list) > 1000 else ip_list
    
    payload = {"ips": ip_batch}
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            
            # Analyze results for threat patterns
            analysis = {
                "total_ips": len(ip_batch),
                "malicious_count": 0,
                "benign_count": 0,
                "unknown_count": 0,
                "detailed_results": [],
                "threat_summary": {},
                "analysis_timestamp": datetime.now().isoformat()
            }
            
            for ip_result in data:
                ip = ip_result.get("ip")
                classification = ip_result.get("classification")
                
                if classification == "malicious":
                    analysis["malicious_count"] += 1
                elif classification == "benign":
                    analysis["benign_count"] += 1
                else:
                    analysis["unknown_count"] += 1
                
                analysis["detailed_results"].append({
                    "ip": ip,
                    "classification": classification,
                    "noise": ip_result.get("noise", False),
                    "riot": ip_result.get("riot", False)
                })
            
            # Calculate threat percentage
            total_classified = analysis["malicious_count"] + analysis["benign_count"]
            if total_classified > 0:
                threat_percentage = (analysis["malicious_count"] / total_classified) * 100
                analysis["threat_summary"]["threat_percentage"] = round(threat_percentage, 2)
                
                if threat_percentage > 50:
                    analysis["threat_summary"]["overall_assessment"] = "High Risk"
                elif threat_percentage > 20:
                    analysis["threat_summary"]["overall_assessment"] = "Moderate Risk"
                else:
                    analysis["threat_summary"]["overall_assessment"] = "Low Risk"
            
            return analysis
            
        else:
            # Fallback to individual lookups for free tier
            return _fallback_bulk_lookup(ip_batch)
            
    except requests.exceptions.RequestException as e:
        return {"error": f"GreyNoise bulk lookup failed: {str(e)}"}

def _fallback_bulk_lookup(ip_list):
    """Fallback bulk lookup using individual API calls"""
    results = {
        "total_ips": len(ip_list),
        "malicious_count": 0,
        "benign_count": 0,
        "unknown_count": 0,
        "detailed_results": [],
        "note": "Performed using individual lookups (free tier)",
        "analysis_timestamp": datetime.now().isoformat()
    }
    
    # Limit to prevent rate limiting
    limited_ips = ip_list[:50]
    
    for ip in limited_ips:
        try:
            analysis = get_noise_analysis(ip)
            if not analysis.get("error"):
                classification = analysis.get("classification")
                
                if classification == "malicious":
                    results["malicious_count"] += 1
                elif classification == "benign":
                    results["benign_count"] += 1
                else:
                    results["unknown_count"] += 1
                
                results["detailed_results"].append({
                    "ip": ip,
                    "classification": classification,
                    "noise": analysis.get("noise", False),
                    "riot": analysis.get("riot", False)
                })
        except:
            # Skip IPs that cause errors
            continue
    
    return results

def get_scanning_statistics(timeframe_days=7):
    """Get scanning activity statistics from GreyNoise"""
    api_key = current_app.config.get('GREYNOISE_API_KEY')
    
    if not api_key:
        return {"error": "GreyNoise API key is not configured"}
    
    # GreyNoise stats endpoint
    endpoint = "https://api.greynoise.io/v2/experimental/gnql/stats"
    
    headers = {
        "Accept": "application/json",
        "key": api_key
    }
    
    # Query for scanning activity in the last week
    query = f"last_seen:{timeframe_days}d classification:malicious"
    params = {"query": query}
    
    try:
        response = requests.get(endpoint, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            
            stats = {
                "timeframe_days": timeframe_days,
                "query": query,
                "stats": data.get("stats", {}),
                "analysis_timestamp": datetime.now().isoformat()
            }
            
            return stats
        else:
            return {"error": f"Failed to get scanning statistics: HTTP {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"GreyNoise statistics request failed: {str(e)}"}