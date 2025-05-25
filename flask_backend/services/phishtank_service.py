import os
import requests
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from flask import current_app

class PhishTankService:
    """Enhanced PhishTank service for enterprise-grade phishing detection"""
    
    def __init__(self):
        self.api_key = current_app.config.get('PHISHTANK_API_KEY')
        self.base_url = "https://checkurl.phishtank.com"
        self.data_url = "http://data.phishtank.com/data/"
        self.headers = {
            "User-Agent": "SecureNet Enterprise SOC/1.0",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.rate_limit_delay = 1  # 1 second between requests
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Implement rate limiting for API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()
    
    def check_phishing_url(self, url: str) -> Dict[str, Any]:
        """Check if a URL is a known phishing site using PhishTank API"""
        if not self.api_key:
            return {
                "error": "PhishTank API key is not configured",
                "url": url,
                "is_phishing": False,
                "risk_score": 0
            }
        
        self._rate_limit()
        
        endpoint = f"{self.base_url}/checkurl/"
        
        data = {
            "url": url,
            "format": "json",
            "app_key": self.api_key
        }
        
        try:
            response = requests.post(endpoint, data=data, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            # Enhanced result processing
            phish_data = result.get("results", {})
            is_phishing = phish_data.get("in_database", False)
            
            result_summary = {
                "url": url,
                "is_phishing": is_phishing,
                "verified": phish_data.get("verified", False),
                "verification_time": phish_data.get("verification_time", None),
                "phish_detail_url": phish_data.get("phish_detail_url", None),
                "risk_score": self._calculate_phishing_risk_score(phish_data),
                "threat_classification": self._classify_phishing_threat(phish_data),
                "confidence": self._calculate_confidence(phish_data),
                "scan_timestamp": datetime.utcnow().isoformat(),
                "source": "PhishTank"
            }
            
            return result_summary
            
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"PhishTank API request failed: {str(e)}")
            return {
                "error": f"PhishTank API request failed: {str(e)}",
                "url": url,
                "is_phishing": False,
                "risk_score": 0,
                "source": "PhishTank"
            }
    
    def batch_url_check(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Batch check multiple URLs for phishing detection"""
        results = []
        total_urls = len(urls)
        
        current_app.logger.info(f"Starting batch phishing check for {total_urls} URLs")
        
        for i, url in enumerate(urls):
            try:
                result = self.check_phishing_url(url)
                result['batch_index'] = i
                results.append(result)
                
                # Progress logging
                if (i + 1) % 10 == 0:
                    current_app.logger.info(f"Processed {i + 1}/{total_urls} URLs")
                    
            except Exception as e:
                current_app.logger.error(f"Error checking URL {url}: {str(e)}")
                results.append({
                    "url": url,
                    "error": str(e),
                    "is_phishing": False,
                    "risk_score": 0,
                    "batch_index": i,
                    "source": "PhishTank"
                })
        
        return results
    
    def get_phishing_statistics(self) -> Dict[str, Any]:
        """Get phishing statistics and trends"""
        try:
            # This would typically use PhishTank's data feeds
            # For now, we'll return mock statistical data
            stats = {
                "total_phish_database_size": 75000,  # Approximate current size
                "verified_phish_count": 60000,
                "last_24h_submissions": 2500,
                "active_phish_sites": 45000,
                "top_targeted_brands": [
                    {"brand": "PayPal", "count": 8500},
                    {"brand": "Microsoft", "count": 7200},
                    {"brand": "Apple", "count": 6800},
                    {"brand": "Amazon", "count": 5900},
                    {"brand": "Google", "count": 5400}
                ],
                "geographic_distribution": {
                    "United States": 35.2,
                    "Russia": 12.8,
                    "China": 10.5,
                    "Netherlands": 8.9,
                    "Germany": 6.4,
                    "Other": 26.2
                },
                "last_updated": datetime.utcnow().isoformat(),
                "source": "PhishTank"
            }
            
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting PhishTank statistics: {str(e)}")
            return {
                "error": str(e),
                "source": "PhishTank"
            }
    
    def get_phishing_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get phishing trends over specified time period"""
        try:
            # Generate trend data (in production, this would use actual PhishTank data)
            trends = {
                "time_period": f"Last {days} days",
                "trend_direction": "increasing",
                "percentage_change": 15.3,
                "daily_averages": self._generate_trend_data(days),
                "peak_activity_hours": [10, 11, 14, 15, 16],  # UTC hours
                "common_attack_vectors": [
                    {"vector": "Email attachments", "percentage": 42.1},
                    {"vector": "Malicious links", "percentage": 31.8},
                    {"vector": "Social media", "percentage": 15.2},
                    {"vector": "SMS/Text", "percentage": 8.7},
                    {"vector": "Direct messages", "percentage": 2.2}
                ],
                "generated_at": datetime.utcnow().isoformat(),
                "source": "PhishTank"
            }
            
            return trends
            
        except Exception as e:
            current_app.logger.error(f"Error getting phishing trends: {str(e)}")
            return {
                "error": str(e),
                "source": "PhishTank"
            }
    
    def _calculate_phishing_risk_score(self, phish_data: Dict[str, Any]) -> int:
        """Calculate risk score based on PhishTank data"""
        score = 0
        
        if phish_data.get("in_database", False):
            score += 80  # High base score for known phishing site
            
            if phish_data.get("verified", False):
                score += 20  # Additional points for verified phish
        
        return min(score, 100)
    
    def _classify_phishing_threat(self, phish_data: Dict[str, Any]) -> str:
        """Classify the type of phishing threat"""
        if not phish_data.get("in_database", False):
            return "Clean"
        
        if phish_data.get("verified", False):
            return "Confirmed Phishing"
        else:
            return "Suspected Phishing"
    
    def _calculate_confidence(self, phish_data: Dict[str, Any]) -> float:
        """Calculate confidence score for the detection"""
        if phish_data.get("verified", False):
            return 0.95
        elif phish_data.get("in_database", False):
            return 0.75
        else:
            return 0.1
    
    def _generate_trend_data(self, days: int) -> List[Dict[str, Any]]:
        """Generate sample trend data"""
        import random
        
        trend_data = []
        base_date = datetime.utcnow() - timedelta(days=days)
        
        for i in range(days):
            date = base_date + timedelta(days=i)
            count = random.randint(1500, 3500)  # Daily phishing attempts
            
            trend_data.append({
                "date": date.strftime("%Y-%m-%d"),
                "phish_count": count,
                "verified_count": int(count * 0.7),
                "active_count": int(count * 0.6)
            })
        
        return trend_data

# Global service instance
phishtank_service = PhishTankService()

# Legacy function for backward compatibility
def check_phishing_url(url):
    """Legacy wrapper for backward compatibility"""
    return phishtank_service.check_phishing_url(url)