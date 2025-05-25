#!/usr/bin/env python3
"""Test script for RealSystemMonitor"""

from services.real_system_monitor import RealSystemMonitor
import json

def test_real_monitor():
    print("Testing RealSystemMonitor...")
    try:
        # Initialize the monitor
        monitor = RealSystemMonitor()
        print("✓ Successfully initialized RealSystemMonitor")
        
        # Get system health
        metrics = monitor.get_real_system_health()
        print("✓ Successfully retrieved system health metrics")
        
        # Print key metrics
        print("\nSystem Health Metrics:")
        print(f"  CPU Usage: {metrics.get('cpu', {}).get('usage_percent', 'N/A')}%")
        print(f"  Memory Usage: {metrics.get('memory', {}).get('usage_percent', 'N/A')}%")
        print(f"  Disk Usage: {metrics.get('disk', {}).get('usage_percent', 'N/A')}%")
        print(f"  Overall Status: {metrics.get('overall_status', 'N/A')}")
        print(f"  Hostname: {metrics.get('hostname', 'N/A')}")
        print(f"  Platform: {metrics.get('platform', 'N/A')}")
        
        # Get network connections
        connections = monitor.get_real_network_connections()
        print(f"\n✓ Successfully retrieved {len(connections)} network connections")
        
        # Print full metrics (formatted)
        print("\nFull metrics JSON:")
        print(json.dumps(metrics, indent=2))
        
        return True
    except Exception as e:
        print(f"❌ Error testing RealSystemMonitor: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_real_monitor()
