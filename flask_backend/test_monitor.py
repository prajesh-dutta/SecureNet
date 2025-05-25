#!/usr/bin/env python3
"""
Test script for RealSystemMonitor
"""

from services.real_system_monitor import RealSystemMonitor

def main():
    try:
        print("Creating RealSystemMonitor instance...")
        monitor = RealSystemMonitor()
        
        print("Getting real system health...")
        metrics = monitor.get_real_system_health()
        
        print("\nReal System Metrics:")
        print(f"CPU: {metrics['cpu_usage']}%")
        print(f"Memory: {metrics['memory_usage']}%")
        print(f"Disk: {metrics['disk_usage']}%")
        print(f"Overall Status: {metrics['overall_status']}")
        print(f"Hostname: {metrics['hostname']}")
        print(f"Platform: {metrics['platform']}")
        
        print("\nSuccess! Real system monitoring is working correctly.")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
