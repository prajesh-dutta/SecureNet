#!/usr/bin/env python3
"""Simple test for RealSystemMonitor"""

from services.real_system_monitor import RealSystemMonitor

def main():
    try:
        # Initialize the monitor
        monitor = RealSystemMonitor()
        print("Successfully initialized RealSystemMonitor")
        
        # Check the method
        methods = [method for method in dir(monitor) if not method.startswith('_')]
        print(f"Available methods: {methods}")
        
        if 'get_real_system_health' in methods:
            print("get_real_system_health method exists!")
            # Try calling it
            metrics = monitor.get_real_system_health()
            print("Successfully called get_real_system_health")
            print(f"Metrics: {metrics.keys()}")
        else:
            print("get_real_system_health method does NOT exist!")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
