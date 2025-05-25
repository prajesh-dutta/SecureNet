#!/usr/bin/env python3
"""Test script to debug import issues."""

import sys
import traceback

print("Python path:", sys.path[0])
print("Attempting to import real_system_monitor module...")

try:
    import real_system_monitor
    print("Module imported successfully!")
    print("Module file:", real_system_monitor.__file__)
    print("Module attributes:", [attr for attr in dir(real_system_monitor) if not attr.startswith('_')])
    
    # Try to access the classes
    if hasattr(real_system_monitor, 'RealSystemMonitor'):
        print("RealSystemMonitor class found!")
    else:
        print("RealSystemMonitor class NOT found!")
        
    if hasattr(real_system_monitor, 'RealThreatDetector'):
        print("RealThreatDetector class found!")
    else:
        print("RealThreatDetector class NOT found!")
        
except Exception as e:
    print("Import failed with error:", str(e))
    traceback.print_exc()

print("\nTrying direct import...")
try:
    from real_system_monitor import RealSystemMonitor, RealThreatDetector
    print("Direct import successful!")
except Exception as e:
    print("Direct import failed:", str(e))
    traceback.print_exc()
