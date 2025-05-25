#!/usr/bin/env python3
"""Debug script to test real_system_monitor.py execution step by step."""

import sys
import traceback

def test_execution():
    """Test the execution of real_system_monitor.py step by step."""
    
    # Test imports first
    try:
        print("Testing imports...")
        import psutil
        import socket
        import subprocess
        import platform
        import json
        import time
        import shutil
        import requests
        import os
        import threading
        from datetime import datetime, timedelta
        from collections import defaultdict, deque
        import hashlib
        import re
        from typing import Dict, List, Optional, Any
        print("✓ All imports successful")
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False
    
    # Test reading the file
    try:
        print("Reading file...")
        with open('real_system_monitor.py', 'r') as f:
            content = f.read()
        print(f"✓ File read successfully ({len(content)} characters)")
    except Exception as e:
        print(f"✗ File read error: {e}")
        return False
    
    # Test compilation
    try:
        print("Compiling code...")
        compiled_code = compile(content, 'real_system_monitor.py', 'exec')
        print("✓ Code compiled successfully")
    except Exception as e:
        print(f"✗ Compilation error: {e}")
        return False
    
    # Test execution
    try:
        print("Executing code...")
        namespace = {}
        exec(compiled_code, namespace)
        print("✓ Code executed successfully")
        
        # Check what was defined
        defined_items = [k for k in namespace.keys() if not k.startswith('__')]
        print(f"Defined items: {defined_items}")
        
        # Specifically check for our classes
        if 'RealSystemMonitor' in namespace:
            print("✓ RealSystemMonitor class found")
        else:
            print("✗ RealSystemMonitor class NOT found")
            
        if 'RealThreatDetector' in namespace:
            print("✓ RealThreatDetector class found")
        else:
            print("✗ RealThreatDetector class NOT found")
            
        return True
        
    except Exception as e:
        print(f"✗ Execution error: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_execution()
