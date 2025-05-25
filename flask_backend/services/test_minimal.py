#!/usr/bin/env python3
# Minimal test of class definitions

import psutil
import platform
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque

class RealSystemMonitor:
    """Real-time system monitoring for cybersecurity analysis."""
    
    def __init__(self):
        self.monitoring = False
        print("RealSystemMonitor initialized")

class RealThreatDetector:
    """Real-time threat detection system."""
    
    def __init__(self):
        self.system_monitor = RealSystemMonitor()
        print("RealThreatDetector initialized")

print("Classes defined successfully")
