#!/usr/bin/env python3
"""
Backward compatibility wrapper for the YoLink Dashboard RTSP Server.
This file imports and runs the main application from the app package.
"""
import sys
import os

# Add the current directory to the path if needed
if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the main application
from app.main import main

if __name__ == "__main__":
    main()