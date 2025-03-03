#!/bin/bash
# Start rtsp-simple-server (it will listen on port 8554 and handle push sources)
rtsp-simple-server &

# Start the Python application
exec python server.py
