#!/bin/bash
# Start rtsp-simple-server with our configuration file
rtsp-simple-server /opt/rtsp-simple-server.yml &

# Start the Python application
exec python server.py
