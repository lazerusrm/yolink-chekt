#!/bin/bash
# Start rtsp-simple-server with the configuration file located in /opt
rtsp-simple-server /opt/rtsp-simple-server.yml &

# Start the Python application
exec python server.py
