#!/bin/bash
set -e  # Exit on error

# Start MediaMTX and capture its PID
mediamtx /opt/mediamtx.yml &
MEDIAMTX_PID=$!

# Wait briefly to ensure MediaMTX starts, then check if it's running
sleep 2
if ! ps -p $MEDIAMTX_PID > /dev/null; then
    echo "Error: MediaMTX failed to start. Check logs."
    cat /opt/mediamtx.log  # Assuming MediaMTX logs here
    exit 1
fi

# Start the Python app
exec python server.py