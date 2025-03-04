#!/bin/bash
# Enhanced docker-entrypoint.sh for YoLink Dashboard RTSP Server
set -e  # Exit on error

# Function to handle application termination
cleanup() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Shutting down services..."

    # Kill MediaMTX if running
    if [ -n "$MEDIAMTX_PID" ] && ps -p $MEDIAMTX_PID > /dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Stopping MediaMTX (PID: $MEDIAMTX_PID)"
        kill -TERM $MEDIAMTX_PID
        # Wait up to 5 seconds for graceful termination
        for i in {1..10}; do
            if ! ps -p $MEDIAMTX_PID > /dev/null; then
                break
            fi
            sleep 0.5
        done
        # Force kill if still running
        if ps -p $MEDIAMTX_PID > /dev/null; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - MediaMTX did not terminate gracefully, forcing kill"
            kill -9 $MEDIAMTX_PID
        fi
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') - Shutdown complete"
}

# Set up trap for clean shutdown
trap cleanup SIGTERM SIGINT

# Validate environment variables
if [ -z "$SERVER_IP" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: SERVER_IP not set, will attempt to auto-detect"
fi

# Check if MediaMTX config exists
if [ ! -f /opt/mediamtx.yml ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: MediaMTX configuration file not found at /opt/mediamtx.yml"
    exit 1
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting MediaMTX RTSP server"

# Create log directory if it doesn't exist
mkdir -p /var/log/mediamtx

# Start MediaMTX with output redirection
mediamtx /opt/mediamtx.yml > /var/log/mediamtx/stdout.log 2> /var/log/mediamtx/stderr.log &
MEDIAMTX_PID=$!

# Wait for MediaMTX to initialize
echo "$(date '+%Y-%m-%d %H:%M:%S') - Waiting for MediaMTX to initialize (PID: $MEDIAMTX_PID)..."
sleep 2

# Check if MediaMTX is running and listening on the configured port
RTSP_PORT=${RTSP_PORT:-8554}
MAX_ATTEMPTS=15
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    # First check if process is still running
    if ! ps -p $MEDIAMTX_PID > /dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: MediaMTX process terminated unexpectedly"
        echo "--- Last 20 lines of MediaMTX stderr: ---"
        tail -n 20 /var/log/mediamtx/stderr.log
        exit 1
    fi

    # Check if port is open
    if netstat -tuln | grep -q ":$RTSP_PORT "; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - MediaMTX successfully started and listening on port $RTSP_PORT"
        break
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') - Waiting for MediaMTX to bind to port $RTSP_PORT (attempt $ATTEMPT/$MAX_ATTEMPTS)..."
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1

    # If we've waited too long, check logs
    if [ $ATTEMPT -gt $MAX_ATTEMPTS ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: MediaMTX failed to start properly within timeout period"
        echo "--- Last 20 lines of MediaMTX stderr: ---"
        tail -n 20 /var/log/mediamtx/stderr.log

        # Check specific errors
        if grep -q "address already in use" /var/log/mediamtx/stderr.log; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - HINT: Port $RTSP_PORT appears to be already in use by another process"
        fi

        exit 1
    fi
done

# Ensure FIFO directories exist
mkdir -p /tmp/streams
chmod 777 /tmp/streams

# Set the working directory to /app (where the rtsp-streamer files are copied)
cd /app

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting YoLink Dashboard RTSP Server"

# Start the YoLink RTSP server using main.py
# The exec command replaces the current process with the new one
exec python main.py