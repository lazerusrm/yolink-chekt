#!/bin/bash
# YoLink RTSP Streaming Diagnostic Script
# Run with: bash rtsp-diagnostic.sh

echo "===== YoLink RTSP Diagnostic Tool ====="
echo "Running diagnostic checks for RTSP streaming components..."

# Check if FFmpeg is installed and version
echo -e "\n[1/7] Checking FFmpeg installation:"
if command -v ffmpeg &> /dev/null; then
    ffmpeg -version | head -n 1
    echo "✅ FFmpeg is installed"
else
    echo "❌ FFmpeg is not installed. Please install FFmpeg."
    exit 1
fi

# Check if the FIFO pipe exists
echo -e "\n[2/7] Checking FIFO pipe:"
if [ -p "/tmp/streams/dashboard_pipe" ]; then
    echo "✅ FIFO pipe exists at /tmp/streams/dashboard_pipe"
else
    echo "❌ FIFO pipe does not exist or is not a pipe. This should be created by the streamer."
    echo "   Creating a test pipe..."
    mkdir -p /tmp/streams
    rm -f /tmp/streams/dashboard_pipe
    mkfifo /tmp/streams/dashboard_pipe
    echo "✅ Test pipe created at /tmp/streams/dashboard_pipe"
fi

# Check Docker container status
echo -e "\n[3/7] Checking Docker container status:"
if command -v docker &> /dev/null; then
    docker ps | grep yolink-rtsp-streamer
    if [ $? -eq 0 ]; then
        echo "✅ Container appears to be running"
    else
        echo "❌ Container not found or not running"
    fi
else
    echo "ℹ️ Docker command not available, skipping container check"
fi

# Check for network connectivity to the websocket proxy
echo -e "\n[4/7] Testing network connectivity to WebSocket proxy:"
if command -v nc &> /dev/null; then
    # Extract host and port
    PROXY_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' websocket-proxy 2>/dev/null || echo "websocket-proxy")
    nc -z -w 2 $PROXY_HOST 3000
    if [ $? -eq 0 ]; then
        echo "✅ Connection to WebSocket proxy ($PROXY_HOST:3000) successful"
    else
        echo "❌ Cannot connect to WebSocket proxy ($PROXY_HOST:3000)"
    fi
else
    echo "ℹ️ netcat not available, skipping connectivity test"
fi

# Check if the RTSP stream is accessible
echo -e "\n[5/7] Testing RTSP stream accessibility:"
SERVER_IP=$(ip route get 1 | sed -n 's/.*src \([0-9.]*\).*/\1/p')
RTSP_URL="rtsp://$SERVER_IP:8554/yolink-dashboard"
if command -v ffprobe &> /dev/null; then
    timeout 5 ffprobe -v quiet -rtsp_transport tcp "$RTSP_URL" 2>&1
    if [ $? -eq 0 ]; then
        echo "✅ RTSP stream at $RTSP_URL is accessible"
    else
        echo "❌ RTSP stream at $RTSP_URL is not accessible"
    fi
else
    echo "ℹ️ ffprobe not available, skipping RTSP stream test"
fi

# Check HTTP API
echo -e "\n[6/7] Testing HTTP API:"
if command -v curl &> /dev/null; then
    curl -s "http://$SERVER_IP:3001/status" | grep -o '"status":"online"' > /dev/null
    if [ $? -eq 0 ]; then
        echo "✅ API is responding at http://$SERVER_IP:3001/status"
    else
        echo "❌ API not responding properly at http://$SERVER_IP:3001/status"
    fi
else
    echo "ℹ️ curl not available, skipping API test"
fi

# Check disk space and resources
echo -e "\n[7/7] Checking system resources:"
df -h /tmp | tail -n 1
echo "Memory usage:"
free -m | grep "Mem:"

echo -e "\n===== Diagnostic Summary ====="
echo "If you're experiencing issues with the RTSP stream, try these steps:"
echo "1. Restart the container: docker restart yolink-rtsp-streamer"
echo "2. Check container logs: docker logs yolink-rtsp-streamer"
echo "3. Try a manual restart via API: curl -X POST http://$SERVER_IP:3001/restart-stream"
echo "4. Verify FFmpeg can read from the FIFO: cat /dev/urandom | head -c 10000 > /tmp/streams/dashboard_pipe"
echo "5. Test frame rendering: curl http://$SERVER_IP:3001/snapshot -o test_frame.jpg"
echo -e "\nFor additional help, review the logs or refer to the troubleshooting section in the documentation."