# Use an official Python slim image
FROM python:3.9-slim

# Install FFmpeg, fonts, and debug tools (procps for ps, net-tools for netstat, curl and vim)
RUN apt-get update && apt-get install -y \
    ffmpeg \
    fonts-dejavu \
    procps \
    net-tools \
    curl \
    vim \
 && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your RTSP streamer code
COPY . .

# Expose the necessary ports (HTTP API, RTSP, WebSocket, WS-Discovery)
EXPOSE 3001 8554 9999 3702

# Start the RTSP streamer server (adjust the filename if necessary)
CMD ["python", "server.py"]
