# Use an official Python slim image
FROM python:3.9-slim

# Install dependencies: FFmpeg, fonts, and debug tools
RUN apt-get update && apt-get install -y \
    ffmpeg \
    fonts-dejavu \
    procps \
    net-tools \
    curl \
    vim \
 && rm -rf /var/lib/apt/lists/*

# Download rtsp-simple-server (mediaMTX)
RUN curl -L https://github.com/aler9/rtsp-simple-server/releases/download/v0.20.1/rtsp-simple-server_v0.20.1_linux_amd64.tar.gz -o rtsp-simple-server.tar.gz \
    && tar -xzvf rtsp-simple-server.tar.gz \
    && mv rtsp-simple-server /usr/local/bin/rtsp-simple-server \
    && rm rtsp-simple-server.tar.gz

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Copy the entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose the necessary ports
# 3001 for the Flask API; 8554 for RTSP; 8555 for ONVIF; 3702 for WS-Discovery.
EXPOSE 3001 8554 8555 3702

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
