# Use Python 3.9 as base image
FROM python:3.9-slim

# Install basic dependencies, including xz-utils for tar.xz extraction and fonts for PIL
RUN apt-get update && apt-get install -y \
    fonts-dejavu \
    procps \
    net-tools \
    curl \
    vim \
    file \
    xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Download and install the latest FFmpeg static binary
RUN curl -L https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz -o ffmpeg.tar.xz \
    && file ffmpeg.tar.xz | grep -q "XZ compressed" || (echo "Downloaded file is not XZ compressed" && exit 1) \
    && mkdir -p /tmp/ffmpeg \
    && tar -xJf ffmpeg.tar.xz -C /tmp/ffmpeg \
    && mv /tmp/ffmpeg/*/ffmpeg /tmp/ffmpeg/*/ffprobe /usr/local/bin/ \
    && rm -rf /tmp/ffmpeg ffmpeg.tar.xz

# Download MediaMTX v1.11.3
RUN curl -L https://github.com/bluenviron/mediamtx/releases/download/v1.11.3/mediamtx_v1.11.3_linux_amd64.tar.gz -o mediamtx.tar.gz \
    && file mediamtx.tar.gz | grep -q "gzip compressed" || (echo "Downloaded file is not a gzip archive" && exit 1) \
    && tar -xzvf mediamtx.tar.gz \
    && mv mediamtx /usr/local/bin/mediamtx \
    && rm mediamtx.tar.gz

# Create FIFO directory for RTSP streaming
RUN mkdir -p /tmp/streams

# Set working directory
WORKDIR /app

# Copy configuration and requirements
COPY mediamtx.yml /opt/mediamtx.yml
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt psutil

# Copy the entire rtsp-streamer directory (including package structure)
COPY . .

# Ensure scripts are executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports for RTSP, API, ONVIF, and WebSocket
EXPOSE 554 80 3702/udp

# Set environment variables (can be overridden by docker-compose)
ENV DASHBOARD_URL=http://websocket-proxy:3000
ENV RTSP_PORT=554
ENV STREAM_NAME=yolink-dashboard
ENV FRAME_RATE=6
ENV WIDTH=1920
ENV HEIGHT=1080
ENV CYCLE_INTERVAL=10000
ENV ENABLE_ONVIF=true
ENV ONVIF_PORT=8000
ENV SERVER_IP=10.250.250.2
ENV RTSP_API_PORT=80
ENV WS_PORT=9999
ENV MAC_ADDRESS=51:12:56:73:D6:AA

# Run the entrypoint script, which starts both MediaMTX and the YoLink RTSP server
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]