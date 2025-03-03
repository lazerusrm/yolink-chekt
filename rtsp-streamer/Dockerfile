FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install dependencies for canvas and ffmpeg
RUN apk add --no-cache \
    build-base \
    g++ \
    cairo-dev \
    jpeg-dev \
    pango-dev \
    giflib-dev \
    pixman-dev \
    pangomm-dev \
    libjpeg-turbo-dev \
    freetype-dev \
    ffmpeg \
    python3

# Copy package files
COPY rtsp-streamer/package*.json ./

# Install Node.js dependencies
RUN npm install

# Copy application code
COPY rtsp-streamer/ ./

# Create directory for temporary stream files
RUN mkdir -p /tmp/streams

# Expose ports for HTTP API, RTSP, and ONVIF
EXPOSE 3001 8554 8555 1900/udp

# Start the application
CMD ["node", "server.js"]