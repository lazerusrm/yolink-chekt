# Build stage (unchanged)
FROM node:18-alpine AS builder
WORKDIR /app
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
    python3
COPY rtsp-streamer/package.json rtsp-streamer/package-lock.json* ./
RUN npm install --silent && npm cache clean --force

# Runtime stage
FROM node:18-alpine
WORKDIR /app
RUN apk add --no-cache \
    ffmpeg \
    cairo \
    jpeg \
    pango \
    giflib \
    pixman \
    libjpeg-turbo \
    freetype
COPY --from=builder /app/node_modules ./node_modules
COPY rtsp-streamer/server.js ./server.js
COPY rtsp-streamer/onvif-service.js ./onvif-service.js
COPY rtsp-streamer/package.json ./package.json
RUN mkdir -p /tmp/streams
EXPOSE 3001 8554 9999
CMD ["node", "server.js"]