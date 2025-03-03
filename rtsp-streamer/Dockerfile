# Build stage
FROM node:18-alpine AS builder
WORKDIR /app
RUN apk add --no-cache build-base g++ cairo-dev jpeg-dev pango-dev giflib-dev pixman-dev pangomm-dev libjpeg-turbo-dev freetype-dev python3
COPY rtsp-streamer/package*.json ./
RUN npm install

# Runtime stage
FROM node:18-alpine
WORKDIR /app
RUN apk add --no-cache ffmpeg
COPY --from=builder /app/node_modules ./node_modules
COPY . ./
RUN mkdir -p /tmp/streams
EXPOSE 3001 8554 9999 8555
CMD ["node", "server.js"]