FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY websocket-proxy/package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY websocket-proxy/ ./

# Expose the port
EXPOSE 3000

# Start the application
CMD ["node", "server.js"]