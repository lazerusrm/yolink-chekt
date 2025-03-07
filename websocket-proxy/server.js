/**
 * WebSocket Proxy for YoLink-Chekt
 * Fetches sensor data from the Flask API and broadcasts it to WebSocket clients
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');

// Configuration from environment variables
const config = {
  fetchInterval: parseInt(process.env.FETCH_INTERVAL, 10) || 1000, // Polling interval in ms
  apiUrl: process.env.API_URL || 'http://yolink_chekt:5000/get_sensor_data', // Flask API endpoint
  port: parseInt(process.env.PORT, 10) || 3000, // WebSocket server port
  heartbeatInterval: 30000 // Heartbeat interval in ms (30 seconds)
};

console.log('Starting WebSocket proxy with configuration:', config);

// Initialize Express and HTTP server
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// State management
let sensorData = []; // Latest sensor data
let lastBroadcastData = null; // For change detection
let fetchTimer = null; // Reference to polling interval

// Fetch sensor data with retry logic
async function fetchSensorData(attempt = 1, maxAttempts = 3) {
  try {
    const response = await axios.get(config.apiUrl, { timeout: 5000 });
    if (!response.data || !Array.isArray(response.data.devices)) {
      throw new Error('Invalid API response format: "devices" array expected');
    }
    sensorData = response.data.devices;
    broadcastUpdate();
  } catch (error) {
    console.error(`Fetch attempt ${attempt}/${maxAttempts} failed:`, error.message);
    if (attempt < maxAttempts) {
      const delay = Math.min(5000, 1000 * Math.pow(2, attempt - 1)); // Exponential backoff
      console.log(`Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      await fetchSensorData(attempt + 1, maxAttempts);
    } else {
      console.error('Max retries reached; will try again on next polling interval');
    }
  }
}

// Broadcast updates only on data change
function broadcastUpdate() {
  const currentData = JSON.stringify(sensorData);
  if (currentData === lastBroadcastData) {
    console.log('No data change detected, skipping broadcast');
    return;
  }

  const message = JSON.stringify({
    type: 'sensors-update',
    sensors: sensorData,
    timestamp: new Date().toISOString()
  });

  let clientsSent = 0;
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
      clientsSent++;
    }
  });
  console.log(`Broadcasted update to ${clientsSent} client(s)`);
  lastBroadcastData = currentData;
}

// WebSocket connection handling with heartbeat
wss.on('connection', (ws) => {
  console.log('New client connected to WebSocket');
  ws.isAlive = true;

  // Send current data immediately
  if (sensorData.length > 0) {
    ws.send(JSON.stringify({
      type: 'sensors-update',
      sensors: sensorData,
      timestamp: new Date().toISOString()
    }));
  }

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('close', () => {
    console.log('Client disconnected from WebSocket');
  });

  ws.on('error', (error) => {
    console.error('WebSocket client error:', error.message);
  });
});

// Heartbeat to detect stale connections
function startHeartbeat() {
  setInterval(() => {
    wss.clients.forEach(ws => {
      if (!ws.isAlive) {
        console.log('Terminating stale WebSocket connection');
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, config.heartbeatInterval);
}

// Start periodic fetching
function startFetching() {
  fetchTimer = setInterval(async () => {
    await fetchSensorData(1);
  }, config.fetchInterval);
  console.log(`Started fetching sensor data every ${config.fetchInterval}ms`);
}

// API endpoints
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    clientsConnected: wss.clients.size,
    sensorsCount: sensorData.length,
    lastUpdate: sensorData.length > 0 ? new Date().toISOString() : null,
    apiUrl: config.apiUrl,
    fetchInterval: config.fetchInterval
  });
});

app.get('/', (req, res) => {
  res.send('YoLink-Chekt WebSocket Proxy is running');
});

// Start the server
server.listen(config.port, () => {
  console.log(`WebSocket proxy running on http://0.0.0.0:${config.port}`);
  console.log(`WebSocket endpoint: ws://0.0.0.0:${config.port}/ws`);
  startFetching();
  startHeartbeat();
  fetchSensorData(1); // Initial fetch
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`${signal} received, shutting down...`);
  if (fetchTimer) clearInterval(fetchTimer);
  wss.clients.forEach(ws => ws.close());
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));