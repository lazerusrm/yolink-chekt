/**
 * WebSocket Proxy for YoLink-Chekt
 * This service fetches sensor data from the Flask API and broadcasts it via WebSocket
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const app = express();
const server = http.createServer(app);

// Configuration
const config = {
  // How often to fetch data from the API (in milliseconds)
  fetchInterval: process.env.FETCH_INTERVAL || 5000,

  // Flask API endpoint
  apiUrl: process.env.API_URL || 'http://yolink_chekt:5000/get_sensor_data',

  // WebSocket server port
  port: process.env.PORT || 3000
};

console.log(`Starting WebSocket proxy with configuration:`, config);

// Initialize WebSocket server on the /ws path
const wss = new WebSocket.Server({
  server,
  path: '/ws'
});

// Store latest sensor data
let sensorData = [];

// Fetch sensor data from the Flask API
async function fetchSensorData() {
  try {
    const response = await axios.get(config.apiUrl);
    if (response.data && response.data.devices) {
      sensorData = response.data.devices;
      broadcastUpdate();
    }
  } catch (error) {
    console.error('Error fetching sensor data:', error.message);
  }
}

// Broadcast sensor data to all connected WebSocket clients
function broadcastUpdate() {
  const message = JSON.stringify({
    type: 'sensors-update',
    sensors: sensorData
  });

  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Set up periodic data fetching
const fetchTimer = setInterval(fetchSensorData, config.fetchInterval);

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('Client connected to WebSocket');

  // Send current data immediately when a client connects
  if (sensorData.length > 0) {
    ws.send(JSON.stringify({
      type: 'sensors-update',
      sensors: sensorData
    }));
  }

  ws.on('close', () => {
    console.log('Client disconnected from WebSocket');
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Status endpoint
app.get('/status', (req, res) => {
  res.json({
    status: 'online',
    clients: wss.clients.size,
    sensors: sensorData.length
  });
});

// Start the server
server.listen(config.port, () => {
  console.log(`WebSocket proxy listening on port ${config.port}`);
  console.log(`WebSocket endpoint available at ws://localhost:${config.port}/ws`);
  console.log(`Status endpoint available at http://localhost:${config.port}/status`);

  // Initial data fetch
  fetchSensorData();
});

// Handle shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  clearInterval(fetchTimer);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  clearInterval(fetchTimer);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});