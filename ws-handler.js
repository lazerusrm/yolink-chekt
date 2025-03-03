// WebSocket handler for YolinkChekt dashboard
// This file should be placed in the YolinkChekt directory

const WebSocket = require('ws');
const http = require('http');

let sensorData = []; // Store the latest sensor data
let wsServer;

// Initialize WebSocket server
function initWebSocketServer(server, app) {
  // Create WebSocket server
  wsServer = new WebSocket.Server({
    server,
    path: '/ws'
  });

  console.log('WebSocket server initialized at /ws');

  // Handle WebSocket connections
  wsServer.on('connection', (ws) => {
    console.log('New WebSocket client connected');

    // Send current data immediately when a client connects
    if (sensorData.length > 0) {
      ws.send(JSON.stringify({
        type: 'sensors-update',
        sensors: sensorData
      }));
    }

    // Handle connection close
    ws.on('close', () => {
      console.log('WebSocket client disconnected');
    });

    // Handle errors
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  });

  return wsServer;
}

// Broadcast sensor updates to all connected clients
function broadcastSensorUpdate(sensors) {
  if (!wsServer) return;

  sensorData = sensors; // Update stored sensor data

  const message = JSON.stringify({
    type: 'sensors-update',
    sensors: sensors
  });

  // Send to all connected clients
  wsServer.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

module.exports = {
  initWebSocketServer,
  broadcastSensorUpdate
};